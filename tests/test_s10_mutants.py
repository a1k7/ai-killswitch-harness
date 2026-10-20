"""Scenario 10: broken enforcement mutants.

For each mutant, apply it via monkeypatch, then run a behaviour that
discriminates between the real implementation and the mutant. The assertion
is written so that it PASSES when the mutant is applied -- that's the whole
point. If the mutant is a no-op, the test fails, which is how we detect
"the mutant doesn't mutate".
"""
from __future__ import annotations

import json
import threading

import pytest

import harness.commit as real_commit
from harness.authz import AuthorizationService
from harness.clock import ManualClock
from harness.killswitch import KillSwitchController
from harness.schemas import ActionRequest, AuthzIssueRequest
from harness.store import DurableStateStore

from harness.mutants import (
    m1_no_persist,
    m2_skip_commit_check,
    m3_recover_clears,
    m4_alt_bypass,
    m5_ignore_epoch,
    m6_dup_retry,
    m7_idempotency_different_payload,
    m8_reuse_consumed_auth,
    m9_budget_overspend,
    m10_stale_evidence_pass,
)


def _issue(authz, request_id="r1", amount_minor=100):
    d = authz.issue(
        AuthzIssueRequest(request_id=request_id, identity="op-a", amount_minor=amount_minor, currency="USD", ttl_seconds=60)
    )
    return ActionRequest(request_id=request_id, action_id="refund", amount_minor=amount_minor, currency="USD", decision_id=d.decision_id, idempotency_key=f"k-{request_id}", identity="op-a")


# ---------------------------------------------------------------------- M1
def test_m1_no_persist_detected(tmp_path, clock):
    db_path = str(tmp_path / "m1.db")
    store = DurableStateStore(db_path, clock)
    store.init_schema(initial_budget_minor=10_000, policy_version="policy-v1")
    authz = AuthorizationService(store, clock)
    ks = KillSwitchController(store, clock, recovery_token="test-recovery-token")

    with pytest.MonkeyPatch.context() as mp:
        m1_no_persist.apply(mp, store=store, authz=authz, killswitch=ks, clock=clock)
        ks.trip()

    fresh = DurableStateStore(db_path, clock)
    assert fresh.get_switch().state.value == "ARMED", "M1 not detected: TRIP persisted to disk"


# ---------------------------------------------------------------------- M2
def test_m2_skip_commit_check_detected(store, authz, killswitch, clock, monkeypatch):
    m2_skip_commit_check.apply(monkeypatch, store=store, authz=authz, killswitch=killswitch, clock=clock)
    req = _issue(authz)
    killswitch.trip()

    result = real_commit.commit_protected_action(store, authz, req, clock)
    assert result.reason_code != "switch_tripped", "M2 not detected: reason_code still switch_tripped"
    assert result.reason_code in ("ok", "stale_epoch", "decision_expired", "policy_mismatch")


# ---------------------------------------------------------------------- M3
def test_m3_recover_clears_detected(store, authz, killswitch, clock, monkeypatch):
    m3_recover_clears.apply(monkeypatch, store=store, authz=authz, killswitch=killswitch, clock=clock)
    killswitch.trip()
    authorized = killswitch.recover(token="definitely-wrong-token")
    assert authorized is True, "M3 not detected: mutant rejected unauthorized recovery"
    assert store.get_switch().state.value == "ARMED"


# ---------------------------------------------------------------------- M4
def test_m4_alt_bypass_detected(store, authz, killswitch, clock, monkeypatch):
    from harness.app import create_app
    from harness.config import Settings

    settings = Settings(db_path=store.db_path, policy_version="policy-v1", initial_budget_minor=10_000, recovery_token="test-recovery-token", harness_env="test", staleness_window_us=5 * 60 * 1_000_000)
    app = create_app(settings=settings, clock=clock)
    store2 = app.state.store
    authz2 = app.state.authz
    ks2 = app.state.killswitch

    m4_alt_bypass.apply(monkeypatch, store=store2, authz=authz2, killswitch=ks2, clock=clock, app=app)
    
    alt_handler = None
    for r in app.router.routes:
        if getattr(r, "path", None) == "/actions/alt":
            alt_handler = r.endpoint
            break
    assert alt_handler is not None, "M4 mutation: /actions/alt route missing"

    ks2.trip()
    before = store2.count_actions()
    d = authz2.issue(AuthzIssueRequest(request_id="r-alt", identity="op-a", amount_minor=100))
    req = ActionRequest(request_id="r-alt", action_id="refund", amount_minor=100, currency="USD", decision_id=d.decision_id, idempotency_key="k-alt", identity="op-a")
    
    alt_handler(req=req, x_test_identity="op-a")
    after = store2.count_actions()
    assert after == before + 1, "M4 not detected: alt handler did not insert a row under TRIP"


# ---------------------------------------------------------------------- M5
def test_m5_ignore_epoch_detected(store, authz, killswitch, clock, monkeypatch):
    m5_ignore_epoch.apply(monkeypatch, store=store, authz=authz, killswitch=killswitch, clock=clock)
    req = _issue(authz)
    killswitch.trip()
    killswitch.recover(token="test-recovery-token")

    result = real_commit.commit_protected_action(store, authz, req, clock)
    assert result.outcome == "SUCCESS", f"M5 not detected: expected bypass SUCCESS, got {result.outcome}/{result.reason_code}"


# ---------------------------------------------------------------------- M6
def test_m6_dup_retry_detected(store, authz, killswitch, clock, monkeypatch):
    m6_dup_retry.apply(monkeypatch, store=store, authz=authz, killswitch=killswitch, clock=clock)
    req = _issue(authz)

    first = real_commit.commit_protected_action(store, authz, req, clock)
    assert first.outcome == "SUCCESS"
    
    second = real_commit.commit_protected_action(store, authz, req, clock)
    assert second.replayed is False, "M6 not detected: second call was replayed"
    assert second.outcome == "REJECTED", f"M6 not detected: second outcome={second.outcome}/{second.reason_code}"
    assert second.reason_code == "decision_consumed"


# ---------------------------------------------------------------------- M7
def test_m7_different_payload_detected(store, authz, clock, monkeypatch):
    """M7: Idempotency key reused with a different request payload."""
    m7_idempotency_different_payload.apply(monkeypatch, store=store, authz=authz, killswitch=None, clock=clock)
    
    d = authz.issue(AuthzIssueRequest(request_id="r1", identity="op-a", amount_minor=100))
    req1 = ActionRequest(request_id="r1", action_id="refund", amount_minor=100, currency="USD", decision_id=d.decision_id, idempotency_key="k1", identity="op-a")
    
    r1 = real_commit.commit_protected_action(store, authz, req1, clock)
    assert r1.outcome == "SUCCESS"
    
    # Create a new request with the SAME key, SAME decision, but a DIFFERENT amount
    req2 = ActionRequest(request_id="r1", action_id="refund", amount_minor=500, currency="USD", decision_id=d.decision_id, idempotency_key="k1", identity="op-a")
    r2 = real_commit.commit_protected_action(store, authz, req2, clock)
    
    # The mutant allows this to pass (either SUCCESS or a bypass of the mismatch check)
    assert r2.outcome == "SUCCESS", "M7 not detected: expected the different-payload replay to succeed"


# ---------------------------------------------------------------------- M8
def test_m8_reuse_consumed_detected(store, authz, clock, monkeypatch):
    """M8: Reuse of an already-consumed authorization.

    The reference enforces 'decision once' at TWO layers:
      (1) commit.py checks `authorizations.consumed == 0`.
      (2) schema constrains `actions.decision_id` UNIQUE.

    The mutant removes layer (1). To demonstrate the violation end-to-end,
    this test removes layer (2) by recreating `actions` without the UNIQUE
    constraint. Two actions sharing a decision_id then coexist, proving the
    logical check was the load-bearing protection.
    """
    with store.writer() as conn:
        conn.execute("ALTER TABLE actions RENAME TO actions_old")
        conn.execute(
            "CREATE TABLE actions ("
            "  rowid INTEGER PRIMARY KEY,"
            "  action_id TEXT NOT NULL,"
            "  decision_id TEXT NOT NULL,"
            "  request_id TEXT NOT NULL,"
            "  identity TEXT NOT NULL,"
            "  amount_minor INTEGER NOT NULL,"
            "  currency TEXT NOT NULL,"
            "  epoch INTEGER NOT NULL,"
            "  committed_at_us INTEGER NOT NULL,"
            "  idempotency_key TEXT NOT NULL UNIQUE"
            ")"
        )
        conn.execute("DROP TABLE actions_old")

    m8_reuse_consumed_auth.apply(monkeypatch, store=store, authz=authz, killswitch=None, clock=clock)

    d = authz.issue(AuthzIssueRequest(request_id="r1", identity="op-a", amount_minor=100))
    req1 = ActionRequest(
        request_id="r1", action_id="refund", amount_minor=100, currency="USD",
        decision_id=d.decision_id, idempotency_key="k1", identity="op-a",
    )
    r1 = real_commit.commit_protected_action(store, authz, req1, clock)
    assert r1.outcome == "SUCCESS"

    req2 = ActionRequest(
        request_id="r1", action_id="refund", amount_minor=100, currency="USD",
        decision_id=d.decision_id, idempotency_key="k2", identity="op-a",
    )
    r2 = real_commit.commit_protected_action(store, authz, req2, clock)
    assert r2.outcome == "SUCCESS", "M8 not detected: expected the second commit to succeed"
    assert store.count_actions() == 2, "M8 not detected: expected two action rows"


def test_m9_budget_overspend_detected(store, authz, clock, monkeypatch):
    """M9: Budget overspending caused by removing the atomic guard."""
    m9_budget_overspend.apply(monkeypatch, store=store, authz=authz, killswitch=None, clock=clock)

    d1 = authz.issue(AuthzIssueRequest(request_id="r1", identity="op-a", amount_minor=10_000))
    d2 = authz.issue(AuthzIssueRequest(request_id="r2", identity="op-a", amount_minor=10_000))

    barrier = threading.Barrier(2)
    results = {}

    req1 = ActionRequest(
        request_id="r1", action_id="refund", amount_minor=10_000, currency="USD",
        decision_id=d1.decision_id, idempotency_key="k1", identity="op-a",
    )
    req2 = ActionRequest(
        request_id="r2", action_id="refund", amount_minor=10_000, currency="USD",
        decision_id=d2.decision_id, idempotency_key="k2", identity="op-a",
    )

    def worker(name, req):
        barrier.wait()
        results[name] = real_commit.commit_protected_action(store, authz, req, clock)

    t1 = threading.Thread(target=worker, args=("t1", req1))
    t2 = threading.Thread(target=worker, args=("t2", req2))
    t1.start(); t2.start(); t1.join(); t2.join()

    assert results["t1"].outcome == "SUCCESS"
    assert results["t2"].outcome == "SUCCESS"
    assert store.get_budget_remaining() == -10_000, (
        f"M9 not detected: expected budget to go negative, got {store.get_budget_remaining()}"
    )
    assert store.count_actions() == 2
# ---------------------------------------------------------------------- M10
def test_m10_stale_evidence_detected(store, authz, clock, monkeypatch):
    """M10: Stale evidence incorrectly receives PASS."""
    m10_stale_evidence_pass.apply(monkeypatch, store=store, authz=authz, killswitch=None, clock=clock)
    
    # Generate a chain that's within the staleness window
    from harness.commit import commit_protected_action
    d = authz.issue(AuthzIssueRequest(request_id="r1", identity="op-a", amount_minor=100))
    req = ActionRequest(request_id="r1", action_id="refund", amount_minor=100, currency="USD", decision_id=d.decision_id, idempotency_key="k1", identity="op-a")
    commit_protected_action(store, authz, req, clock)
    
    # Advance the clock past the staleness window
    clock.advance(10 * 60 * 1_000_000)  # 10 minutes
    
    from harness.verifier import Verifier
    from harness.store import DurableStateStore
    ro = DurableStateStore(store.db_path, clock, readonly=True)
    
    # Under the mutant, evidence_current is always PASS.
    v = Verifier(ro, clock, staleness_window_us=60 * 1_000_000)  # 1 minute window
    report = v.verify()
    by_name = {p.name: p for p in report.properties}
    
    assert by_name["evidence_current"].status == "PASS", "M10 not detected: evidence_current should be forced to PASS"