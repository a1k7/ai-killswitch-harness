"""Scenario 13c: in-flight recovery, idempotency, and evidence.

Covers Tests H-J from the engineering task:

    H. Restart/recovery with an operation still outstanding; recovery does
       not revive stale authorizations; a post-recovery commit by the old
       operation fails on stale_epoch.
    I. Idempotency + retry after cancellation: a retry cannot create a
       duplicate action or bypass the switch check.
    J. Evidence integrity: audit chain records the distinct
       admitted/cancellation_requested/acknowledged/terminal/committed/
       rejected events in correct sequence; tampering with the chain is
       detected by AuditChain.verify_chain.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from harness.audit import AuditChain
from harness.authz import AuthorizationService
from harness.clock import ManualClock
from harness.commit import commit_protected_action
from harness.inflight import InFlightRegistry, TerminalOutcome
from harness.killswitch import KillSwitchController
from harness.schemas import ActionRequest, AuthzIssueRequest
from harness.store import DurableStateStore

REPO_ROOT = Path(__file__).resolve().parent.parent
CHILD = REPO_ROOT / "scripts" / "process_restart_child.py"

TEST_TOKEN = "test-recovery-token"


def _issue_and_request(authz, request_id: str, amount: int = 100):
    d = authz.issue(
        AuthzIssueRequest(
            request_id=request_id, identity="op-a",
            amount_minor=amount, currency="USD", ttl_seconds=60,
        )
    )
    req = ActionRequest(
        request_id=request_id, action_id="refund", amount_minor=amount,
        currency="USD", decision_id=d.decision_id,
        idempotency_key=f"k-{request_id}", identity="op-a",
    )
    return d, req


# =========================================================================
# Test H.1 — recovery does NOT revive a pre-trip decision
# =========================================================================
def test_h_recovery_does_not_revive_pre_trip_decision(
    store, authz, clock, killswitch, inflight
):
    """Admit an operation, trip, then recover. The pre-trip decision must
    still be rejected at commit with stale_epoch. The recovery did not
    silently make the operation valid again."""
    d, req = _issue_and_request(authz, "rH1", amount=100)
    op = inflight.admit(d.decision_id)

    killswitch.trip()
    assert op.cancel_event.is_set()

    # Authorized recovery.
    assert killswitch.recover(token=TEST_TOKEN) is True
    assert store.get_switch().state.value == "ARMED"

    # The old operation's cancel event is still set. Even if the worker
    # ignored it and calls commit, the epoch is bumped -> stale_epoch.
    result = commit_protected_action(store, authz, req, clock)
    assert result.outcome == "REJECTED"
    assert result.reason_code == "stale_epoch"
    inflight.record_terminal(op.operation_id, TerminalOutcome.REJECTED_AT_COMMIT.value)

    assert store.count_actions() == 0
    assert inflight.active_count() == 0


# =========================================================================
# Test H.2 — real process restart with an in-flight op outstanding
# =========================================================================
def test_h_restart_with_operation_outstanding(tmp_path: Path):
    """Trip the switch in a child process, then re-open in the parent.
    A subsequent in-flight-style admission attempt must be denied."""
    db_path = tmp_path / "recover.db"
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    env["HARNESS_ENV"] = "test"
    env["HARNESS_DB_PATH"] = str(db_path)
    env["RECOVERY_TOKEN"] = TEST_TOKEN
    env["HARNESS_POLICY_VERSION"] = "policy-v1"
    env["HARNESS_INITIAL_BUDGET_MINOR"] = "10000"

    # Child trips the switch and exits.
    cp = subprocess.run(
        [sys.executable, str(CHILD), str(db_path)],
        cwd=str(REPO_ROOT), env=env,
        capture_output=True, text=True, check=False, timeout=60,
    )
    assert cp.returncode == 0, cp.stderr
    assert "state=TRIPPED" in cp.stdout, cp.stdout

    # Fresh store, fresh registry. Attempt to admit -> OperationDenied.
    clock = ManualClock()
    store = DurableStateStore(str(db_path), clock)
    authz = AuthorizationService(store, clock)
    reg = InFlightRegistry(store, clock)
    killswitch = KillSwitchController(
        store, clock, recovery_token=TEST_TOKEN, inflight=reg,
    )

    assert store.get_switch().state.value == "TRIPPED"

    d = authz.issue(
        AuthzIssueRequest(
            request_id="rH2", identity="op-a", amount_minor=100,
            currency="USD", ttl_seconds=60,
        )
    )
    from harness.inflight import OperationDenied
    import pytest
    with pytest.raises(OperationDenied):
        reg.admit(d.decision_id)

    # Even a direct commit is rejected.
    req = ActionRequest(
        request_id="rH2", action_id="refund", amount_minor=100,
        currency="USD", decision_id=d.decision_id,
        idempotency_key="k-rH2", identity="op-a",
    )
    result = commit_protected_action(store, authz, req, clock)
    assert result.outcome == "REJECTED"
    assert result.reason_code == "switch_tripped"
    assert store.count_actions() == 0


# =========================================================================
# Test I — idempotency and retry after cancellation
# =========================================================================
def test_i_retry_after_cancellation_does_not_duplicate(
    store, authz, clock, killswitch, inflight
):
    """The operation is cancelled after trip. A retry with the same
    idempotency key returns the recorded rejection, no new action row.
    A retry with a *different* idempotency key is also rejected (switch
    still tripped) and does not create a new action."""
    d, req = _issue_and_request(authz, "rI", amount=100)
    op = inflight.admit(d.decision_id)
    killswitch.trip()

    # First attempt post-trip: rejected at commit boundary.
    r1 = commit_protected_action(store, authz, req, clock)
    assert r1.outcome == "REJECTED"
    assert r1.reason_code == "switch_tripped"
    inflight.record_terminal(op.operation_id, TerminalOutcome.REJECTED_AT_COMMIT.value)

    # Retry same key -> recorded rejection, replayed=True, no second action.
    r2 = commit_protected_action(store, authz, req, clock)
    assert r2.outcome == "REJECTED"
    assert r2.reason_code == "switch_tripped"
    assert r2.replayed is True

    # Retry with a different key but same decision -> still rejected (switch).
    req2 = ActionRequest(
        request_id="rI", action_id="refund", amount_minor=100,
        currency="USD", decision_id=d.decision_id,
        idempotency_key="k-rI-different", identity="op-a",
    )
    r3 = commit_protected_action(store, authz, req2, clock)
    assert r3.outcome == "REJECTED"
    assert r3.reason_code == "switch_tripped"

    assert store.count_actions() == 0
    assert inflight.active_count() == 0


# =========================================================================
# Test J — evidence integrity
# =========================================================================
def test_j_evidence_distinguishes_requested_from_observed(
    store, authz, clock, killswitch, inflight
):
    """The audit chain must contain distinct event types:
        INFLIGHT_ADMITTED
        INFLIGHT_CANCELLATION_REQUESTED
        INFLIGHT_CANCELLATION_ACKNOWLEDGED
        INFLIGHT_TERMINAL_OUTCOME
    And the chain must verify (hash intact).

    'requested' and 'acknowledged' must be distinct events -- the harness
    must not claim cancellation was acknowledged when the worker never
    called acknowledge_cancellation.
    """
    d, req = _issue_and_request(authz, "rJ", amount=100)
    op = inflight.admit(d.decision_id)
    killswitch.trip()

    # Worker is cooperative: acknowledges and records terminal outcome.
    inflight.acknowledge_cancellation(op.operation_id)
    inflight.record_terminal(op.operation_id, TerminalOutcome.CANCELLED_BY_WORKER.value)

    events = AuditChain.read_all(store)
    types = [e.event_type for e in events]

    # Required events present.
    assert "INFLIGHT_ADMITTED" in types
    assert "SWITCH_TRIPPED" in types
    assert "INFLIGHT_CANCELLATION_REQUESTED" in types
    assert "INFLIGHT_CANCELLATION_ACKNOWLEDGED" in types
    assert "INFLIGHT_TERMINAL_OUTCOME" in types

    # Ordered: admitted before requested before acknowledged before terminal.
    def idx(name: str) -> int:
        return types.index(name)

    assert idx("INFLIGHT_ADMITTED") < idx("INFLIGHT_CANCELLATION_REQUESTED")
    assert idx("INFLIGHT_CANCELLATION_REQUESTED") < idx("INFLIGHT_CANCELLATION_ACKNOWLEDGED")
    assert idx("INFLIGHT_CANCELLATION_ACKNOWLEDGED") < idx("INFLIGHT_TERMINAL_OUTCOME")

    # Chain is intact.
    ok, detail = AuditChain.verify_chain(events)
    assert ok, detail


def test_j_tampered_evidence_fails_chain_verification(
    store, authz, clock, killswitch, inflight
):
    """A tampered event must break chain verification."""
    d, req = _issue_and_request(authz, "rJ2", amount=100)
    op = inflight.admit(d.decision_id)
    killswitch.trip()
    inflight.record_terminal(op.operation_id, TerminalOutcome.REJECTED_AT_COMMIT.value)

    # Tamper: mutate the payload of the INFLIGHT_ADMITTED event.
    with store.writer() as conn:
        conn.execute(
            "UPDATE audit_events SET payload_json = ?"
            " WHERE event_type = 'INFLIGHT_ADMITTED'",
            (json.dumps({"tampered": True}),),
        )

    events = AuditChain.read_all(store)
    ok, detail = AuditChain.verify_chain(events)
    assert ok is False
    assert "hash mismatch" in detail or "prev_hash" in detail