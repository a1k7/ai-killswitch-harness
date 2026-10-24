"""Scenario 14: detection tests for in-flight mutants (M11-M16).

Each test applies one mutant and asserts the faulty behavior occurs.
The assertion is inverted from a normal test: we PASS when the mutant
misbehaves, because that proves the mutant was actually exercised.

If a mutant is a no-op (e.g., the monkeypatch failed to take effect),
the corresponding test fails, which is how report.py's matrix detects
"mutant not exercised".
"""
from __future__ import annotations

import threading
from typing import Any

import pytest

import harness.commit as real_commit
from harness.app import create_app
from harness.authz import AuthorizationService
from harness.clock import ManualClock
from harness.commit import commit_protected_action
from harness.config import Settings
from harness.inflight import InFlightRegistry, OperationDenied, TerminalOutcome
from harness.killswitch import KillSwitchController
from harness.schemas import ActionRequest, AuthzIssueRequest
from harness.store import DurableStateStore

from harness.mutants import (
    m11_trip_skips_cancel,
    m12_commit_skips_switch,
    m13_commit_skips_epoch,
    m14_lie_terminal,
    m15_alt_route_bypass,
    m16_recover_revives,
)

TEST_TOKEN = "test-recovery-token"


def _issue(authz, request_id: str, amount: int = 100):
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


# ===================================================================== M11
def test_m11_trip_skips_cancel_detected(
    store, authz, clock, killswitch, inflight, monkeypatch
):
    """M11: trip() sets switch state but does NOT fan out cancellation.
    Detection: after applying the mutant and calling trip(), the cancel_event
    of an already-admitted operation is still unset."""
    d, _req = _issue(authz, "m11")
    op = inflight.admit(d.decision_id)
    assert op.cancel_event.is_set() is False

    m11_trip_skips_cancel.apply(
        monkeypatch, store=store, authz=authz, killswitch=killswitch,
        clock=clock, inflight=inflight,
    )
    killswitch.trip()

    assert op.cancel_event.is_set() is False, (
        "M11 not detected: cancel_event was set (mutant must have called cancel_all)"
    )
    # Switch did trip; only the fan-out was missing.
    assert store.get_switch().state.value == "TRIPPED"


# ===================================================================== M12
def test_m12_commit_skips_switch_detected(
    store, authz, clock, killswitch, inflight, monkeypatch
):
    """M12: commit boundary skips the switch-state check.
    Detection: after trip, commit returns SUCCESS under the mutant
    (the reference returns REJECTED/switch_tripped)."""
    d, req = _issue(authz, "m12")
    op = inflight.admit(d.decision_id)
    killswitch.trip()
    assert op.cancel_event.is_set()

    m12_commit_skips_switch.apply(
        monkeypatch, store=store, authz=authz, killswitch=killswitch,
        clock=clock, inflight=inflight,
    )
    result = real_commit.commit_protected_action(store, authz, req, clock)

    assert result.outcome == "SUCCESS", (
        f"M12 not detected: expected bypass SUCCESS, got "
        f"{result.outcome}/{result.reason_code}"
    )
    assert store.count_actions() == 1


# ===================================================================== M13
def test_m13_commit_skips_epoch_detected(
    store, authz, clock, killswitch, inflight, monkeypatch
):
    """M13: commit boundary ignores the epoch check.
    Detection: pre-trip decision attempted AFTER trip+recover commits
    under the mutant (the reference returns REJECTED/stale_epoch)."""
    d, req = _issue(authz, "m13")
    op = inflight.admit(d.decision_id)
    killswitch.trip()
    assert killswitch.recover(token=TEST_TOKEN) is True
    # Now switch is ARMED at epoch 3, decision is at epoch 1.

    m13_commit_skips_epoch.apply(
        monkeypatch, store=store, authz=authz, killswitch=killswitch,
        clock=clock, inflight=inflight,
    )
    result = real_commit.commit_protected_action(store, authz, req, clock)

    assert result.outcome == "SUCCESS", (
        f"M13 not detected: expected bypass SUCCESS, got "
        f"{result.outcome}/{result.reason_code}"
    )
    assert store.count_actions() == 1


# ===================================================================== M14
def test_m14_lie_terminal_detected(
    store, authz, clock, killswitch, inflight, monkeypatch
):
    """M14: record_terminal overwrites a SUCCEEDED record with CANCELLED_BY_WORKER.
    Detection: after a successful commit and a record_terminal(SUCCEEDED),
    the mutant's record_terminal(CANCELLED_BY_WORKER) overwrites it, so
    the inflight_operations row now claims cancellation even though the
    action row exists."""
    d, req = _issue(authz, "m14")
    op = inflight.admit(d.decision_id)

    # Commit succeeds normally (no trip).
    result = real_commit.commit_protected_action(store, authz, req, clock)
    assert result.outcome == "SUCCESS"
    inflight.record_terminal(op.operation_id, TerminalOutcome.SUCCEEDED.value)

    # Now apply mutant and call record_terminal again with a cancellation.
    m14_lie_terminal.apply(
        monkeypatch, store=store, authz=authz, killswitch=killswitch,
        clock=clock, inflight=inflight,
    )
    inflight.record_terminal(op.operation_id, TerminalOutcome.CANCELLED_BY_WORKER.value)

    # Under the mutant, the row was overwritten. Two contradictory facts
    # coexist: action exists AND operation reports cancelled.
    with store.reader() as conn:
        row = conn.execute(
            "SELECT terminal_outcome FROM inflight_operations"
            " WHERE operation_id = ?", (op.operation_id,),
        ).fetchone()
    assert row is not None
    assert row["terminal_outcome"] == "cancelled_by_worker", (
        f"M14 not detected: expected overwrite to cancelled_by_worker, "
        f"got {row['terminal_outcome']}"
    )
    assert store.count_actions() == 1, (
        "M14: action row should still exist; the lie is that the operation "
        "claims cancellation while the action is committed"
    )


# ===================================================================== M15
def test_m15_alt_route_bypass_detected(
    store, authz, clock, killswitch, inflight, monkeypatch
):
    """M15: /actions/alt route bypasses the guarded commit.
    Detection: after trip, POST to /actions/alt inserts an action row under
    the mutant (the reference rejects)."""
    settings = Settings(
        db_path=store.db_path, policy_version="policy-v1",
        initial_budget_minor=10_000, recovery_token=TEST_TOKEN,
        harness_env="test", staleness_window_us=5 * 60 * 1_000_000,
    )
    app = create_app(settings=settings, clock=clock)
    store2 = app.state.store
    authz2 = app.state.authz
    ks2 = app.state.killswitch

    m15_alt_route_bypass.apply(
        monkeypatch, store=store2, authz=authz2, killswitch=ks2,
        clock=clock, app=app, inflight=None,
    )
    alt_handler = None
    for r in app.router.routes:
        if getattr(r, "path", None) == "/actions/alt":
            alt_handler = r.endpoint
            break
    assert alt_handler is not None, "M15: /actions/alt route missing"

    ks2.trip()
    before = store2.count_actions()
    d = authz2.issue(
        AuthzIssueRequest(request_id="m15", identity="op-a", amount_minor=100)
    )
    req = ActionRequest(
        request_id="m15", action_id="refund", amount_minor=100,
        currency="USD", decision_id=d.decision_id,
        idempotency_key="k-m15", identity="op-a",
    )
    alt_handler(req=req, x_test_identity="op-a")
    after = store2.count_actions()

    assert after == before + 1, (
        f"M15 not detected: bypass handler did not insert a row "
        f"(before={before}, after={after})"
    )


# ===================================================================== M16
def test_m16_recover_revives_detected(
    store, authz, clock, killswitch, inflight, monkeypatch
):
    """M16: recover() clears the cancel_event on active operations and
    rolls the epoch back to 1.
    Detection: after applying the mutant, trip(), then recover(), the
    operation's cancel_event is cleared (reference: it stays set)."""
    d, _req = _issue(authz, "m16")
    op = inflight.admit(d.decision_id)
    killswitch.trip()
    assert op.cancel_event.is_set() is True

    m16_recover_revives.apply(
        monkeypatch, store=store, authz=authz, killswitch=killswitch,
        clock=clock, inflight=inflight,
    )
    assert killswitch.recover(token=TEST_TOKEN) is True

    assert op.cancel_event.is_set() is False, (
        "M16 not detected: cancel_event still set after mutant recover()"
    )
    # And the epoch was rolled back (mutant behavior).
    assert store.get_switch().epoch == 1, (
        f"M16 not detected: epoch should be 1 under the mutant, "
        f"got {store.get_switch().epoch}"
    )