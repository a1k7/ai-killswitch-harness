"""Scenario 13a: in-flight operations — basic lifecycle.

Covers Tests A-D from the engineering task:

    A. Control case: normal completion without trip.
    B. Kill switch trips before admission -> new admission denied.
    C. Kill switch trips during execution -> cancellation requested; worker
       observes it and does not commit.
    D. In-flight operation attempts to commit AFTER trip -> commit boundary
       rejects; no side effect.
"""
from __future__ import annotations

import threading
from typing import Any

from harness.authz import AuthorizationService
from harness.clock import ManualClock
from harness.commit import commit_protected_action
from harness.inflight import InFlightRegistry, OperationDenied, TerminalOutcome
from harness.killswitch import KillSwitchController
from harness.schemas import ActionRequest, AuthzIssueRequest
from harness.store import DurableStateStore


def _issue_and_request(authz: AuthorizationService, request_id: str, amount: int = 100):
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
# Test A — control: normal completion
# =========================================================================
def test_a_normal_completion(store, authz, clock, killswitch, inflight):
    d, req = _issue_and_request(authz, "rA", amount=100)
    op = inflight.admit(d.decision_id)
    assert inflight.active_count() == 1

    # No trip. The worker runs to completion normally.
    result = commit_protected_action(store, authz, req, clock)
    assert result.outcome == "SUCCESS"
    inflight.record_terminal(op.operation_id, TerminalOutcome.SUCCEEDED.value)

    assert store.count_actions() == 1
    assert store.get_budget_remaining() == 10_000 - 100
    assert inflight.active_count() == 0


# =========================================================================
# Test B — trip before admission
# =========================================================================
def test_b_trip_before_admission(store, authz, clock, killswitch, inflight):
    killswitch.trip()
    d, req = _issue_and_request(authz, "rB", amount=100)

    with __import__("pytest").raises(OperationDenied):
        inflight.admit(d.decision_id)

    # Even if someone later calls commit, the boundary rejects.
    result = commit_protected_action(store, authz, req, clock)
    assert result.outcome == "REJECTED"
    assert result.reason_code == "switch_tripped"
    assert store.count_actions() == 0
    assert inflight.active_count() == 0


# =========================================================================
# Test C — trip during execution; cooperative worker observes cancellation
# =========================================================================
def test_c_trip_during_execution_cooperative(
    store, authz, clock, killswitch, inflight
):
    d, req = _issue_and_request(authz, "rC", amount=100)
    op = inflight.admit(d.decision_id)

    admitted = threading.Event()
    allowed_to_continue = threading.Event()
    outcome: dict[str, Any] = {}

    def worker():
        admitted.set()
        # Deterministic pause: block until the test signals us.
        allowed_to_continue.wait(timeout=10)
        # Cooperative worker: check the cancel event before committing.
        if op.cancel_event.is_set():
            inflight.acknowledge_cancellation(op.operation_id)
            inflight.record_terminal(
                op.operation_id, TerminalOutcome.CANCELLED_BY_WORKER.value
            )
            outcome["status"] = "cancelled_before_commit"
            return
        # Not cancelled -> commit normally.
        result = commit_protected_action(store, authz, req, clock)
        outcome["status"] = result.outcome
        inflight.record_terminal(
            op.operation_id,
            TerminalOutcome.SUCCEEDED.value
            if result.outcome == "SUCCESS"
            else TerminalOutcome.REJECTED_AT_COMMIT.value,
        )

    t = threading.Thread(target=worker)
    t.start()
    admitted.wait(timeout=10)
    assert inflight.active_count() == 1

    killswitch.trip()
    # The trip set the cancel event.
    assert op.cancel_event.is_set() is True
    # Release the worker.
    allowed_to_continue.set()
    t.join(timeout=10)
    assert not t.is_alive()

    assert outcome["status"] == "cancelled_before_commit"
    assert store.count_actions() == 0
    assert store.get_budget_remaining() == 10_000
    assert inflight.active_count() == 0


# =========================================================================
# Test D — non-cooperative worker attempts commit AFTER trip
# =========================================================================
def test_d_commit_after_trip_rejected(store, authz, clock, killswitch, inflight):
    d, req = _issue_and_request(authz, "rD", amount=100)
    op = inflight.admit(d.decision_id)

    admitted = threading.Event()
    allowed_to_continue = threading.Event()
    outcome: dict[str, Any] = {}

    def worker():
        admitted.set()
        allowed_to_continue.wait(timeout=10)
        # Non-cooperative: ignore the cancel event; call commit anyway.
        result = commit_protected_action(store, authz, req, clock)
        outcome["status"] = result.outcome
        outcome["reason"] = result.reason_code
        inflight.record_terminal(
            op.operation_id,
            TerminalOutcome.REJECTED_AT_COMMIT.value
            if result.outcome == "REJECTED"
            else TerminalOutcome.SUCCEEDED.value,
        )

    t = threading.Thread(target=worker)
    t.start()
    admitted.wait(timeout=10)
    assert inflight.active_count() == 1

    killswitch.trip()
    allowed_to_continue.set()
    t.join(timeout=10)
    assert not t.is_alive()

    # The commit boundary rejected because switch state was TRIPPED.
    assert outcome["status"] == "REJECTED"
    assert outcome["reason"] == "switch_tripped"
    assert store.count_actions() == 0
    assert store.get_budget_remaining() == 10_000
    assert inflight.active_count() == 0