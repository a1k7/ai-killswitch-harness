"""Scenario 13b: in-flight races.

Covers Tests E-G from the engineering task:

    E. Cancellation race: commit-before-trip (SUCCESS) and trip-before-commit
       (REJECTED). The linearization point is SQLite's writer lock; we do not
       force an ordering via sleep, we serialize the two operations sequentially
       in the two directed cases so the order is provable, plus a Barrier test
       that accepts either outcome.
    F. Multiple in-flight operations: all trip; none commit.
    G. Non-cooperative worker: commit boundary still enforces.
"""
from __future__ import annotations

import threading
from typing import Any

from harness.commit import commit_protected_action
from harness.inflight import TerminalOutcome
from harness.schemas import ActionRequest, AuthzIssueRequest


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
# Test E — cancellation race
# =========================================================================
def test_e_commit_before_trip(store, authz, clock, killswitch, inflight):
    """Ordering 1: commit runs to completion, THEN trip fires."""
    d, req = _issue_and_request(authz, "rE1", amount=100)
    op = inflight.admit(d.decision_id)

    result = commit_protected_action(store, authz, req, clock)
    assert result.outcome == "SUCCESS"
    inflight.record_terminal(op.operation_id, TerminalOutcome.SUCCEEDED.value)

    killswitch.trip()
    # Trip afterwards does not retract a completed commit.
    assert store.count_actions() == 1
    assert inflight.active_count() == 0


def test_e_trip_before_commit(store, authz, clock, killswitch, inflight):
    """Ordering 2: trip runs to completion, THEN commit attempts."""
    d, req = _issue_and_request(authz, "rE2", amount=100)
    op = inflight.admit(d.decision_id)

    killswitch.trip()
    assert op.cancel_event.is_set()

    # Non-cooperative: worker ignores cancellation and commits anyway.
    result = commit_protected_action(store, authz, req, clock)
    assert result.outcome == "REJECTED"
    assert result.reason_code == "switch_tripped"
    inflight.record_terminal(op.operation_id, TerminalOutcome.REJECTED_AT_COMMIT.value)

    assert store.count_actions() == 0
    assert inflight.active_count() == 0


def test_e_concurrent_race_consistency(store, authz, clock, killswitch, inflight):
    """Barrier: commit and trip fire simultaneously. Whatever order SQLite's
    writer lock grants, the observable outcome must be consistent with ONE of:
      - commit linearized first -> SUCCESS, action exists, switch is TRIPPED
        afterwards, terminal recorded as SUCCEEDED.
      - trip linearized first   -> REJECTED/switch_tripped, no action, terminal
        recorded as REJECTED_AT_COMMIT.
    """
    d, req = _issue_and_request(authz, "rE3", amount=100)
    op = inflight.admit(d.decision_id)
    barrier = threading.Barrier(2)
    outcomes: dict[str, Any] = {}

    def trip_thread():
        barrier.wait()
        outcomes["trip"] = killswitch.trip(actor="racer", reason="race")

    def commit_thread():
        barrier.wait()
        r = commit_protected_action(store, authz, req, clock)
        outcomes["commit"] = r
        if r.outcome == "SUCCESS":
            inflight.record_terminal(op.operation_id, TerminalOutcome.SUCCEEDED.value)
        else:
            inflight.record_terminal(
                op.operation_id, TerminalOutcome.REJECTED_AT_COMMIT.value
            )

    t1 = threading.Thread(target=trip_thread)
    t2 = threading.Thread(target=commit_thread)
    t1.start(); t2.start(); t1.join(); t2.join()

    assert "trip" in outcomes and "commit" in outcomes
    assert store.get_switch().state.value == "TRIPPED"

    if outcomes["commit"].outcome == "SUCCESS":
        assert store.count_actions() == 1
        assert outcomes["commit"].reason_code == "ok"
    else:
        assert outcomes["commit"].outcome == "REJECTED"
        assert outcomes["commit"].reason_code == "switch_tripped"
        assert store.count_actions() == 0
    assert inflight.active_count() == 0


# =========================================================================
# Test F — multiple in-flight operations
# =========================================================================
def test_f_multiple_operations_all_blocked(store, authz, clock, killswitch, inflight):
    """Start 5 operations, all admitted. Trip. All must have cancel_event set.
    Non-cooperative workers attempt commit; all are rejected at commit; no
    action row exists."""
    ops = []
    reqs = []
    for i in range(5):
        d, req = _issue_and_request(authz, f"rF{i}", amount=100)
        ops.append(inflight.admit(d.decision_id))
        reqs.append(req)
    assert inflight.active_count() == 5

    killswitch.trip()
    for op in ops:
        assert op.cancel_event.is_set()

    # Non-cooperative workers proceed to commit anyway.
    for i, req in enumerate(reqs):
        r = commit_protected_action(store, authz, req, clock)
        assert r.outcome == "REJECTED"
        assert r.reason_code == "switch_tripped"
        inflight.record_terminal(ops[i].operation_id, TerminalOutcome.REJECTED_AT_COMMIT.value)

    assert store.count_actions() == 0
    assert store.get_budget_remaining() == 10_000
    assert inflight.active_count() == 0


# =========================================================================
# Test G — non-cooperative worker
# =========================================================================
def test_g_non_cooperative_worker_commit_boundary_enforces(
    store, authz, clock, killswitch, inflight
):
    """Worker ignores the cancel event. The commit boundary is the only
    enforcement that matters; it must reject."""
    d, req = _issue_and_request(authz, "rG", amount=100)
    op = inflight.admit(d.decision_id)
    admitted = threading.Event()
    proceed = threading.Event()
    outcome: dict[str, Any] = {}

    def worker():
        admitted.set()
        proceed.wait(timeout=10)
        # Deliberately ignore op.cancel_event. Do NOT acknowledge.
        # Attempt commit anyway.
        r = commit_protected_action(store, authz, req, clock)
        outcome["outcome"] = r.outcome
        outcome["reason"] = r.reason_code
        inflight.record_terminal(
            op.operation_id, TerminalOutcome.REJECTED_AT_COMMIT.value
            if r.outcome == "REJECTED"
            else TerminalOutcome.SUCCEEDED.value,
        )

    t = threading.Thread(target=worker)
    t.start()
    admitted.wait(timeout=10)

    killswitch.trip()
    proceed.set()
    t.join(timeout=10)
    assert not t.is_alive()

    assert outcome["outcome"] == "REJECTED"
    assert outcome["reason"] == "switch_tripped"
    assert store.count_actions() == 0
    assert inflight.active_count() == 0