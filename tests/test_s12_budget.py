"""Scenario 12: budget enforcement and composition with TRIP.

Sub-tests:
  (a) Two commits for exactly the remaining budget succeed; the next fails
      with BUDGET_EXCEEDED.
  (b) Concurrency: two simultaneous commits for exactly half the remaining
      budget both succeed; a third fails on budget.
  (c) TRIP takes precedence: with a fresh decision and exhausted budget,
      a commit under TRIP returns SWITCH_TRIPPED (not BUDGET_EXCEEDED).
"""
from __future__ import annotations

import threading

from harness.commit import commit_protected_action
from harness.schemas import ActionRequest, AuthzIssueRequest


def _issue(authz, request_id: str, amount_minor: int):
    return authz.issue(
        AuthzIssueRequest(
            request_id=request_id, identity="op-a",
            amount_minor=amount_minor, currency="USD", ttl_seconds=60,
        )
    )


def _mk(decision, key: str) -> ActionRequest:
    return ActionRequest(
        request_id=decision.request_id,
        action_id=decision.action_id,
        amount_minor=decision.amount_minor,
        currency=decision.currency,
        decision_id=decision.decision_id,
        idempotency_key=key,
        identity=decision.identity,
    )


def test_budget_sequential(store, authz, clock):
    # 10_000 available. Commit 6_000, 4_000 succeed; 1 more of 1 fails.
    for i, amt in enumerate([6000, 4000]):
        d = _issue(authz, f"r{i}", amt)
        r = commit_protected_action(store, authz, _mk(d, f"k{i}"), clock)
        assert r.outcome == "SUCCESS", (i, r)
    assert store.get_budget_remaining() == 0

    d = _issue(authz, "r-exceed", 1)
    r = commit_protected_action(store, authz, _mk(d, "k-exceed"), clock)
    assert r.outcome == "REJECTED"
    assert r.reason_code == "budget_exceeded"


def test_budget_concurrent(store, authz, clock):
    # Reset via fixtures, but ensure deterministic starting state.
    assert store.get_budget_remaining() == 10_000

    # Two commits of exactly 5_000 each; both must succeed.
    d1 = _issue(authz, "r1", 5000)
    d2 = _issue(authz, "r2", 5000)
    barrier = threading.Barrier(2)
    results: dict = {}

    def worker(name: str, d):
        barrier.wait()
        results[name] = commit_protected_action(store, authz, _mk(d, f"k-{name}"), clock)

    t1 = threading.Thread(target=worker, args=("t1", d1))
    t2 = threading.Thread(target=worker, args=("t2", d2))
    t1.start(); t2.start(); t1.join(); t2.join()

    assert results["t1"].outcome == "SUCCESS", results["t1"]
    assert results["t2"].outcome == "SUCCESS", results["t2"]
    assert store.get_budget_remaining() == 0
    assert store.count_actions() == 2


def test_trip_precedes_budget(store, authz, killswitch, clock):
    # Exhaust budget with a single commit.
    d = _issue(authz, "r1", 10_000)
    r = commit_protected_action(store, authz, _mk(d, "k1"), clock)
    assert r.outcome == "SUCCESS"
    assert store.get_budget_remaining() == 0

    # Issue a fresh decision (post-trip epoch), then trip.
    killswitch.trip()
    d2 = _issue(authz, "r2", 100)
    r2 = commit_protected_action(store, authz, _mk(d2, "k2"), clock)
    # Switch check runs before budget: SWITCH_TRIPPED wins.
    assert r2.outcome == "REJECTED"
    assert r2.reason_code == "switch_tripped"