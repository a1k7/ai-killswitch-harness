"""Scenario 6: concurrent actions.

Two sub-tests:
  (a) Distinct valid decisions, both submitted at once. Under SQLite's
      BEGIN IMMEDIATE serialization both commits should succeed (one action
      per decision) and the audit chain must remain intact.

  (b) The SAME decision submitted by two threads. Exactly one commits; the
      other is rejected with reason_code == "decision_consumed" because the
      nonce-consumption check is atomic on the writer.

No sleeps are used. Barrier is the only synchronization primitive.
"""
from __future__ import annotations

import threading

from harness.audit import AuditChain
from harness.commit import commit_protected_action
from harness.schemas import ActionRequest, AuthzIssueRequest


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


def test_two_distinct_decisions_both_commit(store, authz, clock):
    d1 = authz.issue(
        AuthzIssueRequest(request_id="r1", identity="op-a", amount_minor=100)
    )
    d2 = authz.issue(
        AuthzIssueRequest(request_id="r2", identity="op-a", amount_minor=100)
    )

    barrier = threading.Barrier(2)
    results: dict = {}

    def worker(name: str, decision):
        barrier.wait()
        results[name] = commit_protected_action(
            store, authz, _mk(decision, f"k-{name}"), clock
        )

    t1 = threading.Thread(target=worker, args=("t1", d1))
    t2 = threading.Thread(target=worker, args=("t2", d2))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results["t1"].outcome == "SUCCESS", results["t1"]
    assert results["t2"].outcome == "SUCCESS", results["t2"]
    assert store.count_actions() == 2
    assert store.get_budget_remaining() == 10_000 - 200

    events = AuditChain.read_all(store)
    ok, detail = AuditChain.verify_chain(events)
    assert ok, detail


def test_same_decision_race_yields_one_commit(store, authz, clock):
    decision = authz.issue(
        AuthzIssueRequest(request_id="rS", identity="op-a", amount_minor=100)
    )

    barrier = threading.Barrier(2)
    results: dict = {}

    def worker(name: str):
        barrier.wait()
        results[name] = commit_protected_action(
            store, authz, _mk(decision, f"k-shared-{name}"), clock
        )

    t1 = threading.Thread(target=worker, args=("t1",))
    t2 = threading.Thread(target=worker, args=("t2",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    outcomes = sorted([results["t1"].outcome, results["t2"].outcome])
    assert outcomes == ["REJECTED", "SUCCESS"], outcomes
    assert store.count_actions() == 1

    losing = (
        results["t1"] if results["t1"].outcome == "REJECTED" else results["t2"]
    )
    assert losing.reason_code == "decision_consumed", losing

    events = AuditChain.read_all(store)
    ok, detail = AuditChain.verify_chain(events)
    assert ok, detail