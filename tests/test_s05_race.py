"""Scenario 5: in-flight action racing with shutdown.

Three tests:
  (a) sequential: commit before trip preserves the action.
  (b) sequential: trip before commit rejects.
  (c) true concurrent: two threads behind a Barrier, one calls trip() and one
      calls commit_protected_action(). Exactly one linearization is possible
      per run, but the test asserts:
        - if commit wins: 1 action exists, reason == "ok", and the switch is
          TRIPPED afterwards (the trip thread completed, just after the commit).
        - if trip wins: 0 actions exist, reason == "switch_tripped", and the
          switch is TRIPPED afterwards.

No sleeps. Barrier is the only synchronization primitive.
"""
from __future__ import annotations

import threading

from harness.commit import commit_protected_action
from harness.schemas import ActionRequest, AuthzIssueRequest


def _issue_and_build(authz, request_id="r-race", amount=100):
    d = authz.issue(
        AuthzIssueRequest(
            request_id=request_id,
            identity="op-a",
            amount_minor=amount,
            currency="USD",
            ttl_seconds=120,
        )
    )
    return d, ActionRequest(
        request_id=request_id,
        action_id="refund",
        amount_minor=amount,
        currency="USD",
        decision_id=d.decision_id,
        idempotency_key=f"k-{request_id}",
        identity="op-a",
    )


def test_commit_before_trip_preserves_action(store, authz, killswitch, clock):
    _d, req = _issue_and_build(authz)
    r = commit_protected_action(store, authz, req, clock)
    assert r.outcome == "SUCCESS"
    assert r.reason_code == "ok"
    killswitch.trip()
    assert store.count_actions() == 1


def test_trip_before_commit_rejects(store, authz, killswitch, clock):
    _d, req = _issue_and_build(authz)
    killswitch.trip()
    r = commit_protected_action(store, authz, req, clock)
    assert r.outcome == "REJECTED"
    assert r.reason_code == "switch_tripped"
    assert store.count_actions() == 0


def test_concurrent_race_is_mutually_exclusive(store, authz, killswitch, clock):
    """Both operations are launched simultaneously behind a Barrier.

    Whichever operation acquires the writer lock first wins. We assert:
      - the two outcomes are consistent with ONE of the two linearizations,
      - afterwards the switch is definitely TRIPPED (the trip thread always
        runs to completion),
      - no partial state: if commit won, exactly 1 action exists and the
        recorded reason is 'ok'; if trip won, 0 actions and 'switch_tripped'.
    """
    _d, req = _issue_and_build(authz, request_id="r-race2", amount=200)
    barrier = threading.Barrier(2)
    outcomes: dict = {}

    def trip_thread():
        barrier.wait()
        outcomes["trip"] = killswitch.trip(actor="racer", reason="race")

    def commit_thread():
        barrier.wait()
        outcomes["commit"] = commit_protected_action(store, authz, req, clock)

    t1 = threading.Thread(target=trip_thread)
    t2 = threading.Thread(target=commit_thread)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert "trip" in outcomes, "trip thread did not complete"
    assert "commit" in outcomes, "commit thread did not complete"

    trip_status = outcomes["trip"]
    commit_result = outcomes["commit"]
    action_count = store.count_actions()

    # The switch is TRIPPED after the race, either way.
    assert trip_status.state.value == "TRIPPED"
    assert store.get_switch().state.value == "TRIPPED"

    if commit_result.outcome == "SUCCESS":
        # Commit linearized before TRIP: exactly one action exists.
        assert action_count == 1
        assert commit_result.reason_code == "ok"
    else:
        # TRIP linearized first: no action, rejected on switch state.
        assert commit_result.outcome == "REJECTED"
        assert commit_result.reason_code == "switch_tripped"
        assert action_count == 0