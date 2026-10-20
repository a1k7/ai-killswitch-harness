"""Scenario 7: Retry after shutdown."""
from __future__ import annotations

from harness.commit import commit_protected_action
from harness.schemas import ActionRequest, AuthzIssueRequest


def _build(authz, request_id="r", key="k", amount=100):
    d = authz.issue(
        AuthzIssueRequest(request_id=request_id, identity="op-a", amount_minor=amount)
    )
    return ActionRequest(
        request_id=request_id, action_id="refund", amount_minor=amount,
        currency="USD", decision_id=d.decision_id,
        idempotency_key=key, identity="op-a",
    )


def test_retry_after_shutdown_does_not_create_new_action(store, authz, killswitch, clock):
    # 1. Original action fails BEFORE shutdown (e.g. expired)
    d = authz.issue(AuthzIssueRequest(request_id="r1", identity="op-a", amount_minor=100, ttl_seconds=1))
    req = ActionRequest(
        request_id="r1", action_id="refund", amount_minor=100, currency="USD",
        decision_id=d.decision_id, idempotency_key="k1", identity="op-a",
    )
    clock.advance(2_000_000)  # expire it
    r1 = commit_protected_action(store, authz, req, clock)
    assert r1.outcome == "REJECTED"
    assert r1.reason_code == "decision_expired"

    # 2. TRIP the switch
    killswitch.trip()

    # 3. Retry the exact same request.
    # Because the idempotency key is recorded as REJECTED, it should return
    # the cached rejection, NOT try to execute again.
    r2 = commit_protected_action(store, authz, req, clock)
    assert r2.outcome == "REJECTED"
    assert r2.reason_code == "decision_expired"
    assert r2.replayed is True
    assert store.count_actions() == 0


def test_retry_of_successful_action_returns_success_after_shutdown(store, authz, killswitch, clock):
    req = _build(authz, request_id="r2", key="k2")
    r1 = commit_protected_action(store, authz, req, clock)
    assert r1.outcome == "SUCCESS"

    killswitch.trip()
    r2 = commit_protected_action(store, authz, req, clock)
    assert r2.outcome == "SUCCESS"
    assert r2.replayed is True
    assert store.count_actions() == 1