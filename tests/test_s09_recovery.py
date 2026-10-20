"""Scenario 9: Controlled recovery."""
from __future__ import annotations

from harness.commit import commit_protected_action
from harness.schemas import ActionRequest, AuthzIssueRequest


def test_recovery_requires_authorization(store, authz, killswitch, clock):
    d = authz.issue(AuthzIssueRequest(request_id="r1", identity="op-a", amount_minor=100))
    killswitch.trip()

    # Unauthorized
    assert killswitch.recover(token="wrong-token") is False
    assert killswitch.status().state.value == "TRIPPED"

    # Authorized
    assert killswitch.recover(token="test-recovery-token") is True
    assert killswitch.status().state.value == "ARMED"

    # Old decision is STALE_EPOCH because recovery bumped the epoch
    req = ActionRequest(
        request_id="r1", action_id="refund", amount_minor=100, currency="USD",
        decision_id=d.decision_id, idempotency_key="k1", identity="op-a",
    )
    r = commit_protected_action(store, authz, req, clock)
    assert r.outcome == "REJECTED"
    assert r.reason_code == "stale_epoch"

    # New decision works
    d2 = authz.issue(AuthzIssueRequest(request_id="r2", identity="op-a", amount_minor=100))
    req2 = ActionRequest(
        request_id="r2", action_id="refund", amount_minor=100, currency="USD",
        decision_id=d2.decision_id, idempotency_key="k2", identity="op-a",
    )
    assert commit_protected_action(store, authz, req2, clock).outcome == "SUCCESS"