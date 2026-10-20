"""Scenario 2: TRIP blocks new actions at the commit boundary."""
from __future__ import annotations

from harness.commit import commit_protected_action
from harness.schemas import ActionRequest, AuthzIssueRequest


def _issue(authz, request_id: str, amount_minor: int = 100):
    return authz.issue(
        AuthzIssueRequest(
            request_id=request_id,
            identity="op-a",
            amount_minor=amount_minor,
            currency="USD",
            ttl_seconds=30,
        )
    )


def test_trip_blocks_new_actions(store, authz, killswitch, clock):
    d = _issue(authz, "r-pre")
    killswitch.trip(actor="op-a", reason="test")

    req = ActionRequest(
        request_id="r-pre",
        action_id="refund",
        amount_minor=100,
        currency="USD",
        decision_id=d.decision_id,
        idempotency_key="k1",
        identity="op-a",
    )
    result = commit_protected_action(store, authz, req, clock)

    assert result.outcome == "REJECTED"
    assert result.reason_code == "switch_tripped"
    assert store.count_actions() == 0
    assert store.get_budget_remaining() == 10_000

    rejected = [
        e for e in store.list_audit() if e["event_type"] == "ACTION_REJECTED"
    ]
    assert len(rejected) == 1


def test_trip_then_alt_request_is_also_rejected(store, authz, killswitch, clock):
    """Guard is at commit, not per-route; a direct call must reject too."""
    d = _issue(authz, "r-alt")
    killswitch.trip()

    req = ActionRequest(
        request_id="r-alt",
        action_id="refund",
        amount_minor=100,
        currency="USD",
        decision_id=d.decision_id,
        idempotency_key="k-alt",
        identity="op-a",
    )
    result = commit_protected_action(store, authz, req, clock)
    assert result.outcome == "REJECTED"
    assert result.reason_code == "switch_tripped"