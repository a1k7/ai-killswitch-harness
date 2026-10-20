"""Scenario 4: stale authorization is rejected at commit time."""
from __future__ import annotations

from harness.commit import commit_protected_action
from harness.schemas import ActionRequest, AuthzIssueRequest


def test_pre_trip_decision_rejected_under_trip(store, authz, killswitch, clock):
    d = authz.issue(
        AuthzIssueRequest(
            request_id="r1",
            identity="op-a",
            amount_minor=500,
            currency="USD",
            ttl_seconds=120,
        )
    )
    killswitch.trip()

    req = ActionRequest(
        request_id="r1",
        action_id="refund",
        amount_minor=500,
        currency="USD",
        decision_id=d.decision_id,
        idempotency_key="k1",
        identity="op-a",
    )
    result = commit_protected_action(store, authz, req, clock)
    assert result.outcome == "REJECTED"
    # Under TRIP, the switch check fires first.
    assert result.reason_code == "switch_tripped"
    assert store.count_actions() == 0


def test_pre_trip_decision_rejected_after_recovery_as_stale_epoch(
    store, authz, killswitch, clock
):
    # 1. Issue decision at epoch 1 (ARMED)
    d = authz.issue(
        AuthzIssueRequest(
            request_id="r1",
            identity="op-a",
            amount_minor=500,
            currency="USD",
            ttl_seconds=120,
        )
    )
    
    # 2. Trip -> epoch 2
    killswitch.trip()
    
    # 3. Recover -> epoch 3
    assert killswitch.recover(token="test-recovery-token") is True

    # 4. Attempt to use the epoch-1 decision at epoch-3 switch state.
    req = ActionRequest(
        request_id="r1",
        action_id="refund",
        amount_minor=500,
        currency="USD",
        decision_id=d.decision_id,
        idempotency_key="k1",
        identity="op-a",
    )
    result = commit_protected_action(store, authz, req, clock)
    
    # The switch is ARMED, so it passes the switch check. 
    # It then fails the epoch check -> STALE_EPOCH.
    assert result.outcome == "REJECTED"
    assert result.reason_code == "stale_epoch"
    assert store.count_actions() == 0