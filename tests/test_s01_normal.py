"""Scenario 1: normal operation — one issued decision, one committed action."""
from __future__ import annotations

from harness.commit import commit_protected_action
from harness.schemas import ActionRequest, AuthzIssueRequest


def test_normal_operation_commits_once(store, authz, killswitch, clock):
    d = authz.issue(
        AuthzIssueRequest(
            request_id="r1", identity="op-a",
            amount_minor=250, currency="USD", ttl_seconds=30,
        )
    )
    req = ActionRequest(
        request_id="r1", action_id="refund", amount_minor=250, currency="USD",
        decision_id=d.decision_id, idempotency_key="k1", identity="op-a",
    )
    result = commit_protected_action(store, authz, req, clock)
    assert result.outcome == "SUCCESS"
    assert result.reason_code == "ok"
    assert result.replayed is False
    assert store.count_actions() == 1
    assert store.get_budget_remaining() == 10_000 - 250

    with store.reader() as conn:
        row = conn.execute(
            "SELECT outcome, reason_code FROM idempotency WHERE key='k1'"
        ).fetchone()
    assert row["outcome"] == "SUCCESS"
    assert row["reason_code"] == "ok"

    events = [e for e in store.list_audit() if e["event_type"] == "ACTION_COMMITTED"]
    assert len(events) == 1