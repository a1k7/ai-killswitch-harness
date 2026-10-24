"""M12: commit boundary skips the switch-state check.

The mutant forces state=ARMED AND forces epoch=decision.epoch. Both layers
must be bypassed for the commit to succeed, because the reference has
defense-in-depth: switch-state and epoch are checked independently. This
mutant demonstrates the "both checks bypassed" scenario.

Detected by: test_m12_commit_skips_switch_detected.
"""
from __future__ import annotations

import json
from typing import Any

import harness.commit as real_commit
from ..schemas import SwitchState, SwitchStatus

_ORIGINAL = real_commit.commit_protected_action


def _commit_skipping_switch_and_epoch(store, authz, request, clock=None):
    row = store.get_authorization(request.decision_id)
    decision_epoch = 1
    if row is not None:
        decision = json.loads(row["request_json"])
        decision_epoch = int(decision["epoch"])

    real_get = store.get_switch_conn

    def fake_get(conn):
        s = real_get(conn)
        return SwitchStatus(
            state=SwitchState.ARMED,
            epoch=decision_epoch,
            policy_version=s.policy_version,
            updated_at_us=s.updated_at_us,
        )

    store.get_switch_conn = fake_get
    try:
        return _ORIGINAL(store, authz, request, clock)
    finally:
        store.get_switch_conn = real_get


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None, inflight=None) -> None:
    monkeypatch.setattr(real_commit, "commit_protected_action", _commit_skipping_switch_and_epoch)
    if app is not None:
        import harness.app as real_app
        monkeypatch.setattr(real_app, "commit_protected_action", _commit_skipping_switch_and_epoch)
