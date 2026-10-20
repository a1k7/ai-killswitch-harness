"""M5: commit_protected_action does not compare decision.epoch to switch.epoch."""
from __future__ import annotations

import json as _json
from typing import Any

import harness.commit as real_commit
from ..schemas import SwitchState, SwitchStatus

_ORIGINAL_COMMIT = real_commit.commit_protected_action


def _commit_ignoring_epoch(store, authz, request, clock=None):
    row = store.get_authorization(request.decision_id)
    if row is None:
        return _ORIGINAL_COMMIT(store, authz, request, clock)
    decision = _json.loads(row["request_json"])
    real_get = store.get_switch_conn

    def fake_get_switch_conn(conn):
        s = real_get(conn)
        return SwitchStatus(state=s.state, epoch=int(decision["epoch"]), policy_version=s.policy_version, updated_at_us=s.updated_at_us)

    store.get_switch_conn = fake_get_switch_conn  # type: ignore[method-assign]
    try:
        return _ORIGINAL_COMMIT(store, authz, request, clock)
    finally:
        store.get_switch_conn = real_get  # type: ignore[method-assign]


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None) -> None:
    monkeypatch.setattr(real_commit, "commit_protected_action", _commit_ignoring_epoch)
    if app is not None:
        import harness.app as real_app
        monkeypatch.setattr(real_app, "commit_protected_action", _commit_ignoring_epoch)