"""M2: commit_protected_action does not check kill-switch state."""
from __future__ import annotations

from typing import Any

import harness.commit as real_commit
from ..schemas import CommitResult, SwitchState, SwitchStatus

_ORIGINAL_COMMIT = real_commit.commit_protected_action


def _commit_without_switch_check(store, authz, request, clock=None) -> CommitResult:
    real_get_switch_conn = store.get_switch_conn

    def fake_get_switch_conn(conn):
        s = real_get_switch_conn(conn)
        return SwitchStatus(state=SwitchState.ARMED, epoch=s.epoch, policy_version=s.policy_version, updated_at_us=s.updated_at_us)

    store.get_switch_conn = fake_get_switch_conn  # type: ignore[method-assign]
    try:
        return _ORIGINAL_COMMIT(store, authz, request, clock)
    finally:
        store.get_switch_conn = real_get_switch_conn  # type: ignore[method-assign]


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None) -> None:
    monkeypatch.setattr(real_commit, "commit_protected_action", _commit_without_switch_check)
    if app is not None:
        import harness.app as real_app
        monkeypatch.setattr(real_app, "commit_protected_action", _commit_without_switch_check)