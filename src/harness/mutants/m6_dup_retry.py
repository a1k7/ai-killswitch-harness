"""M6: idempotency short-circuit is bypassed on retry."""
from __future__ import annotations

from typing import Any

import harness.commit as real_commit

_ORIGINAL_COMMIT = real_commit.commit_protected_action


def _commit_without_idempotency(store, authz, request, clock=None):
    with store.writer() as conn:
        conn.execute("DELETE FROM idempotency WHERE key = ?", (request.idempotency_key,))
    return _ORIGINAL_COMMIT(store, authz, request, clock)


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None) -> None:
    monkeypatch.setattr(real_commit, "commit_protected_action", _commit_without_idempotency)
    if app is not None:
        import harness.app as real_app
        monkeypatch.setattr(real_app, "commit_protected_action", _commit_without_idempotency)