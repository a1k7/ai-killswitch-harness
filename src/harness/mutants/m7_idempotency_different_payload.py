"""M7: Idempotency key reused with a different request payload.

The reference commit boundary returns the recorded result for a replay
without checking that the replayed request matches the original. A correct
implementation must reject the replay if the payload (amount, action, etc.)
differs.

Detected by: tests/test_s10_mutants.py::test_m7_different_payload_detected.
"""
from __future__ import annotations

from typing import Any

import harness.commit as real_commit
from ..schemas import CommitResult

_ORIGINAL_COMMIT = real_commit.commit_protected_action


def _commit_replaying_different_payload(store, authz, request, clock=None) -> CommitResult:
    # The mutant does NOT delete the idempotency row. It runs the original
    # commit. If the idempotency key exists, the original returns the
    # previously-recorded result. But the original ALSO checks that the
    # request matches the recorded decision. So this mutant cannot work by
    # delegating to the original -- it must bypass the request-binding check.

    # We do that by patching the store's get_authorization to return a decision
    # whose fields match the NEW request (so the request-binding check passes),
    # but whose decision_id is the OLD one (so the nonce is already consumed).
    # That is the actual attack the mutant demonstrates.
    import json
    real_get_auth = store.get_authorization

    def fake_get_auth(decision_id: str):
        row = real_get_auth(decision_id)
        if row is None:
            return None
        # If the stored decision has a different amount than the new request,
        # replace the stored JSON with one whose amount matches. This makes
        # the request-binding check pass even though the payload changed.
        stored = json.loads(row["request_json"])
        if stored["amount_minor"] != request.amount_minor:
            stored["amount_minor"] = request.amount_minor
            return {
                "decision_id": row["decision_id"],
                "epoch": row["epoch"],
                "policy_version": row["policy_version"],
                "issued_at_us": row["issued_at_us"],
                "expires_at_us": row["expires_at_us"],
                "consumed": row["consumed"],
                "request_json": json.dumps(stored, separators=(",", ":")),
                "signature_hex": row["signature_hex"],
            }
        return row

    store.get_authorization = fake_get_auth  # type: ignore[method-assign]
    try:
        return _ORIGINAL_COMMIT(store, authz, request, clock)
    finally:
        store.get_authorization = real_get_auth  # type: ignore[method-assign]


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None) -> None:
    monkeypatch.setattr(real_commit, "commit_protected_action", _commit_replaying_different_payload)
    if app is not None:
        import harness.app as real_app
        monkeypatch.setattr(real_app, "commit_protected_action", _commit_replaying_different_payload)