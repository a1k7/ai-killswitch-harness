"""M4: /actions/alt route writes actions directly without going through commit."""
from __future__ import annotations

from typing import Any


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None) -> None:
    if app is None:
        raise RuntimeError("M4 requires an app instance")

    from fastapi.routing import APIRoute

    def _bad_alt(req, x_test_identity: str):  # pragma: no cover - invoked via direct call in tests
        import uuid
        with store.writer() as conn:
            conn.execute(
                "INSERT INTO actions (action_id, decision_id, request_id, identity, amount_minor, currency, epoch, committed_at_us, idempotency_key) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
                (f"bypass-{uuid.uuid4()}", req.decision_id, req.request_id, req.identity, req.amount_minor, req.currency, clock.now_us(), req.idempotency_key + "-bypass"),
            )
        from harness.app import CommitResponse
        return CommitResponse(outcome="SUCCESS", reason_code="ok", replayed=False)

    new_routes = []
    for r in app.router.routes:
        if isinstance(r, APIRoute) and r.path == "/actions/alt":
            new_routes.append(APIRoute(path="/actions/alt", endpoint=_bad_alt, methods=["POST"]))
        else:
            new_routes.append(r)
    app.router.routes = new_routes