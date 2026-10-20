"""Scenario 8: alternate invocation path.

Both `/actions` and `/actions/alt` must enforce kill-switch shutdown. The
alternate route exists specifically to catch any future refactor that
re-implements commit logic outside the single guarded function.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _issue_via_app(client: TestClient, request_id: str, amount_minor: int = 100) -> dict:
    r = client.post(
        "/decisions/issue",
        json={
            "request_id": request_id,
            "identity": "op-a",
            "amount_minor": amount_minor,
            "currency": "USD",
            "ttl_seconds": 30,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


def _action_body(request_id: str, decision_id: str, idempotency_key: str) -> dict:
    return {
        "request_id": request_id,
        "action_id": "refund",
        "amount_minor": 100,
        "currency": "USD",
        "decision_id": decision_id,
        "idempotency_key": idempotency_key,
        "identity": "op-a",
    }


def test_primary_route_rejects_under_trip(client: TestClient):
    d = _issue_via_app(client, "r-primary")
    client.post("/trip", headers={"X-Test-Identity": "op-a"})

    body = _action_body("r-primary", d["decision_id"], "k-primary")
    r = client.post("/actions", headers={"X-Test-Identity": "op-a"}, json=body)
    assert r.status_code == 200
    assert r.json()["outcome"] == "REJECTED"
    assert r.json()["reason_code"] == "switch_tripped"


def test_alt_route_rejects_under_trip(client: TestClient):
    d = _issue_via_app(client, "r-alt")
    client.post("/trip", headers={"X-Test-Identity": "op-a"})

    body = _action_body("r-alt", d["decision_id"], "k-alt")
    r = client.post("/actions/alt", headers={"X-Test-Identity": "op-a"}, json=body)
    assert r.status_code == 200
    assert r.json()["outcome"] == "REJECTED"
    assert r.json()["reason_code"] == "switch_tripped"

    # Cross-check: no action rows anywhere
    hist = client.get("/history").json()
    assert hist["count"] == 0


def test_alt_route_identical_to_primary_under_armed(client: TestClient):
    """Both routes succeed identically under ARMED."""
    d = _issue_via_app(client, "r-armed")
    body = _action_body("r-armed", d["decision_id"], "k-armed")
    r = client.post("/actions", headers={"X-Test-Identity": "op-a"}, json=body)
    assert r.status_code == 200
    assert r.json()["outcome"] == "SUCCESS"

    # Replay via alt with the same idempotency key must return the recorded
    # success (replayed=True) and not create a second action.
    r2 = client.post("/actions/alt", headers={"X-Test-Identity": "op-a"}, json=body)
    assert r2.status_code == 200
    assert r2.json()["outcome"] == "SUCCESS"
    assert r2.json()["replayed"] is True

    hist = client.get("/history").json()
    assert hist["count"] == 1