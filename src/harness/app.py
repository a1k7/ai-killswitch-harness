"""FastAPI app factory. See README for setup.

Every mutating path goes through commit_protected_action() in harness.commit.
`/actions` and `/actions/alt` both call the same function; Scenario 8 proves
neither route can bypass the kill-switch guard.
"""
from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .audit import AuditChain
from .authz import AuthorizationService
from .clock import Clock, RealClock
from .commit import commit_protected_action
from .config import Settings
from .killswitch import KillSwitchController
from .schemas import (
    ActionRequest,
    AuthzIssueRequest,
    CommitResult,
    SwitchStatus,
)
from .store import DurableStateStore
from .verifier import Verifier


# --------------------------------------------------------------- request/response models
class TripResponse(BaseModel):
    state: str
    epoch: int
    policy_version: str
    updated_at_us: int


class StatusResponse(BaseModel):
    state: str
    epoch: int
    policy_version: str
    updated_at_us: int


class IssueDecisionResponse(BaseModel):
    decision_id: str
    request_id: str
    action_id: str
    identity: str
    amount_minor: int
    currency: str
    policy_version: str
    epoch: int
    issued_at_us: int
    expires_at_us: int
    signature_hex: str


class CommitResponse(BaseModel):
    outcome: str
    reason_code: str
    action_id: Optional[str] = None
    decision_id: Optional[str] = None
    epoch: Optional[int] = None
    replayed: bool = False
    event_seq: Optional[int] = None


class RecoveryResponse(BaseModel):
    authorized: bool
    state: str
    epoch: int


class ResetResponse(BaseModel):
    reset: bool
    state: str
    epoch: int


# --------------------------------------------------------------- helpers
def _switch_to_response(s: SwitchStatus) -> StatusResponse:
    return StatusResponse(
        state=s.state.value,
        epoch=s.epoch,
        policy_version=s.policy_version,
        updated_at_us=s.updated_at_us,
    )


def _commit_to_response(c: CommitResult) -> CommitResponse:
    return CommitResponse(
        outcome=c.outcome,
        reason_code=c.reason_code,
        action_id=c.action_id,
        decision_id=c.decision_id,
        epoch=c.epoch,
        replayed=c.replayed,
        event_seq=c.event_seq,
    )


def create_app(
    settings: Optional[Settings] = None,
    clock: Optional[Clock] = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    clock = clock or RealClock()

    store = DurableStateStore(settings.db_path, clock)
    store.init_schema(
        initial_budget_minor=settings.initial_budget_minor,
        policy_version=settings.policy_version,
    )
    authz = AuthorizationService(store, clock)
    ks = KillSwitchController(store, clock, recovery_token=settings.recovery_token)

    app = FastAPI(
        title="AI Kill-Switch Verification Harness",
        version="0.1.0",
        description=(
            "Reference harness. NOT production-certified. Do not deploy with "
            "real credentials; test identities only."
        ),
    )
    app.state.settings = settings
    app.state.clock = clock
    app.state.store = store
    app.state.authz = authz
    app.state.killswitch = ks

    # ---------------- health
    @app.get("/health")
    def health() -> dict:
        return {
            "status": "ok",
            "env": settings.harness_env,
            "policy_version": settings.policy_version,
        }

    # ---------------- switch status
    @app.get("/status", response_model=StatusResponse)
    def status() -> StatusResponse:
        return _switch_to_response(ks.status())

    # ---------------- trip
    @app.post("/trip", response_model=TripResponse)
    def trip(
        x_test_identity: str = Header(..., alias="X-Test-Identity"),
    ) -> TripResponse:
        s = ks.trip(actor=x_test_identity, reason="api")
        return TripResponse(
            state=s.state.value,
            epoch=s.epoch,
            policy_version=s.policy_version,
            updated_at_us=s.updated_at_us,
        )

    # ---------------- issue decision (helper endpoint for demo; not the guard)
    @app.post("/decisions/issue", response_model=IssueDecisionResponse)
    def issue_decision(req: AuthzIssueRequest) -> IssueDecisionResponse:
        d = authz.issue(req)
        return IssueDecisionResponse(**d.model_dump())

    # ---------------- protected action (primary route)
    @app.post("/actions", response_model=CommitResponse)
    def actions(
        req: ActionRequest,
        x_test_identity: str = Header(..., alias="X-Test-Identity"),
    ) -> CommitResponse:
        if x_test_identity != req.identity:
            raise HTTPException(status_code=400, detail="identity mismatch")
        result = commit_protected_action(store, authz, req, clock)
        return _commit_to_response(result)

    # ---------------- protected action (alternate route — MUST behave identically)
    @app.post("/actions/alt", response_model=CommitResponse)
    def actions_alt(
        req: ActionRequest,
        x_test_identity: str = Header(..., alias="X-Test-Identity"),
    ) -> CommitResponse:
        if x_test_identity != req.identity:
            raise HTTPException(status_code=400, detail="identity mismatch")
        result = commit_protected_action(store, authz, req, clock)
        return _commit_to_response(result)

    # ---------------- recovery
    @app.post("/recovery", response_model=RecoveryResponse)
    def recovery(
        x_recovery_token: str = Header(..., alias="X-Recovery-Token"),
        x_test_identity: str = Header("operator", alias="X-Test-Identity"),
    ) -> RecoveryResponse:
        authorized = ks.recover(token=x_recovery_token, actor=x_test_identity)
        if not authorized:
            raise HTTPException(status_code=403, detail="recovery_unauthorized")
        s = ks.status()
        return RecoveryResponse(authorized=True, state=s.state.value, epoch=s.epoch)

    # ---------------- history
    @app.get("/history")
    def history() -> dict:
        rows = store.list_actions()
        return {
            "count": len(rows),
            "actions": [
                {
                    "action_id": r["action_id"],
                    "decision_id": r["decision_id"],
                    "request_id": r["request_id"],
                    "identity": r["identity"],
                    "amount_minor": int(r["amount_minor"]),
                    "currency": r["currency"],
                    "epoch": int(r["epoch"]),
                    "committed_at_us": int(r["committed_at_us"]),
                    "idempotency_key": r["idempotency_key"],
                }
                for r in rows
            ],
        }

    # ---------------- export audit chain
    @app.get("/export")
    def export() -> dict:
        events = AuditChain.read_all(store)
        return {
            "head_seq": events[-1].seq if events else 0,
            "head_hash": events[-1].hash if events else "0" * 64,
            "events": [
                {
                    "seq": ev.seq,
                    "event_id": ev.event_id,
                    "event_type": ev.event_type,
                    "recorded_at_us": ev.recorded_at_us,
                    "payload": ev.payload,
                    "prev_hash": ev.prev_hash,
                    "hash": ev.hash,
                }
                for ev in events
            ],
        }

    # ---------------- verify
    @app.post("/verify")
    def verify() -> dict:
        ro = DurableStateStore(settings.db_path, clock, readonly=True)
        verifier = Verifier(
            ro, clock, staleness_window_us=settings.staleness_window_us
        )
        return verifier.verify().to_dict()

    # ---------------- test-only reset
    @app.post("/reset", response_model=ResetResponse)
    def reset() -> ResetResponse:
        if not settings.reset_enabled:
            raise HTTPException(status_code=403, detail="test_only_operation")
        ks.reset_for_test(
            initial_budget_minor=settings.initial_budget_minor,
            policy_version=settings.policy_version,
        )
        s = ks.status()
        return ResetResponse(reset=True, state=s.state.value, epoch=s.epoch)

    return app


__all__ = ["create_app"]