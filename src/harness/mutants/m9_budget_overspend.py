"""M9: Budget overspending caused by concurrent commits.

The reference commit does:
    UPDATE budget SET remaining_minor = remaining_minor - ?
    WHERE id = 1 AND remaining_minor >= ?
which refuses to decrement below zero. The mutant drops the WHERE guard,
so two sequential commits for the full budget both succeed and remaining
goes negative. That is the invariant being violated: no sequence of
commits, serialized or concurrent, may drive remaining below zero.

Detected by: tests/test_s10_mutants.py::test_m9_budget_overspend_detected.
"""
from __future__ import annotations

import uuid
from typing import Any

import harness.commit as real_commit
from ..audit import AuditChain
from ..authz import AuthorizationService
from ..clock import Clock
from ..errors import ReasonCode
from ..schemas import ActionRequest, AuthorizationDecision, CommitResult, SwitchState
from ..store import DurableStateStore


def _mutant_commit(
    store: DurableStateStore,
    authz: AuthorizationService,
    request: ActionRequest,
    clock: Clock | None = None,
) -> CommitResult:
    clock = clock or store.clock

    # Idempotency short-circuit (unchanged).
    with store.reader() as rconn:
        existing = rconn.execute(
            "SELECT outcome, reason_code, action_id, decision_id, epoch"
            " FROM idempotency WHERE key = ?",
            (request.idempotency_key,),
        ).fetchone()
    if existing is not None:
        return CommitResult(
            outcome=existing["outcome"],
            reason_code=str(existing["reason_code"]),
            action_id=existing["action_id"],
            decision_id=existing["decision_id"],
            epoch=int(existing["epoch"]) if existing["epoch"] is not None else None,
            replayed=True,
        )

    with store.writer() as conn:
        now_us = clock.now_us()
        switch = store.get_switch_conn(conn)
        if switch.state != SwitchState.ARMED:
            return CommitResult(
                outcome="REJECTED", reason_code=ReasonCode.SWITCH_TRIPPED.value,
                decision_id=request.decision_id, epoch=switch.epoch, replayed=False,
            )

        row = conn.execute(
            "SELECT request_json, consumed FROM authorizations WHERE decision_id = ?",
            (request.decision_id,),
        ).fetchone()
        if row is None:
            return CommitResult(
                outcome="REJECTED", reason_code=ReasonCode.DECISION_UNKNOWN.value,
                decision_id=request.decision_id, epoch=switch.epoch, replayed=False,
            )
        decision = AuthorizationDecision.model_validate_json(row["request_json"])

        if not (
            decision.request_id == request.request_id
            and decision.action_id == request.action_id
            and decision.identity == request.identity
            and decision.amount_minor == request.amount_minor
            and decision.currency == request.currency
        ):
            return CommitResult(
                outcome="REJECTED", reason_code=ReasonCode.REQUEST_MISMATCH.value,
                decision_id=request.decision_id, epoch=switch.epoch, replayed=False,
            )
        if now_us >= decision.expires_at_us:
            return CommitResult(
                outcome="REJECTED", reason_code=ReasonCode.DECISION_EXPIRED.value,
                decision_id=request.decision_id, epoch=switch.epoch, replayed=False,
            )
        if decision.epoch != switch.epoch:
            return CommitResult(
                outcome="REJECTED", reason_code=ReasonCode.STALE_EPOCH.value,
                decision_id=request.decision_id, epoch=switch.epoch, replayed=False,
            )
        if decision.policy_version != switch.policy_version:
            return CommitResult(
                outcome="REJECTED", reason_code=ReasonCode.POLICY_MISMATCH.value,
                decision_id=request.decision_id, epoch=switch.epoch, replayed=False,
            )
        if int(row["consumed"]) != 0:
            return CommitResult(
                outcome="REJECTED", reason_code=ReasonCode.DECISION_CONSUMED.value,
                decision_id=request.decision_id, epoch=switch.epoch, replayed=False,
            )

        # ---- THE MUTATION: no `AND remaining_minor >= ?` guard.
        conn.execute(
            "UPDATE budget SET remaining_minor = remaining_minor - ? WHERE id = 1",
            (request.amount_minor,),
        )
        conn.execute(
            "UPDATE authorizations SET consumed = 1 WHERE decision_id = ?",
            (request.decision_id,),
        )
        action_id = f"{request.action_id}-{uuid.uuid4()}"
        conn.execute(
            "INSERT INTO actions"
            " (action_id, decision_id, request_id, identity, amount_minor,"
            "  currency, epoch, committed_at_us, idempotency_key)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                action_id, request.decision_id, request.request_id,
                request.identity, request.amount_minor, request.currency,
                switch.epoch, now_us, request.idempotency_key,
            ),
        )
        seq = AuditChain.append(
            conn,
            event_type="ACTION_COMMITTED",
            payload={
                "request_id": request.request_id, "action_id": action_id,
                "decision_id": request.decision_id,
                "idempotency_key": request.idempotency_key,
                "amount_minor": request.amount_minor, "currency": request.currency,
                "epoch": switch.epoch, "policy_version": switch.policy_version,
                "reason_code": ReasonCode.OK.value, "outcome": "SUCCESS",
            },
            ts_us=now_us,
        )
        conn.execute(
            "INSERT INTO idempotency"
            " (key, outcome, reason_code, action_id, decision_id, epoch, recorded_at_us)"
            " VALUES (?, 'SUCCESS', ?, ?, ?, ?, ?)",
            (request.idempotency_key, ReasonCode.OK.value, action_id,
             request.decision_id, switch.epoch, now_us),
        )
        return CommitResult(
            outcome="SUCCESS", reason_code=ReasonCode.OK.value,
            action_id=action_id, decision_id=request.decision_id,
            epoch=switch.epoch, replayed=False, event_seq=seq,
        )


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None) -> None:
    monkeypatch.setattr(real_commit, "commit_protected_action", _mutant_commit)
    if app is not None:
        import harness.app as real_app
        monkeypatch.setattr(real_app, "commit_protected_action", _mutant_commit)