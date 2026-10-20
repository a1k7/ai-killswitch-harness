"""M8: Reuse of an already-consumed authorization.

Mutant replaces commit_protected_action entirely. It performs all the normal
checks EXCEPT the `consumed` flag. It still consumes the decision on commit
(it has to, or audit would break), but it does NOT refuse an already-consumed
decision. The result: an authorization can be used to commit multiple
distinct actions, each with its own idempotency key.

Detected by: tests/test_s10_mutants.py::test_m8_reuse_consumed_detected.
"""
from __future__ import annotations

import json
from typing import Any

from ..audit import AuditChain
from ..authz import AuthorizationService
from ..clock import Clock
from ..errors import ReasonCode
from ..schemas import ActionRequest, AuthorizationDecision, CommitResult, SwitchState
from ..store import DurableStateStore


def _mutant_commit(store: DurableStateStore, authz: AuthorizationService, request: ActionRequest, clock: Clock | None = None) -> CommitResult:
    clock = clock or store.clock

    # Idempotency short-circuit (unchanged from reference).
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

        row = conn.execute(
            "SELECT request_json, consumed FROM authorizations WHERE decision_id = ?",
            (request.decision_id,),
        ).fetchone()
        if row is None:
            raise _MutantReject(ReasonCode.DECISION_UNKNOWN, switch.epoch)
        decision = AuthorizationDecision.model_validate_json(row["request_json"])

        if not (
            decision.request_id == request.request_id
            and decision.action_id == request.action_id
            and decision.identity == request.identity
            and decision.amount_minor == request.amount_minor
            and decision.currency == request.currency
        ):
            raise _MutantReject(ReasonCode.REQUEST_MISMATCH, switch.epoch)
        if switch.state != SwitchState.ARMED:
            raise _MutantReject(ReasonCode.SWITCH_TRIPPED, switch.epoch)
        if now_us >= decision.expires_at_us:
            raise _MutantReject(ReasonCode.DECISION_EXPIRED, switch.epoch)
        if decision.epoch != switch.epoch:
            raise _MutantReject(ReasonCode.STALE_EPOCH, switch.epoch)
        if decision.policy_version != switch.policy_version:
            raise _MutantReject(ReasonCode.POLICY_MISMATCH, switch.epoch)
        # --- THE MUTATION: consumed check is deliberately omitted ---
        cur = conn.execute(
            "UPDATE budget SET remaining_minor = remaining_minor - ?"
            " WHERE id = 1 AND remaining_minor >= ?",
            (request.amount_minor, request.amount_minor),
        )
        if cur.rowcount != 1:
            raise _MutantReject(ReasonCode.BUDGET_EXCEEDED, switch.epoch)
        conn.execute(
            "UPDATE authorizations SET consumed = 1 WHERE decision_id = ?",
            (request.decision_id,),
        )
        # `decision_id` is UNIQUE in `actions`, so use a fresh action_id per row.
        import uuid
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
            conn, event_type="ACTION_COMMITTED",
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


class _MutantReject(Exception):
    def __init__(self, reason: ReasonCode, epoch: int) -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.epoch = epoch


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None) -> None:
    import harness.commit as real_commit
    monkeypatch.setattr(real_commit, "commit_protected_action", _mutant_commit)
    if app is not None:
        import harness.app as real_app
        monkeypatch.setattr(real_app, "commit_protected_action", _mutant_commit)