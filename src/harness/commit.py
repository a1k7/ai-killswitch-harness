"""Commit boundary for protected actions.

This module is THE enforcement point. Every invocation route MUST call
commit_protected_action(); there is no other function in this package that
mutates `actions`, `idempotency`, or decrements `budget`.

All work happens inside one BEGIN IMMEDIATE transaction so that TRIP (also
serialized on the same SQLite writer) is linearized before or after the
commit -- never interleaved.

Check order (documented on purpose):
    0. idempotency short-circuit  (previous committed result returned as-is)
    1. load decision              -> DECISION_UNKNOWN
    2. request binding            -> REQUEST_MISMATCH
    3. switch state == ARMED      -> SWITCH_TRIPPED
    4. decision not expired       -> DECISION_EXPIRED
    5. decision epoch == switch   -> STALE_EPOCH
    6. policy matches             -> POLICY_MISMATCH
    7. nonce not consumed         -> DECISION_CONSUMED
    8. budget sufficient          -> BUDGET_EXCEEDED

Rationale for putting SWITCH_TRIPPED above STALE_EPOCH: TRIP bumps the epoch,
so a decision issued pre-trip would otherwise be reported as stale_epoch even
though the dominant fact is that shutdown is active. Reporting SWITCH_TRIPPED
whenever the switch is not ARMED keeps the reason codes deterministic and
easy to reason about. After RECOVER, the epoch remains bumped (recover also
bumps), so the same decision now reports STALE_EPOCH -- which is the intended
post-recovery contract.
"""
from __future__ import annotations

from .audit import AuditChain
from .authz import AuthorizationService, _DecisionError
from .clock import Clock
from .errors import ReasonCode
from .schemas import (
    ActionRequest,
    AuthorizationDecision,
    CommitResult,
    SwitchState,
)
from .store import DurableStateStore


def _append_rejection(
    store: DurableStateStore,
    clock: Clock,
    request: ActionRequest,
    reason: ReasonCode,
    epoch: int,
) -> int:
    """Append ACTION_REJECTED + idempotency row inside caller's transaction."""
    with store.writer() as conn:
        seq = AuditChain.append(
            conn,
            event_type="ACTION_REJECTED",
            payload={
                "request_id": request.request_id,
                "action_id": request.action_id,
                "decision_id": request.decision_id,
                "idempotency_key": request.idempotency_key,
                "reason_code": reason.value,
                "outcome": "REJECTED",
                "epoch": epoch,
            },
            ts_us=clock.now_us(),
        )
        conn.execute(
            "INSERT OR REPLACE INTO idempotency"
            " (key, outcome, reason_code, action_id, decision_id, epoch, recorded_at_us)"
            " VALUES (?, 'REJECTED', ?, NULL, ?, ?, ?)",
            (
                request.idempotency_key,
                reason.value,
                request.decision_id,
                epoch,
                clock.now_us(),
            ),
        )
        return seq


def commit_protected_action(
    store: DurableStateStore,
    authz: AuthorizationService,
    request: ActionRequest,
    clock: Clock | None = None,
) -> CommitResult:
    clock = clock or store.clock

    # 0. idempotency short-circuit
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

    # 1..8 atomic writer window
    try:
        with store.writer() as conn:
            now_us = clock.now_us()
            switch = store.get_switch_conn(conn)

            # 1. load decision
            row = conn.execute(
                "SELECT request_json, consumed FROM authorizations WHERE decision_id = ?",
                (request.decision_id,),
            ).fetchone()
            if row is None:
                raise _DecisionError(ReasonCode.DECISION_UNKNOWN)

            decision = AuthorizationDecision.model_validate_json(row["request_json"])

            # 2. request binding
            if not (
                decision.request_id == request.request_id
                and decision.action_id == request.action_id
                and decision.identity == request.identity
                and decision.amount_minor == request.amount_minor
                and decision.currency == request.currency
            ):
                raise _DecisionError(ReasonCode.REQUEST_MISMATCH)

            # 3. switch state == ARMED (takes precedence over staleness)
            if switch.state != SwitchState.ARMED:
                raise _DecisionError(ReasonCode.SWITCH_TRIPPED)

            # 4. expiry
            if now_us >= decision.expires_at_us:
                raise _DecisionError(ReasonCode.DECISION_EXPIRED)

            # 5. epoch
            if decision.epoch != switch.epoch:
                raise _DecisionError(ReasonCode.STALE_EPOCH)

            # 6. policy
            if decision.policy_version != switch.policy_version:
                raise _DecisionError(ReasonCode.POLICY_MISMATCH)

            # 7. nonce consumption
            if int(row["consumed"]) != 0:
                raise _DecisionError(ReasonCode.DECISION_CONSUMED)

            # 8. budget
            cur = conn.execute(
                "UPDATE budget SET remaining_minor = remaining_minor - ?"
                " WHERE id = 1 AND remaining_minor >= ?",
                (request.amount_minor, request.amount_minor),
            )
            if cur.rowcount != 1:
                raise _DecisionError(ReasonCode.BUDGET_EXCEEDED)

            # commit mutations
            conn.execute(
                "UPDATE authorizations SET consumed = 1 WHERE decision_id = ?",
                (request.decision_id,),
            )
            conn.execute(
                "INSERT INTO actions"
                " (action_id, decision_id, request_id, identity, amount_minor,"
                "  currency, epoch, committed_at_us, idempotency_key)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    request.action_id,
                    request.decision_id,
                    request.request_id,
                    request.identity,
                    request.amount_minor,
                    request.currency,
                    switch.epoch,
                    now_us,
                    request.idempotency_key,
                ),
            )
            seq = AuditChain.append(
                conn,
                event_type="ACTION_COMMITTED",
                payload={
                    "request_id": request.request_id,
                    "action_id": request.action_id,
                    "decision_id": request.decision_id,
                    "idempotency_key": request.idempotency_key,
                    "amount_minor": request.amount_minor,
                    "currency": request.currency,
                    "epoch": switch.epoch,
                    "policy_version": switch.policy_version,
                    "reason_code": ReasonCode.OK.value,
                    "outcome": "SUCCESS",
                },
                ts_us=now_us,
            )
            conn.execute(
                "INSERT INTO idempotency"
                " (key, outcome, reason_code, action_id, decision_id, epoch, recorded_at_us)"
                " VALUES (?, 'SUCCESS', ?, ?, ?, ?, ?)",
                (
                    request.idempotency_key,
                    ReasonCode.OK.value,
                    request.action_id,
                    request.decision_id,
                    switch.epoch,
                    now_us,
                ),
            )

            return CommitResult(
                outcome="SUCCESS",
                reason_code=ReasonCode.OK.value,
                action_id=request.action_id,
                decision_id=request.decision_id,
                epoch=switch.epoch,
                replayed=False,
                event_seq=seq,
            )
    except _DecisionError as de:
        with store.reader() as rconn:
            switch_now = store.get_switch_conn(rconn)
        seq = _append_rejection(store, clock, request, de.reason, switch_now.epoch)
        return CommitResult(
            outcome="REJECTED",
            reason_code=de.reason.value,
            decision_id=request.decision_id,
            epoch=switch_now.epoch,
            replayed=False,
            event_seq=seq,
        )


__all__ = ["commit_protected_action"]