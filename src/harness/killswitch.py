"""Kill-switch controller. Explicit operations only.

TRIP and RECOVER increment the epoch so previously-issued decisions become
STALE_EPOCH at the commit boundary. RECOVER requires an operator token; a
restart, health check, or timeout NEVER implicitly clears TRIPPED.

TRIP also fans out cooperative cancellation requests to any registered
in-flight operations. This is a request, not a guarantee that the workers
stopped. The commit boundary remains authoritative.
"""
from __future__ import annotations

import hmac
from typing import TYPE_CHECKING

from .audit import AuditChain
from .clock import Clock
from .errors import ReasonCode
from .schemas import SwitchState, SwitchStatus
from .store import DurableStateStore

if TYPE_CHECKING:
    from .inflight import InFlightRegistry


class KillSwitchController:
    def __init__(
        self,
        store: DurableStateStore,
        clock: Clock,
        *,
        recovery_token: str,
        inflight: "InFlightRegistry | None" = None,
    ) -> None:
        self.store = store
        self.clock = clock
        self.recovery_token = recovery_token
        self.inflight = inflight

    def status(self) -> SwitchStatus:
        return self.store.get_switch()

    def trip(self, *, actor: str = "operator", reason: str = "manual") -> SwitchStatus:
        with self.store.writer() as conn:
            current = self.store.get_switch_conn(conn)
            new_epoch = current.epoch + 1
            now_us = self.clock.now_us()
            conn.execute(
                "UPDATE kill_switch SET state = ?, epoch = ?, updated_at_us = ?"
                " WHERE id = 1",
                (SwitchState.TRIPPED.value, new_epoch, now_us),
            )
            AuditChain.append(
                conn,
                event_type="SWITCH_TRIPPED",
                payload={
                    "actor": actor,
                    "reason": reason,
                    "previous_state": current.state.value,
                    "previous_epoch": current.epoch,
                    "new_state": SwitchState.TRIPPED.value,
                    "new_epoch": new_epoch,
                    "outcome": "SUCCESS",
                    "reason_code": "trip",
                },
                ts_us=now_us,
            )
            if self.inflight is not None:
                self.inflight.cancel_all(conn, now_us)
            return SwitchStatus(
                state=SwitchState.TRIPPED,
                epoch=new_epoch,
                policy_version=current.policy_version,
                updated_at_us=now_us,
            )

    def recover(self, *, token: str, actor: str = "operator") -> bool:
        authorized = hmac.compare_digest(
            (token or "").encode("utf-8"), self.recovery_token.encode("utf-8")
        )
        with self.store.writer() as conn:
            current = self.store.get_switch_conn(conn)
            now_us = self.clock.now_us()

            if not authorized:
                AuditChain.append(
                    conn,
                    event_type="RECOVERY_DENIED",
                    payload={
                        "actor": actor,
                        "reason_code": ReasonCode.RECOVERY_UNAUTHORIZED.value,
                        "outcome": "REJECTED",
                        "current_state": current.state.value,
                        "current_epoch": current.epoch,
                    },
                    ts_us=now_us,
                )
                return False

            if current.state != SwitchState.TRIPPED:
                AuditChain.append(
                    conn,
                    event_type="RECOVERY_NOOP",
                    payload={
                        "actor": actor,
                        "reason_code": ReasonCode.RECOVERY_NOT_TRIPPED.value,
                        "outcome": "REJECTED",
                        "current_state": current.state.value,
                        "current_epoch": current.epoch,
                    },
                    ts_us=now_us,
                )
                return True

            new_epoch = current.epoch + 1
            conn.execute(
                "UPDATE kill_switch SET state = ?, epoch = ?, updated_at_us = ?"
                " WHERE id = 1",
                (SwitchState.ARMED.value, new_epoch, now_us),
            )
            AuditChain.append(
                conn,
                event_type="RECOVERY_AUTHORIZED",
                payload={
                    "actor": actor,
                    "previous_state": current.state.value,
                    "previous_epoch": current.epoch,
                    "new_state": SwitchState.ARMED.value,
                    "new_epoch": new_epoch,
                    "outcome": "SUCCESS",
                    "reason_code": "recover",
                },
                ts_us=now_us,
            )
            return True

    def reset_for_test(self, *, initial_budget_minor: int, policy_version: str) -> None:
        with self.store.writer() as conn:
            conn.execute("DELETE FROM actions")
            conn.execute("DELETE FROM idempotency")
            conn.execute("DELETE FROM authorizations")
            conn.execute("DELETE FROM audit_events")
            conn.execute("DELETE FROM budget")
            conn.execute("DELETE FROM kill_switch")
            conn.execute(
                "INSERT INTO kill_switch (id, state, epoch, policy_version, updated_at_us)"
                " VALUES (1, ?, 1, ?, ?)",
                (SwitchState.ARMED.value, policy_version, self.clock.now_us()),
            )
            conn.execute(
                "INSERT INTO budget (id, initial_minor, remaining_minor) VALUES (1, ?, ?)",
                (initial_budget_minor, initial_budget_minor),
            )


__all__ = ["KillSwitchController"]