"""M11: TRIP transitions the switch but does not fan out cancellation."""
from __future__ import annotations
from typing import Any
from ..audit import AuditChain
from ..schemas import SwitchState, SwitchStatus


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None, inflight=None) -> None:
    def _trip_no_cancel(self, *, actor: str = "operator", reason: str = "manual") -> SwitchStatus:
        with self.store.writer() as conn:
            current = self.store.get_switch_conn(conn)
            new_epoch = current.epoch + 1
            now_us = self.clock.now_us()
            conn.execute(
                "UPDATE kill_switch SET state = ?, epoch = ?, updated_at_us = ? WHERE id = 1",
                (SwitchState.TRIPPED.value, new_epoch, now_us),
            )
            AuditChain.append(
                conn, event_type="SWITCH_TRIPPED",
                payload={
                    "actor": actor, "reason": reason,
                    "previous_state": current.state.value,
                    "previous_epoch": current.epoch,
                    "new_state": SwitchState.TRIPPED.value,
                    "new_epoch": new_epoch,
                    "outcome": "SUCCESS", "reason_code": "trip",
                }, ts_us=now_us,
            )
            return SwitchStatus(
                state=SwitchState.TRIPPED, epoch=new_epoch,
                policy_version=current.policy_version, updated_at_us=now_us,
            )
    monkeypatch.setattr(type(killswitch), "trip", _trip_no_cancel)
