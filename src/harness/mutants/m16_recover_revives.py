"""M16: recover() clears cancel events and rolls the epoch back."""
from __future__ import annotations
import hmac
from typing import Any
from ..audit import AuditChain
from ..schemas import SwitchState


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None, inflight=None) -> None:
    def _recover_reviving(self, *, token: str, actor: str = "operator") -> bool:
        authorized = hmac.compare_digest(
            (token or "").encode("utf-8"), self.recovery_token.encode("utf-8")
        )
        if not authorized:
            return False
        with self.store.writer() as conn:
            current = self.store.get_switch_conn(conn)
            now_us = self.clock.now_us()
            conn.execute(
                "UPDATE kill_switch SET state = ?, epoch = ?, updated_at_us = ? WHERE id = 1",
                (SwitchState.ARMED.value, 1, now_us),
            )
            AuditChain.append(
                conn, event_type="RECOVERY_AUTHORIZED",
                payload={
                    "actor": actor, "previous_state": current.state.value,
                    "previous_epoch": current.epoch,
                    "new_state": SwitchState.ARMED.value,
                    "new_epoch": 1, "outcome": "SUCCESS", "reason_code": "recover",
                }, ts_us=now_us,
            )
            if self.inflight is not None:
                with self.inflight._lock:
                    for op in self.inflight._active.values():
                        op.cancel_event.clear()
            return True

    monkeypatch.setattr(type(killswitch), "recover", _recover_reviving)
