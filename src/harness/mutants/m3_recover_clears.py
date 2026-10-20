"""M3: RECOVER ignores the operator token and always succeeds."""
from __future__ import annotations

from typing import Any

from ..audit import AuditChain
from ..schemas import SwitchState


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None) -> None:
    def _recover(self, *, token: str, actor: str = "operator") -> bool:
        with self.store.writer() as conn:
            current = self.store.get_switch_conn(conn)
            now_us = self.clock.now_us()
            new_epoch = current.epoch + 1
            conn.execute("UPDATE kill_switch SET state = ?, epoch = ?, updated_at_us = ? WHERE id = 1", (SwitchState.ARMED.value, new_epoch, now_us))
            AuditChain.append(
                conn, event_type="RECOVERY_AUTHORIZED",
                payload={"actor": actor, "previous_state": current.state.value, "previous_epoch": current.epoch, "new_state": SwitchState.ARMED.value, "new_epoch": new_epoch, "outcome": "SUCCESS", "reason_code": "recover"},
                ts_us=now_us,
            )
            return True

    monkeypatch.setattr(type(killswitch), "recover", _recover)