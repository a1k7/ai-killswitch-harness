"""M1: in-memory-only TRIP. Verify on-disk row is unchanged after trip()."""
from __future__ import annotations

from typing import Any

from ..audit import AuditChain
from ..schemas import SwitchState, SwitchStatus


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None) -> None:
    in_memory: dict[str, Any] = {"state": SwitchState.ARMED, "epoch": None}

    def _trip(self, *, actor: str = "operator", reason: str = "manual") -> SwitchStatus:
        current = self.store.get_switch()
        if in_memory["epoch"] is None:
            in_memory["epoch"] = current.epoch
        in_memory["state"] = SwitchState.TRIPPED
        in_memory["epoch"] += 1
        now_us = self.clock.now_us()
        # Audit only; no kill_switch UPDATE.
        with self.store.writer() as conn:
            AuditChain.append(
                conn, event_type="SWITCH_TRIPPED",
                payload={"actor": actor, "reason": reason, "new_state": SwitchState.TRIPPED.value, "new_epoch": in_memory["epoch"], "outcome": "SUCCESS", "reason_code": "trip"},
                ts_us=now_us,
            )
        return SwitchStatus(state=SwitchState.TRIPPED, epoch=in_memory["epoch"], policy_version=current.policy_version, updated_at_us=now_us)

    monkeypatch.setattr(type(killswitch), "trip", _trip)