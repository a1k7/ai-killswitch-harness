"""M14: record_terminal overwrites a SUCCEEDED record with CANCELLED_BY_WORKER."""
from __future__ import annotations
from typing import Any
from ..audit import AuditChain


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None, inflight=None) -> None:
    if inflight is None:
        raise RuntimeError("M14 requires the inflight registry")

    def _record_terminal_overwriting(self, operation_id: str, outcome: str) -> None:
        with self._store.writer() as conn:
            now_us = self._clock.now_us()
            conn.execute(
                "UPDATE inflight_operations SET terminal_outcome = ?,"
                " terminal_at_us = ? WHERE operation_id = ?",
                (outcome, now_us, operation_id),
            )
            AuditChain.append(
                conn, event_type="INFLIGHT_TERMINAL_OUTCOME",
                payload={"operation_id": operation_id, "outcome": outcome},
                ts_us=now_us,
            )
        with self._lock:
            self._active.pop(operation_id, None)

    monkeypatch.setattr(type(inflight), "record_terminal", _record_terminal_overwriting)
