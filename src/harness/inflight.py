"""In-flight operation registry.

Tracks protected operations that have been admitted but not yet reached a
terminal state. Provides cooperative cancellation via threading.Event and
records admission / cancellation / terminal-outcome events to the audit chain.

The commit boundary (commit_protected_action in harness.commit) remains
authoritative. This module does not weaken enforcement. Its job is to
provide visibility and a cooperative cancellation signal so the harness can
test the property 'a tripped switch prevents commit even for an operation
that was already in flight'.
"""
from __future__ import annotations

import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .audit import AuditChain
from .clock import Clock
from .errors import HarnessError
from .schemas import SwitchState
from .store import DurableStateStore

_TERMINAL_VALUES = {"cancelled_by_worker", "rejected_at_commit", "succeeded", "unknown"}


class OperationDenied(HarnessError):
    """Raised when admission is rejected because the switch is not ARMED."""


class TerminalOutcome(str, Enum):
    CANCELLED_BY_WORKER = "cancelled_by_worker"
    REJECTED_AT_COMMIT = "rejected_at_commit"
    SUCCEEDED = "succeeded"
    UNKNOWN = "unknown"


@dataclass
class InFlightOperation:
    operation_id: str
    decision_id: str
    admitted_epoch: int
    cancel_event: threading.Event
    terminal_outcome: Optional[str] = field(default=None)


class InFlightRegistry:
    """Thread-safe registry of in-flight protected operations.

    Each admitted operation gets a unique operation_id and a threading.Event
    that the trip path will set. Workers are expected to poll the event and
    treat it as a cooperative cancellation signal. Workers are NOT required
    to honor it; the commit boundary remains authoritative.
    """

    def __init__(self, store: DurableStateStore, clock: Clock) -> None:
        self._store = store
        self._clock = clock
        self._lock = threading.Lock()
        self._active: dict[str, InFlightOperation] = {}

    # ---------------------------------------------------------------- admit
    def admit(self, decision_id: str) -> InFlightOperation:
        """Register an operation as in flight.

        Raises OperationDenied if the kill switch is not currently ARMED.
        The check and the audit append happen in one writer transaction so
        that a concurrent trip cannot interleave between the check and the
        admission record.
        """
        with self._store.writer() as conn:
            switch = self._store.get_switch_conn(conn)
            if switch.state != SwitchState.ARMED:
                raise OperationDenied("switch_tripped")
            op_id = f"op-{uuid.uuid4()}"
            now_us = self._clock.now_us()
            # Insert the operation row. terminal_outcome is NULL.
            conn.execute(
                "INSERT INTO inflight_operations"
                " (operation_id, decision_id, admitted_epoch, admitted_at_us,"
                "  terminal_outcome, terminal_at_us)"
                " VALUES (?, ?, ?, ?, NULL, NULL)",
                (op_id, decision_id, switch.epoch, now_us),
            )
            AuditChain.append(
                conn,
                event_type="INFLIGHT_ADMITTED",
                payload={
                    "operation_id": op_id,
                    "decision_id": decision_id,
                    "epoch": switch.epoch,
                    "outcome": "ADMITTED",
                },
                ts_us=now_us,
            )

        op = InFlightOperation(
            operation_id=op_id,
            decision_id=decision_id,
            admitted_epoch=switch.epoch,
            cancel_event=threading.Event(),
        )
        with self._lock:
            self._active[op_id] = op
        return op

    # ---------------------------------------------------------------- trip hook
    def cancel_all(self, conn: sqlite3.Connection, now_us: int) -> list[str]:
        """Set the cancel event on every active op and write audit events.

        MUST be called inside the caller's writer transaction (i.e., the one
        trip() opened). This makes the request-for-cancellation atomic with
        the state transition to TRIPPED. It does NOT establish that the
        workers stopped; that requires their acknowledgement or a subsequent
        commit-boundary rejection.
        """
        with self._lock:
            ops = list(self._active.values())
        for op in ops:
            op.cancel_event.set()
            AuditChain.append(
                conn,
                event_type="INFLIGHT_CANCELLATION_REQUESTED",
                payload={
                    "operation_id": op.operation_id,
                    "decision_id": op.decision_id,
                    "outcome": "REQUESTED",
                },
                ts_us=now_us,
            )
        return [op.operation_id for op in ops]

    # ---------------------------------------------------------------- acknowledge
    def acknowledge_cancellation(self, operation_id: str) -> None:
        """Record that a worker observed the cancellation request.

        Does NOT imply the worker stopped; only that it noticed.
        """
        with self._store.writer() as conn:
            now_us = self._clock.now_us()
            AuditChain.append(
                conn,
                event_type="INFLIGHT_CANCELLATION_ACKNOWLEDGED",
                payload={
                    "operation_id": operation_id,
                    "outcome": "ACKNOWLEDGED",
                },
                ts_us=now_us,
            )

    # ---------------------------------------------------------------- terminal
    def record_terminal(self, operation_id: str, outcome: str) -> None:
        """Record the terminal outcome of an operation.

        outcome must be one of TerminalOutcome values. Once recorded, the
        operation is removed from the active registry.
        """
        if outcome not in _TERMINAL_VALUES:
            raise HarnessError(f"invalid terminal outcome: {outcome}")
        with self._store.writer() as conn:
            now_us = self._clock.now_us()
            row = conn.execute(
                "SELECT terminal_outcome FROM inflight_operations"
                " WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise HarnessError(f"operation {operation_id} not found")
            if row["terminal_outcome"] is not None:
                # Idempotent: don't overwrite a terminal record.
                return
            conn.execute(
                "UPDATE inflight_operations SET terminal_outcome = ?,"
                " terminal_at_us = ? WHERE operation_id = ?",
                (outcome, now_us, operation_id),
            )
            AuditChain.append(
                conn,
                event_type="INFLIGHT_TERMINAL_OUTCOME",
                payload={
                    "operation_id": operation_id,
                    "outcome": outcome,
                },
                ts_us=now_us,
            )
        with self._lock:
            self._active.pop(operation_id, None)

    # ---------------------------------------------------------------- helpers
    def active_count(self) -> int:
        with self._lock:
            return len(self._active)

    def is_cancel_requested(self, operation_id: str) -> bool:
        with self._lock:
            op = self._active.get(operation_id)
        return op.cancel_event.is_set() if op is not None else False