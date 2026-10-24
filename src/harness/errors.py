"""Stable reason codes and typed errors. Tests assert exact codes."""
from __future__ import annotations

from enum import Enum


class ReasonCode(str, Enum):
    # success / informational
    OK = "ok"
    IDEMPOTENCY_REPLAY = "idempotency_replay"

    # kill switch / state
    SWITCH_TRIPPED = "switch_tripped"
    SWITCH_INACTIVE = "switch_inactive"
    STATE_MISSING = "state_missing"

    # authorization
    DECISION_UNKNOWN = "decision_unknown"
    DECISION_EXPIRED = "decision_expired"
    DECISION_CONSUMED = "decision_consumed"
    DECISION_SIGNATURE_INVALID = "decision_signature_invalid"
    STALE_EPOCH = "stale_epoch"
    POLICY_MISMATCH = "policy_mismatch"
    REQUEST_MISMATCH = "request_mismatch"

    # recovery
    RECOVERY_UNAUTHORIZED = "recovery_unauthorized"
    RECOVERY_NOT_TRIPPED = "recovery_not_tripped"

    # in-flight cancellation
    INFLIGHT_CANCELLED = "inflight_cancelled"
    INFLIGHT_DENIED = "inflight_denied"

    # budget
    BUDGET_EXCEEDED = "budget_exceeded"

    # misc
    INVALID_REQUEST = "invalid_request"
    TEST_ONLY_OPERATION = "test_only_operation"


class HarnessError(Exception):
    """Raised for programming errors in the harness itself, not for enforcement decisions."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message