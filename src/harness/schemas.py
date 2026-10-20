"""Typed request/response/record models."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from .errors import ReasonCode


class SwitchState(str, Enum):
    ARMED = "ARMED"        # execution permitted (subject to other checks)
    TRIPPED = "TRIPPED"    # shutdown: protected actions must be rejected


class DecisionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"


class ActionRequest(BaseModel):
    request_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1, description="e.g. 'refund'")
    amount_minor: int = Field(ge=0)
    currency: str = Field(min_length=3, max_length=8)
    decision_id: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1)
    identity: str = Field(min_length=1, description="test identity, not real auth")


class AuthorizationDecision(BaseModel):
    decision_id: str
    request_id: str
    action_id: str
    identity: str
    amount_minor: int
    currency: str
    policy_version: str
    epoch: int
    issued_at_us: int
    expires_at_us: int
    signature_hex: str


class AuthzIssueRequest(BaseModel):
    request_id: str
    action_id: str = "refund"
    identity: str
    amount_minor: int = Field(ge=0)
    currency: str = "USD"
    ttl_seconds: int = Field(default=30, ge=1, le=3600)


@dataclass
class CommitResult:
    outcome: Literal["SUCCESS", "REJECTED"]
    reason_code: str
    action_id: Optional[str] = None
    decision_id: Optional[str] = None
    epoch: Optional[int] = None
    replayed: bool = False
    event_seq: Optional[int] = None
    detail: Optional[str] = None


@dataclass
class VerifyProperty:
    name: str
    status: Literal["PASS", "FAIL", "INCONCLUSIVE"]
    detail: str = ""


@dataclass
class VerifyReport:
    properties: list[VerifyProperty] = field(default_factory=list)
    observed_at_us: int = 0
    audit_head_seq: int = 0
    audit_head_hash: str = ""

    def overall(self) -> Literal["PASS", "FAIL", "INCONCLUSIVE"]:
        statuses = {p.status for p in self.properties}
        if "FAIL" in statuses:
            return "FAIL"
        if "INCONCLUSIVE" in statuses or not self.properties:
            return "INCONCLUSIVE"
        return "PASS"

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall(),
            "observed_at_us": self.observed_at_us,
            "audit_head_seq": self.audit_head_seq,
            "audit_head_hash": self.audit_head_hash,
            "properties": [
                {"name": p.name, "status": p.status, "detail": p.detail}
                for p in self.properties
            ],
        }


@dataclass
class SwitchStatus:
    state: SwitchState
    epoch: int
    policy_version: str
    updated_at_us: int


@dataclass
class AuditRecord:
    seq: int
    event_id: str
    event_type: str
    recorded_at_us: int
    payload: dict[str, Any]
    prev_hash: str
    hash: str


__all__ = [
    "SwitchState",
    "DecisionStatus",
    "ActionRequest",
    "AuthorizationDecision",
    "AuthzIssueRequest",
    "CommitResult",
    "VerifyProperty",
    "VerifyReport",
    "SwitchStatus",
    "AuditRecord",
    "ReasonCode",
]