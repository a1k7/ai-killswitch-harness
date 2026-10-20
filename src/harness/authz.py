"""Authorization decision service.

Issues short-lived Ed25519-signed decisions. The signing key is generated once
per database (stored in `authz_keys`) so decisions survive process restart. A
production deployment would use KMS/HSM; this harness keeps the key on-disk to
stay fully local.

The commit boundary MUST re-check every property of the decision at commit time
(expiry, epoch, policy, nonce consumption). A valid signature alone is NOT
sufficient to execute.
"""
from __future__ import annotations

import json
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .clock import Clock
from .errors import HarnessError, ReasonCode
from .schemas import AuthorizationDecision, AuthzIssueRequest
from .store import DurableStateStore

_KEY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS authz_keys (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    private_key_hex TEXT NOT NULL,
    public_key_hex TEXT NOT NULL
)
"""


def _canonical_decision_payload(decision: AuthorizationDecision) -> bytes:
    """Deterministic bytes over all fields except signature_hex."""
    payload = {
        "decision_id": decision.decision_id,
        "request_id": decision.request_id,
        "action_id": decision.action_id,
        "identity": decision.identity,
        "amount_minor": decision.amount_minor,
        "currency": decision.currency,
        "policy_version": decision.policy_version,
        "epoch": decision.epoch,
        "issued_at_us": decision.issued_at_us,
        "expires_at_us": decision.expires_at_us,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class AuthorizationService:
    def __init__(self, store: DurableStateStore, clock: Clock) -> None:
        self.store = store
        self.clock = clock
        self._priv: Ed25519PrivateKey
        self._pub: Ed25519PublicKey
        self._ensure_key()

    # -------------------------------------------------------------- key mgmt
    def _ensure_key(self) -> None:
        with self.store.writer() as conn:
            conn.execute(_KEY_TABLE_SQL)
            row = conn.execute(
                "SELECT private_key_hex, public_key_hex FROM authz_keys WHERE id = 1"
            ).fetchone()
            if row is None:
                priv = Ed25519PrivateKey.generate()
                priv_bytes = priv.private_bytes(
                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                )
                pub_bytes = priv.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
                conn.execute(
                    "INSERT INTO authz_keys (id, private_key_hex, public_key_hex)"
                    " VALUES (1, ?, ?)",
                    (priv_bytes.hex(), pub_bytes.hex()),
                )
                self._priv = priv
                self._pub = priv.public_key()
            else:
                priv_bytes = bytes.fromhex(row["private_key_hex"])
                pub_bytes = bytes.fromhex(row["public_key_hex"])
                self._priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
                self._pub = Ed25519PublicKey.from_public_bytes(pub_bytes)

    # -------------------------------------------------------------- issue
    def issue(self, req: AuthzIssueRequest) -> AuthorizationDecision:
        switch = self.store.get_switch()
        now = self.clock.now_us()
        decision = AuthorizationDecision(
            decision_id=str(uuid.uuid4()),
            request_id=req.request_id,
            action_id=req.action_id,
            identity=req.identity,
            amount_minor=req.amount_minor,
            currency=req.currency,
            policy_version=switch.policy_version,
            epoch=switch.epoch,
            issued_at_us=now,
            expires_at_us=now + req.ttl_seconds * 1_000_000,
            signature_hex="",
        )
        sig = self._priv.sign(_canonical_decision_payload(decision))
        decision.signature_hex = sig.hex()

        with self.store.writer() as conn:
            conn.execute(
                "INSERT INTO authorizations"
                " (decision_id, epoch, policy_version, issued_at_us, expires_at_us,"
                "  consumed, request_json, signature_hex)"
                " VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
                (
                    decision.decision_id,
                    decision.epoch,
                    decision.policy_version,
                    decision.issued_at_us,
                    decision.expires_at_us,
                    json.dumps(decision.model_dump(), separators=(",", ":")),
                    decision.signature_hex,
                ),
            )
        return decision

    # -------------------------------------------------------------- load/verify
    def load_and_verify(self, decision_id: str) -> AuthorizationDecision:
        row = self.store.get_authorization(decision_id)
        if row is None:
            raise HarnessError(f"decision {decision_id} not found")
        decision = AuthorizationDecision.model_validate_json(row["request_json"])
        try:
            self._pub.verify(
                bytes.fromhex(decision.signature_hex),
                _canonical_decision_payload(decision),
            )
        except InvalidSignature as exc:
            raise HarnessError(ReasonCode.DECISION_SIGNATURE_INVALID.value) from exc
        return decision

    def is_consumed(self, decision_id: str) -> bool:
        row = self.store.get_authorization(decision_id)
        if row is None:
            raise HarnessError(f"decision {decision_id} not found")
        return bool(row["consumed"])

    # -------------------------------------------------------------- consume (inside writer)
    def consume_conn(self, conn, decision_id: str) -> None:
        """Must be called inside a DurableStateStore.writer() transaction."""
        row = conn.execute(
            "SELECT consumed FROM authorizations WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        if row is None:
            raise _DecisionError(ReasonCode.DECISION_UNKNOWN)
        if int(row["consumed"]) != 0:
            raise _DecisionError(ReasonCode.DECISION_CONSUMED)
        conn.execute(
            "UPDATE authorizations SET consumed = 1 WHERE decision_id = ?",
            (decision_id,),
        )


class _DecisionError(Exception):
    """Internal signal to abort the writer transaction with a reason code."""

    def __init__(self, reason: ReasonCode) -> None:
        super().__init__(reason.value)
        self.reason = reason


__all__ = ["AuthorizationService", "_DecisionError", "_canonical_decision_payload"]