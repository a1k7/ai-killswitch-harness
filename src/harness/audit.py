"""Append-only SHA-256 hash-chained audit log.

Calling convention: AuditChain.append(...) MUST be invoked with the same
sqlite3.Connection that the caller opened via DurableStateStore.writer().
This ensures state mutation and audit append are in one transaction.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any

from .schemas import AuditRecord
from .store import DurableStateStore

GENESIS_HASH = "0" * 64


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_event(prev_hash: str, core: dict[str, Any]) -> str:
    material = prev_hash + _canonical_json(core)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditChain:
    @staticmethod
    def _head(conn: sqlite3.Connection) -> tuple[int, str]:
        row = conn.execute(
            "SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return 0, GENESIS_HASH
        return int(row["seq"]), str(row["hash"])

    @staticmethod
    def append(
        conn: sqlite3.Connection,
        *,
        event_type: str,
        payload: dict[str, Any],
        ts_us: int,
    ) -> int:
        prev_seq, prev_hash = AuditChain._head(conn)
        event_id = str(uuid.uuid4())
        core = {
            "event_id": event_id,
            "event_type": event_type,
            "ts_us": int(ts_us),
            "payload": payload,
        }
        h = _hash_event(prev_hash, core)
        cur = conn.execute(
            "INSERT INTO audit_events (event_id, event_type, recorded_at_us, payload_json, prev_hash, hash)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (event_id, event_type, int(ts_us), _canonical_json(payload), prev_hash, h),
        )
        return int(cur.lastrowid)

    @staticmethod
    def read_all(store: DurableStateStore) -> list[AuditRecord]:
        rows = store.list_audit()
        out: list[AuditRecord] = []
        for r in rows:
            out.append(
                AuditRecord(
                    seq=int(r["seq"]),
                    event_id=str(r["event_id"]),
                    event_type=str(r["event_type"]),
                    recorded_at_us=int(r["recorded_at_us"]),
                    payload=json.loads(r["payload_json"]),
                    prev_hash=str(r["prev_hash"]),
                    hash=str(r["hash"]),
                )
            )
        return out

    @staticmethod
    def verify_chain(events: list[AuditRecord]) -> tuple[bool, str]:
        prev_hash = GENESIS_HASH
        expected_seq = 1
        for ev in events:
            if ev.seq != expected_seq:
                return False, f"sequence gap: expected {expected_seq}, got {ev.seq}"
            if ev.prev_hash != prev_hash:
                return False, f"prev_hash mismatch at seq {ev.seq}"
            core = {
                "event_id": ev.event_id,
                "event_type": ev.event_type,
                "ts_us": ev.recorded_at_us,
                "payload": ev.payload,
            }
            expected = _hash_event(ev.prev_hash, core)
            if expected != ev.hash:
                return False, f"hash mismatch at seq {ev.seq}"
            prev_hash = ev.hash
            expected_seq += 1
        return True, "ok"


__all__ = ["AuditChain", "GENESIS_HASH"]