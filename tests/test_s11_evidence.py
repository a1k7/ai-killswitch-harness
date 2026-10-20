"""Scenario 11: evidence integrity and freshness.

Sub-tests:
  (a) Baseline: a lifecycle with one ACTION_COMMITTED, no switch events,
      produces audit_chain_intact=PASS but evidence_sufficient=INCONCLUSIVE.
      A committed action alone does NOT establish current switch state.
  (b) Tampering an audit event payload breaks the hash chain; the verifier
      reports audit_chain_intact=FAIL.
  (c) Reordering the audit rows is detected (seq continuity check fails).
  (d) Only ACTION_REJECTED events in the chain -> evidence_sufficient=INCONCLUSIVE.
"""
from __future__ import annotations

import json

from harness.audit import AuditChain
from harness.commit import commit_protected_action
from harness.schemas import ActionRequest, AuthzIssueRequest
from harness.store import DurableStateStore
from harness.verifier import Verifier


def _commit_one(store, authz, clock, request_id="r1"):
    d = authz.issue(
        AuthzIssueRequest(request_id=request_id, identity="op-a", amount_minor=100)
    )
    req = ActionRequest(
        request_id=request_id, action_id="refund", amount_minor=100,
        currency="USD", decision_id=d.decision_id,
        idempotency_key=f"k-{request_id}", identity="op-a",
    )
    result = commit_protected_action(store, authz, req, clock)
    assert result.outcome == "SUCCESS", result


def test_baseline_chain_intact_but_state_inconclusive(store, authz, clock):
    _commit_one(store, authz, clock)
    ro = DurableStateStore(store.db_path, clock, readonly=True)
    report = Verifier(ro, clock).verify()
    by_name = {p.name: p for p in report.properties}

    assert by_name["audit_chain_intact"].status == "PASS"
    assert by_name["no_duplicate_actions"].status == "PASS"
    assert by_name["no_actions_while_tripped"].status == "PASS"
    assert by_name["no_stale_epoch_commits"].status == "PASS"
    assert by_name["evidence_sufficient"].status == "INCONCLUSIVE"
    assert report.overall() == "INCONCLUSIVE"


def test_tampered_event_fails_chain_integrity(store, authz, clock):
    _commit_one(store, authz, clock)
    with store.writer() as conn:
        conn.execute(
            "UPDATE audit_events SET payload_json = ? WHERE event_type = 'ACTION_COMMITTED'",
            (json.dumps({"tampered": True}),),
        )
    ro = DurableStateStore(store.db_path, clock, readonly=True)
    report = Verifier(ro, clock).verify()
    by_name = {p.name: p for p in report.properties}
    assert by_name["audit_chain_intact"].status == "FAIL"
    assert report.overall() == "FAIL"


def test_reordered_event_detected(store, authz, clock, killswitch):
    _commit_one(store, authz, clock, "r1")
    killswitch.trip()

    with store.writer() as conn:
        rows = conn.execute(
            "SELECT seq, event_id FROM audit_events ORDER BY seq"
        ).fetchall()
        assert len(rows) >= 2, f"expected >=2 events, got {len(rows)}"
        a, b = rows[0], rows[1]
        conn.execute("UPDATE audit_events SET seq = -1 WHERE seq = ?", (a["seq"],))
        conn.execute(
            "UPDATE audit_events SET seq = ? WHERE seq = ?",
            (a["seq"], b["seq"]),
        )
        conn.execute("UPDATE audit_events SET seq = ? WHERE seq = -1", (b["seq"],))

    ro = DurableStateStore(store.db_path, clock, readonly=True)
    report = Verifier(ro, clock).verify()
    by_name = {p.name: p for p in report.properties}
    assert by_name["audit_chain_intact"].status == "FAIL"


def test_only_rejections_is_inconclusive(store, authz, clock, killswitch):
    """A chain with only ACTION_REJECTED events cannot establish current
    switch state. evidence_sufficient must be INCONCLUSIVE, not PASS."""
    import hashlib

    killswitch.trip()
    d = authz.issue(
        AuthzIssueRequest(request_id="r1", identity="op-a", amount_minor=100)
    )
    commit_protected_action(
        store, authz,
        ActionRequest(
            request_id="r1", action_id="refund", amount_minor=100,
            currency="USD", decision_id=d.decision_id,
            idempotency_key="k1", identity="op-a",
        ),
        clock,
    )

    # Delete SWITCH_TRIPPED, then recompute hashes in place for the remaining
    # rows. Do NOT delete-and-reinsert: `seq` is AUTOINCREMENT and would not
    # restart at 1, breaking sequence continuity even though hashes would be
    # correct. Recompute prev_hash/hash in place, keeping the surviving seq
    # values, and reset seq to 1..N on the survivors so the chain is a valid
    # chain-from-genesis (which is exactly what an attacker who recomputed the
    # chain after removing one event would produce -- and the verifier must
    # accept it as intact, then judge sufficiency on content, not on the
    # absence of a sequence gap).
    with store.writer() as conn:
        conn.execute("DELETE FROM audit_events WHERE event_type = 'SWITCH_TRIPPED'")
        rows = conn.execute(
            "SELECT seq, event_id, event_type, recorded_at_us, payload_json"
            " FROM audit_events ORDER BY seq"
        ).fetchall()
        conn.execute("DELETE FROM audit_events")
        # sqlite_sequence reset so AUTOINCREMENT restarts at 1.
        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'audit_events'")
        prev = "0" * 64
        for r in rows:
            core = {
                "event_id": r["event_id"],
                "event_type": r["event_type"],
                "ts_us": int(r["recorded_at_us"]),
                "payload": json.loads(r["payload_json"]),
            }
            material = prev + json.dumps(
                core, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            h = hashlib.sha256(material.encode("utf-8")).hexdigest()
            conn.execute(
                "INSERT INTO audit_events"
                " (event_id, event_type, recorded_at_us, payload_json, prev_hash, hash)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (r["event_id"], r["event_type"], int(r["recorded_at_us"]),
                 r["payload_json"], prev, h),
            )
            prev = h

    ro = DurableStateStore(store.db_path, clock, readonly=True)
    report = Verifier(ro, clock).verify()
    by_name = {p.name: p for p in report.properties}
    assert by_name["audit_chain_intact"].status == "PASS"
    assert by_name["evidence_sufficient"].status == "INCONCLUSIVE"
    assert report.overall() == "INCONCLUSIVE"