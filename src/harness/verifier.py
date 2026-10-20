"""Independent verifier.

Reads durable evidence from SQLite READ-ONLY and returns a VerifyReport with
per-property PASS / FAIL / INCONCLUSIVE.

TRUST BOUNDARIES (important):
    The verifier shares the SQLite file with the gateway. It is a separate
    MODULE but NOT independent infrastructure. An attacker who can rewrite the
    entire database file and recompute the whole hash chain defeats
    `audit_chain_intact`. Detecting that requires an external witness (e.g.,
    shipping signed head digests to a remote log). Documented as residual risk.

    A valid signature on a refusal proves the refusal bytes were produced by
    the signer at issue time; it does NOT prove current kill-switch state.
"""
from __future__ import annotations

from .audit import AuditChain
from .clock import Clock, RealClock
from .schemas import AuditRecord, SwitchState, VerifyProperty, VerifyReport
from .store import DurableStateStore


class Verifier:
    def __init__(
        self,
        store_readonly: DurableStateStore,
        clock: Clock | None = None,
        *,
        staleness_window_us: int = 5 * 60 * 1_000_000,
    ) -> None:
        if not store_readonly.readonly:
            raise ValueError("Verifier requires a store opened with readonly=True")
        self.store = store_readonly
        self.clock = clock or RealClock()
        self.staleness_window_us = staleness_window_us

    # -------------------------------------------------------------- helpers
    def _switch_intervals(
        self, events: list[AuditRecord]
    ) -> list[tuple[int, int | None, SwitchState, int]]:
        """Return [(start_us, end_us_or_None, state, epoch), ...] derived from audit.

        Convention: harness seeds ARMED/epoch=1 at time 0. Only SWITCH_TRIPPED
        and RECOVERY_AUTHORIZED change state.
        """
        intervals: list[tuple[int, int | None, SwitchState, int]] = [
            (0, None, SwitchState.ARMED, 1)
        ]
        for ev in events:
            if ev.event_type == "SWITCH_TRIPPED":
                new_state = SwitchState.TRIPPED
                new_epoch = int(ev.payload.get("new_epoch", 0))
            elif ev.event_type == "RECOVERY_AUTHORIZED":
                new_state = SwitchState.ARMED
                new_epoch = int(ev.payload.get("new_epoch", 0))
            else:
                continue
            start, _end, st, ep = intervals[-1]
            intervals[-1] = (start, ev.recorded_at_us, st, ep)
            intervals.append((ev.recorded_at_us, None, new_state, new_epoch))
        return intervals

    @staticmethod
    def _state_at(
        intervals: list[tuple[int, int | None, SwitchState, int]],
        ts_us: int,
    ) -> tuple[SwitchState, int] | None:
        for start, end, state, epoch in intervals:
            if ts_us >= start and (end is None or ts_us < end):
                return state, epoch
        return None

    # -------------------------------------------------------------- verify
    def verify(self) -> VerifyReport:
        observed_at_us = self.clock.now_us()
        events = AuditChain.read_all(self.store)
        report = VerifyReport(observed_at_us=observed_at_us)
        if events:
            report.audit_head_seq = events[-1].seq
            report.audit_head_hash = events[-1].hash

        # ---------------- audit_chain_intact
        ok, detail = AuditChain.verify_chain(events)
        report.properties.append(
            VerifyProperty(
                name="audit_chain_intact",
                status="PASS" if ok else "FAIL",
                detail=detail,
            )
        )

        # ---------------- no_duplicate_actions
        with self.store.reader() as conn:
            dup_action_rows = conn.execute(
                "SELECT idempotency_key, COUNT(*) AS c FROM actions"
                " GROUP BY idempotency_key HAVING c > 1"
            ).fetchall()
            action_count = int(
                conn.execute("SELECT COUNT(*) AS c FROM actions").fetchone()["c"]
            )
            idem_count = int(
                conn.execute("SELECT COUNT(*) AS c FROM idempotency").fetchone()["c"]
            )
            dup_idem_rows = conn.execute(
                "SELECT key, COUNT(*) AS c FROM idempotency"
                " GROUP BY key HAVING c > 1"
            ).fetchall()

        if dup_action_rows or dup_idem_rows:
            report.properties.append(
                VerifyProperty(
                    name="no_duplicate_actions",
                    status="FAIL",
                    detail=(
                        f"duplicate action keys={len(dup_action_rows)} "
                        f"idempotency keys={len(dup_idem_rows)}"
                    ),
                )
            )
        elif action_count == 0 and idem_count == 0:
            report.properties.append(
                VerifyProperty(
                    name="no_duplicate_actions",
                    status="PASS",
                    detail="no actions or idempotency rows; vacuous",
                )
            )
        else:
            report.properties.append(
                VerifyProperty(
                    name="no_duplicate_actions",
                    status="PASS",
                    detail=f"actions={action_count} idem={idem_count}",
                )
            )

        # ---------------- no_actions_while_tripped
        intervals = self._switch_intervals(events)
        with self.store.reader() as conn:
            actions = conn.execute(
                "SELECT action_id, epoch, committed_at_us FROM actions"
                " ORDER BY committed_at_us"
            ).fetchall()
        violation_actions = []
        inconclusive_actions = []
        for a in actions:
            state_at = self._state_at(intervals, int(a["committed_at_us"]))
            if state_at is None:
                inconclusive_actions.append(a["action_id"])
                continue
            state, _ = state_at
            if state == SwitchState.TRIPPED:
                violation_actions.append(a["action_id"])
        if violation_actions:
            report.properties.append(
                VerifyProperty(
                    name="no_actions_while_tripped",
                    status="FAIL",
                    detail=f"actions committed while TRIPPED: {violation_actions}",
                )
            )
        elif inconclusive_actions:
            report.properties.append(
                VerifyProperty(
                    name="no_actions_while_tripped",
                    status="INCONCLUSIVE",
                    detail=f"no covering interval for: {inconclusive_actions}",
                )
            )
        else:
            report.properties.append(
                VerifyProperty(
                    name="no_actions_while_tripped",
                    status="PASS",
                    detail=f"checked {len(actions)} action(s)",
                )
            )

        # ---------------- no_stale_epoch_commits
        stale = []
        no_cover = []
        for a in actions:
            state_at = self._state_at(intervals, int(a["committed_at_us"]))
            if state_at is None:
                no_cover.append(a["action_id"])
                continue
            _, epoch_at = state_at
            if int(a["epoch"]) != int(epoch_at):
                stale.append(
                    {"action_id": a["action_id"], "action_epoch": int(a["epoch"]),
                     "epoch_at": int(epoch_at)}
                )
        if stale:
            report.properties.append(
                VerifyProperty(
                    name="no_stale_epoch_commits",
                    status="FAIL",
                    detail=f"epoch mismatches: {stale}",
                )
            )
        elif no_cover:
            report.properties.append(
                VerifyProperty(
                    name="no_stale_epoch_commits",
                    status="INCONCLUSIVE",
                    detail=f"no covering interval for: {no_cover}",
                )
            )
        else:
            report.properties.append(
                VerifyProperty(
                    name="no_stale_epoch_commits",
                    status="PASS",
                    detail=f"checked {len(actions)} action(s)",
                )
            )

        # ---------------- evidence_current
        if not events:
            report.properties.append(
                VerifyProperty(
                    name="evidence_current",
                    status="INCONCLUSIVE",
                    detail="audit chain empty",
                )
            )
        else:
            age_us = observed_at_us - events[-1].recorded_at_us
            if age_us > self.staleness_window_us:
                report.properties.append(
                    VerifyProperty(
                        name="evidence_current",
                        status="INCONCLUSIVE",
                        detail=f"head older than window by {age_us - self.staleness_window_us}us",
                    )
                )
            else:
                report.properties.append(
                    VerifyProperty(
                        name="evidence_current",
                        status="PASS",
                        detail=f"head age {age_us}us within window",
                    )
                )

        # ---------------- evidence_sufficient
        # Sufficient iff at least one state-changing event exists whose payload
        # declares an outcome, OR the switch table currently says ARMED and the
        # chain contains at least one event (any). Signed refusals (ACTION_REJECTED)
        # alone do NOT establish current state, so we require a state-change
        # event OR zero refusals combined with zero actions (empty system).
        state_change_events = [
            ev for ev in events
            if ev.event_type in ("SWITCH_TRIPPED", "RECOVERY_AUTHORIZED")
        ]
        only_rejections = (
            len(events) > 0
            and all(ev.event_type == "ACTION_REJECTED" for ev in events)
        )
        if state_change_events:
            report.properties.append(
                VerifyProperty(
                    name="evidence_sufficient",
                    status="PASS",
                    detail=f"state-change events present: {len(state_change_events)}",
                )
            )
        elif only_rejections:
            report.properties.append(
                VerifyProperty(
                    name="evidence_sufficient",
                    status="INCONCLUSIVE",
                    detail="only ACTION_REJECTED events present; cannot establish current state",
                )
            )
        elif not events:
            # Empty system: current switch table (read-only) is the only evidence
            current = self.store.get_switch()
            report.properties.append(
                VerifyProperty(
                    name="evidence_sufficient",
                    status="PASS",
                    detail=f"no audit events; switch currently {current.state.value}",
                )
            )
        else:
            report.properties.append(
                VerifyProperty(
                    name="evidence_sufficient",
                    status="INCONCLUSIVE",
                    detail="no state-change events and no rejection-only evidence",
                )
            )

        return report


__all__ = ["Verifier"]