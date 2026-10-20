"""End-to-end demonstration of the kill-switch harness.

Runs a full lifecycle in a temporary database:

    initial -> issue+commit -> idempotent replay -> trip -> reject under trip
            -> unauthorized recovery (rejected)
            -> authorized recovery -> replay of previously rejected decision
            -> stale decision (STALE_EPOCH) -> fresh decision (SUCCESS)
            -> verifier report -> JSON summary

Prints machine-readable JSON to stdout so two runs can be diffed.

Usage:
    PYTHONPATH=src .venv/bin/python scripts/demo.py [--db PATH] [--keep] [--budget N]

Exit codes:
    0  demo completed; verifier returned PASS or INCONCLUSIVE
    1  demo completed but verifier returned FAIL
    2  unexpected exception
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

# Make src/ importable when running from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from harness.authz import AuthorizationService
from harness.clock import RealClock
from harness.commit import commit_protected_action
from harness.killswitch import KillSwitchController
from harness.schemas import ActionRequest, AuthzIssueRequest
from harness.store import DurableStateStore
from harness.verifier import Verifier

TOKEN = "demo-recovery-token"


def _print_section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def main() -> int:
    ap = argparse.ArgumentParser(description="Kill-switch harness demo")
    ap.add_argument("--db", help="Database path (default: temporary file)")
    ap.add_argument("--keep", action="store_true", help="Keep the temp database")
    ap.add_argument("--budget", type=int, default=10_000)
    args = ap.parse_args()

    if args.db:
        db_path = args.db
        cleanup = False
    else:
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        cleanup = not args.keep

    clock = RealClock()
    summary: dict = {"db_path": db_path, "steps": []}

    try:
        store = DurableStateStore(db_path, clock)
        store.init_schema(
            initial_budget_minor=args.budget, policy_version="policy-v1"
        )
        authz = AuthorizationService(store, clock)
        killswitch = KillSwitchController(store, clock, recovery_token=TOKEN)

        # ---------------- 1. Initial state
        _print_section("1. Initial state")
        s = killswitch.status()
        print(
            f"   state={s.state.value} epoch={s.epoch} "
            f"budget={store.get_budget_remaining()}"
        )
        summary["steps"].append(
            {
                "step": "initial",
                "state": s.state.value,
                "epoch": s.epoch,
                "budget": store.get_budget_remaining(),
            }
        )

        # ---------------- 2. Issue + commit
        _print_section("2. Issue authorization and commit")
        d1 = authz.issue(
            AuthzIssueRequest(
                request_id="demo-r1",
                identity="op-a",
                amount_minor=250,
                currency="USD",
                ttl_seconds=60,
            )
        )
        req1 = ActionRequest(
            request_id="demo-r1",
            action_id="refund",
            amount_minor=250,
            currency="USD",
            decision_id=d1.decision_id,
            idempotency_key="demo-k1",
            identity="op-a",
        )
        r1 = commit_protected_action(store, authz, req1, clock)
        print(f"   outcome={r1.outcome} reason={r1.reason_code} replayed={r1.replayed}")
        summary["steps"].append(
            {
                "step": "commit",
                "outcome": r1.outcome,
                "reason": r1.reason_code,
                "replayed": r1.replayed,
            }
        )

        # ---------------- 3. Idempotent replay
        _print_section("3. Retry same request (idempotent replay)")
        r2 = commit_protected_action(store, authz, req1, clock)
        print(f"   outcome={r2.outcome} reason={r2.reason_code} replayed={r2.replayed}")
        summary["steps"].append(
            {
                "step": "replay",
                "outcome": r2.outcome,
                "reason": r2.reason_code,
                "replayed": r2.replayed,
            }
        )

        # ---------------- 4. TRIP
        _print_section("4. TRIP the kill switch")
        s = killswitch.trip(actor="op-a", reason="demo")
        print(f"   state={s.state.value} epoch={s.epoch}")
        summary["steps"].append(
            {"step": "trip", "state": s.state.value, "epoch": s.epoch}
        )

        # ---------------- 5. Attempt a new action under TRIP
        _print_section("5. Attempt a new action under TRIP")
        d2 = authz.issue(
            AuthzIssueRequest(
                request_id="demo-r2",
                identity="op-a",
                amount_minor=100,
                currency="USD",
                ttl_seconds=60,
            )
        )
        req2 = ActionRequest(
            request_id="demo-r2",
            action_id="refund",
            amount_minor=100,
            currency="USD",
            decision_id=d2.decision_id,
            idempotency_key="demo-k2",
            identity="op-a",
        )
        r3 = commit_protected_action(store, authz, req2, clock)
        print(f"   outcome={r3.outcome} reason={r3.reason_code}")
        summary["steps"].append(
            {
                "step": "commit_under_trip",
                "outcome": r3.outcome,
                "reason": r3.reason_code,
            }
        )

        # ---------------- 6. Unauthorized recovery
        _print_section("6. Unauthorized recovery")
        ok = killswitch.recover(token="wrong-token")
        s = killswitch.status()
        print(f"   authorized={ok} state={s.state.value} epoch={s.epoch}")
        summary["steps"].append(
            {
                "step": "recover_unauthorized",
                "authorized": ok,
                "state": s.state.value,
                "epoch": s.epoch,
            }
        )

        # ---------------- 7. Authorized recovery
        _print_section("7. Authorized recovery")
        ok = killswitch.recover(token=TOKEN)
        s = killswitch.status()
        print(f"   authorized={ok} state={s.state.value} epoch={s.epoch}")
        summary["steps"].append(
            {
                "step": "recover_authorized",
                "authorized": ok,
                "state": s.state.value,
                "epoch": s.epoch,
            }
        )

        # ---------------- 8. Replay of previously-rejected decision
        _print_section(
            "8. Replay of previously-rejected decision (idempotency)"
        )
        r4 = commit_protected_action(store, authz, req2, clock)
        print(f"   outcome={r4.outcome} reason={r4.reason_code} replayed={r4.replayed}")
        summary["steps"].append(
            {
                "step": "replay_rejected_after_recovery",
                "outcome": r4.outcome,
                "reason": r4.reason_code,
                "replayed": r4.replayed,
            }
        )

        # ---------------- 9. Stale decision at commit (STALE_EPOCH)
        _print_section("9. Stale decision rejected at commit (STALE_EPOCH)")
        # Issue while ARMED, never commit, then trip+recover, then attempt.
        d_pre = authz.issue(
            AuthzIssueRequest(
                request_id="demo-stale",
                identity="op-a",
                amount_minor=100,
                currency="USD",
                ttl_seconds=60,
            )
        )
        assert killswitch.trip().state.value == "TRIPPED"
        assert killswitch.recover(token=TOKEN) is True
        stale_req = ActionRequest(
            request_id="demo-stale",
            action_id="refund",
            amount_minor=100,
            currency="USD",
            decision_id=d_pre.decision_id,
            idempotency_key="demo-k-stale",
            identity="op-a",
        )
        r5 = commit_protected_action(store, authz, stale_req, clock)
        print(f"   outcome={r5.outcome} reason={r5.reason_code}")
        summary["steps"].append(
            {
                "step": "stale_after_recovery",
                "outcome": r5.outcome,
                "reason": r5.reason_code,
            }
        )

        # ---------------- 10. Fresh decision after recovery
        _print_section("10. Fresh decision after recovery (must succeed)")
        d3 = authz.issue(
            AuthzIssueRequest(
                request_id="demo-r3",
                identity="op-a",
                amount_minor=100,
                currency="USD",
                ttl_seconds=60,
            )
        )
        req3 = ActionRequest(
            request_id="demo-r3",
            action_id="refund",
            amount_minor=100,
            currency="USD",
            decision_id=d3.decision_id,
            idempotency_key="demo-k3",
            identity="op-a",
        )
        r6 = commit_protected_action(store, authz, req3, clock)
        print(f"   outcome={r6.outcome} reason={r6.reason_code}")
        summary["steps"].append(
            {
                "step": "fresh_after_recovery",
                "outcome": r6.outcome,
                "reason": r6.reason_code,
            }
        )

        # ---------------- 11. Verifier report
        _print_section("11. Independent verifier report")
        ro = DurableStateStore(db_path, clock, readonly=True)
        report = Verifier(
            ro, clock, staleness_window_us=60 * 60 * 1_000_000
        ).verify()
        for p in report.properties:
            print(f"   {p.name:30s} {p.status:14s} {p.detail}")
        print(f"   {'overall':30s} {report.overall()}")
        summary["verifier"] = report.to_dict()

        # ---------------- 12. JSON summary
        _print_section("12. Machine-readable summary")
        print(json.dumps(summary, indent=2, sort_keys=True))

        return 0 if report.overall() != "FAIL" else 1

    except Exception:
        traceback.print_exc()
        return 2
    finally:
        if cleanup and Path(db_path).exists():
            try:
                Path(db_path).unlink()
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())