"""Generate a machine-readable test report with per-mutant detection matrix.

Covers all 16 mutants (M1-M16) including the six in-flight cancellation
mutants (M11-M16) and the four extended mutants from earlier batches.

Usage:
    PYTHONPATH=src .venv/bin/python scripts/report.py [--out report.json]
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

GROUPS = [
    ("suite_all",        ["tests/"],
        "Full test suite"),
    ("restart",          ["tests/test_s03_restart.py"],
        "Real process restart"),
    ("race",             ["tests/test_s05_race.py"],
        "Deterministic in-flight race"),
    ("concurrent",       ["tests/test_s06_concurrent.py", "tests/test_s12_budget.py"],
        "Concurrent actions and budget"),
    ("mutants",          ["tests/test_s10_mutants.py"],
        "Broken-control mutants (M1-M10)"),
    ("inflight_basic",   ["tests/test_s13_inflight_basic.py"],
        "In-flight cancellation: basic (Tests A-D)"),
    ("inflight_race",    ["tests/test_s13_inflight_race.py"],
        "In-flight cancellation: race (Tests E-G)"),
    ("inflight_recovery",["tests/test_s13_inflight_recovery.py"],
        "In-flight cancellation: recovery/idempotency/evidence (Tests H-J)"),
    ("inflight_mutants", ["tests/test_s14_inflight_mutants.py"],
        "In-flight mutants (M11-M16)"),
    ("evidence",         ["tests/test_s11_evidence.py"],
        "Evidence integrity and freshness"),
    ("api",              ["tests/test_s08_alt_route.py"],
        "API route enforcement"),
    ("stale_auth",       ["tests/test_s04_stale_auth.py"],
        "Stale authorization classification"),
]

MUTANT_MATRIX = {
    "M1":  {"description": "no_persist - TRIP not written to disk",
            "invariant": "Kill-switch state must survive process restart",
            "test": "test_m1_no_persist_detected", "expected": "PASSED"},
    "M2":  {"description": "skip_commit_check - commit ignores switch",
            "invariant": "Commit must reject when switch state != ARMED",
            "test": "test_m2_skip_commit_check_detected", "expected": "PASSED"},
    "M3":  {"description": "recover_clears - recover() ignores token",
            "invariant": "Recovery must require the operator token",
            "test": "test_m3_recover_clears_detected", "expected": "PASSED"},
    "M4":  {"description": "alt_bypass - alternate route bypasses commit",
            "invariant": "Every route must reach the same guarded commit function",
            "test": "test_m4_alt_bypass_detected", "expected": "PASSED"},
    "M5":  {"description": "ignore_epoch - commit ignores decision epoch",
            "invariant": "Decision epoch must match current switch epoch",
            "test": "test_m5_ignore_epoch_detected", "expected": "PASSED"},
    "M6":  {"description": "dup_retry - idempotency short-circuit removed",
            "invariant": "Repeated requests with same key must not re-execute",
            "test": "test_m6_dup_retry_detected", "expected": "PASSED"},
    "M7":  {"description": "idempotency_different_payload",
            "invariant": "Idempotency key bound to original payload",
            "test": "test_m7_different_payload_detected", "expected": "PASSED"},
    "M8":  {"description": "reuse_consumed_auth",
            "invariant": "Decision nonce consumed at most once",
            "test": "test_m8_reuse_consumed_detected", "expected": "PASSED"},
    "M9":  {"description": "budget_overspend",
            "invariant": "Budget must never go negative",
            "test": "test_m9_budget_overspend_detected", "expected": "PASSED"},
    "M10": {"description": "stale_evidence_pass",
            "invariant": "Stale evidence must be INCONCLUSIVE, not PASS",
            "test": "test_m10_stale_evidence_detected", "expected": "PASSED"},
    "M11": {"description": "trip_skips_cancel - TRIP does not fan out cancellation",
            "invariant": "Trip must signal cancellation to in-flight operations",
            "test": "test_m11_trip_skips_cancel_detected", "expected": "PASSED"},
    "M12": {"description": "commit_skips_switch - skips switch AND epoch checks",
            "invariant": "Commit enforces switch state; epoch is defense-in-depth",
            "test": "test_m12_commit_skips_switch_detected", "expected": "PASSED"},
    "M13": {"description": "commit_skips_epoch",
            "invariant": "Commit must reject stale pre-trip decisions after recovery",
            "test": "test_m13_commit_skips_epoch_detected", "expected": "PASSED"},
    "M14": {"description": "lie_terminal - overwrites SUCCEEDED with CANCELLED",
            "invariant": "Terminal outcome must be recorded exactly once",
            "test": "test_m14_lie_terminal_detected", "expected": "PASSED"},
    "M15": {"description": "alt_route_bypass - /actions/alt writes without commit",
            "invariant": "Alternate routes must not bypass in-flight enforcement",
            "test": "test_m15_alt_route_bypass_detected", "expected": "PASSED"},
    "M16": {"description": "recover_revives - recover() clears cancel events",
            "invariant": "Recovery must not revive invalid in-flight operations",
            "test": "test_m16_recover_revives_detected", "expected": "PASSED"},
}


def _run_pytest(args: list[str], extra: list[str] | None = None) -> subprocess.CompletedProcess:
    cmd = [
        ".venv/bin/python", "-m", "pytest",
        *args, "--no-header", "-p", "no:cacheprovider",
        "-o", "addopts=", "--color=no",
    ]
    if extra:
        cmd.extend(extra)
    return subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300)


def _summarize(proc: subprocess.CompletedProcess) -> dict:
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    summary_line = lines[-1] if lines else "(no output)"
    status = {0: "PASSED", 1: "FAILED", 2: "INTERRUPTED",
              3: "INTERNAL_ERROR", 4: "USAGE_ERROR", 5: "NO_TESTS"}.get(
        proc.returncode, f"EXIT_{proc.returncode}")
    return {"status": status, "exit_code": proc.returncode,
            "summary": summary_line,
            "stdout_tail": lines[-30:] if lines else [],
            "stderr_tail": [ln for ln in proc.stderr.strip().splitlines()[-10:] if ln.strip()]}


def _parse_test_outcomes(proc: subprocess.CompletedProcess) -> dict[str, str]:
    outcomes: dict[str, str] = {}
    for raw in proc.stdout.splitlines():
        line = raw.strip()
        if "::" not in line:
            continue
        after = line.split("::", 1)[1]
        parts = after.split()
        if not parts:
            continue
        test_name = parts[0]
        for st in ("PASSED", "FAILED", "ERROR", "SKIPPED", "XFAIL", "XPASS"):
            if st in parts:
                outcomes[test_name] = st
                break
    return outcomes


def _run_mutant_matrix() -> dict:
    try:
        proc = _run_pytest(
            ["tests/test_s10_mutants.py", "tests/test_s14_inflight_mutants.py"],
            extra=["-v"],
        )
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "rows": [], "matrix": {}}

    outcomes = _parse_test_outcomes(proc)
    rows = []
    all_detected = True
    for mutant_id, spec in MUTANT_MATRIX.items():
        observed = outcomes.get(spec["test"], "NOT_RUN")
        detected = observed == spec["expected"]
        if not detected:
            all_detected = False
        rows.append({
            "id": mutant_id,
            "description": spec["description"],
            "invariant": spec["invariant"],
            "test": spec["test"],
            "expected": spec["expected"],
            "observed": observed,
            "detected": detected,
        })
    return {
        "status": "PASSED" if all_detected else "FAILED",
        "rows": rows,
        "matrix": {r["id"]: r for r in rows},
        "exit_code": proc.returncode,
        "stdout_tail": [ln for ln in proc.stdout.strip().splitlines()[-30:] if ln.strip()],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="report.json")
    args = ap.parse_args()

    report: dict = {"groups": {}, "mutants": {}, "overall": "UNKNOWN"}
    any_failed = False
    any_missing = False

    for name, group_args, human in GROUPS:
        print(f"running: {name} ({human}) ...", flush=True)
        try:
            proc = _run_pytest(group_args)
        except subprocess.TimeoutExpired:
            report["groups"][name] = {"human": human, "status": "TIMEOUT"}
            any_missing = True
            print("  TIMEOUT")
            continue
        summary = _summarize(proc)
        report["groups"][name] = {"human": human, "pytest_args": group_args, **summary}
        if summary["status"] == "PASSED":
            print(f"  {summary['summary']}")
        elif summary["status"] in ("FAILED", "INTERNAL_ERROR", "INTERRUPTED", "USAGE_ERROR"):
            print(f"  FAILED: {summary['summary']}")
            any_failed = True
        else:
            print(f"  {summary['status']}: {summary['summary']}")
            any_missing = True

    print("running: mutant_matrix (M1-M16) ...", flush=True)
    matrix = _run_mutant_matrix()
    report["mutants"] = matrix
    detected = sum(1 for r in matrix["rows"] if r["detected"])
    total = len(matrix["rows"])
    if matrix["status"] == "PASSED":
        print(f"  {detected}/{total} mutants detected")
        for row in matrix["rows"]:
            print(f"    {row['id']:>3}: {row['observed']:<8} {row['description']}")
    else:
        print(f"  mutant matrix: FAILED ({detected}/{total})")
        for row in matrix["rows"]:
            if not row["detected"]:
                print(f"    MISSED: {row['id']} ({row['test']} = {row['observed']})")
        any_failed = True

    if any_failed:
        report["overall"] = "FAILED"
    elif any_missing:
        report["overall"] = "INCONCLUSIVE"
    else:
        report["overall"] = "PASSED"

    Path(args.out).write_text(json.dumps(report, indent=2))
    print()
    print(f"wrote {args.out}")
    print(f"overall: {report['overall']}")
    return 0 if report["overall"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
