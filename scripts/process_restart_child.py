"""Child process for the real-restart test.

Usage:
    python scripts/process_restart_child.py <db_path>

Trips the kill switch, prints the resulting epoch to stdout, exits 0.
The parent test opens a fresh store against the same db_path and verifies
that the switch is still TRIPPED.
"""
from __future__ import annotations

import sys

sys.path.insert(0, "src")

from harness.clock import RealClock
from harness.config import Settings
from harness.killswitch import KillSwitchController
from harness.store import DurableStateStore


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: process_restart_child.py <db_path>", file=sys.stderr)
        return 2
    db_path = sys.argv[1]
    settings = Settings.from_env()
    clock = RealClock()
    store = DurableStateStore(db_path, clock)
    store.init_schema(
        initial_budget_minor=settings.initial_budget_minor,
        policy_version=settings.policy_version,
    )
    ks = KillSwitchController(store, clock, recovery_token=settings.recovery_token)
    status = ks.trip(actor="child-process", reason="restart-test")
    print(f"child tripped; state={status.state.value} epoch={status.epoch}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())