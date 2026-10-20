"""Clock abstraction. All times are integer microseconds since Unix epoch (UTC)."""
from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now_us(self) -> int: ...


class RealClock:
    """Wall clock. Truncates to microseconds."""

    def now_us(self) -> int:
        return int(time.time() * 1_000_000)


class ManualClock:
    """Deterministic clock for tests. Starts at an arbitrary epoch and advances only when told."""

    def __init__(self, start_us: int = 1_700_000_000_000_000) -> None:
        self._t = int(start_us)

    def now_us(self) -> int:
        return self._t

    def advance(self, delta_us: int) -> int:
        if delta_us < 0:
            raise ValueError("ManualClock only advances forward")
        self._t += int(delta_us)
        return self._t

    def set(self, value_us: int) -> None:
        self._t = int(value_us)