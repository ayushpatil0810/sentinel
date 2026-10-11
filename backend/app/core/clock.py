"""
Injected Clock abstraction (spec.md §0, architecture.md D-27).

All code that needs "now" must use an injected Clock, never datetime.now() directly.
This lets tests and the scripted replay control time deterministically.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime


class Clock:
    """Real-time clock.  Returns UTC datetimes."""

    def now_dt(self) -> datetime:
        """Return the current UTC datetime with millisecond precision."""
        return datetime.now(UTC).replace(microsecond=0)

    def now_iso(self) -> str:
        """Return UTC ISO-8601 string with milliseconds and Z (spec.md §0)."""
        dt = datetime.now(UTC)
        ms = dt.microsecond // 1000
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"

    def monotonic(self) -> float:
        """Return time.monotonic() for budget tracking."""
        return time.monotonic()

    def timestamp(self) -> float:
        """Return a POSIX timestamp (seconds since epoch)."""
        return datetime.now(UTC).timestamp()


class FixedClock(Clock):
    """
    Deterministic clock for tests and replay (spec.md §0).

    Starts at *start_iso* and advances by *step_ms* milliseconds
    on every call to now_iso() (so each call returns a distinct value).
    """

    def __init__(
        self,
        start_iso: str = "2026-01-01T00:00:00.000Z",
        step_ms: int = 1000,
    ) -> None:
        self._dt = _parse_iso(start_iso)
        self._step_ms = step_ms
        self._mono: float = 0.0

    def now_dt(self) -> datetime:
        dt = self._dt
        from datetime import timedelta
        self._dt = self._dt + timedelta(milliseconds=self._step_ms)
        return dt

    def now_iso(self) -> str:
        dt = self.now_dt()
        ms = dt.microsecond // 1000
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"

    def monotonic(self) -> float:
        val = self._mono
        self._mono += self._step_ms / 1000.0
        return val

    def timestamp(self) -> float:
        return self._dt.timestamp()

    def advance(self, seconds: float) -> None:
        """Advance the clock by *seconds* (for expiry tests)."""
        from datetime import timedelta
        self._dt = self._dt + timedelta(seconds=seconds)
        self._mono += seconds


def _parse_iso(s: str) -> datetime:
    """Parse 'YYYY-MM-DDTHH:MM:SS.mmmZ' into a UTC datetime."""
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


# Module-level default clock; tests swap this via dependency injection
_default_clock: Clock = Clock()


def get_clock() -> Clock:
    """FastAPI dependency: return the active clock."""
    return _default_clock


def set_clock(clock: Clock) -> None:
    """Replace the module-level clock (test helper)."""
    global _default_clock
    _default_clock = clock
