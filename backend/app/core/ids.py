"""
ID generation helpers.

All IDs use a monotonically increasing counter seeded at startup.
Prefixes match the domain object:
    req_   – request IDs (middleware)
    sess_  – sessions
    act_   – actions
    apr_   – approvals
    prop_  – policy proposals
    rev_   – ingress reviews
    run_   – test / benchmark runs
    pay_   – ledger payload IDs

Format: <prefix><zero-padded 9-digit counter>  (e.g. act_000000001)
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_counters: dict[str, int] = {}


def next_id(prefix: str) -> str:
    """Return the next ID for *prefix*, e.g. 'act_000001'."""
    with _lock:
        n = _counters.get(prefix, 0) + 1
        _counters[prefix] = n
        return f"{prefix}{n:06d}"


def reset_counters() -> None:
    """Reset all counters to zero (call from test fixtures)."""
    with _lock:
        _counters.clear()


def peek_counter(prefix: str) -> int:
    """Return the current counter value without incrementing (for tests)."""
    with _lock:
        return _counters.get(prefix, 0)
