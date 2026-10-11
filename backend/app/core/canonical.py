"""
Canonical JSON helper (D-23, spec.md §0).

Rule:
    sorted keys, separators (',', ':'), ensure_ascii=False, UTF-8,
    no floats (callers must convert floats to int before passing),
    no NaN or Infinity.

Used by the ledger hasher, fingerprint computation, and approval signatures.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json(obj: Any) -> str:
    """Return the canonical JSON string of *obj*.

    Raises TypeError if *obj* contains a float (use int everywhere per D-20).
    """
    _check_no_float(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_json_bytes(obj: Any) -> bytes:
    """Return canonical JSON encoded as UTF-8 bytes."""
    return canonical_json(obj).encode("utf-8")


def _check_no_float(obj: Any) -> None:
    """Recursively verify no float values are present."""
    if isinstance(obj, float):
        raise TypeError(f"canonical_json: float values are forbidden, got {obj!r}")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_no_float(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_no_float(item)
