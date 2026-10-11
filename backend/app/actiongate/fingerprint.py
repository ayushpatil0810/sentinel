"""
Action fingerprinting (AG-06, data-models.md §4).

Fingerprint:
  SHA-256(canonical_json({agent_id, action_type, arguments, target}))
  where target is the value at target_field (or null).
"""

from __future__ import annotations

import hashlib
from typing import Any

from backend.app.core.canonical import canonical_json


def extract_target(arguments: dict[str, Any], target_field: str | None) -> str | None:
    """Extract target string from arguments using JSON pointer (e.g. '/to/0', '/url', '/resource')."""
    if not target_field:
        return None

    parts = [p for p in target_field.split("/") if p]
    cur: Any = arguments
    for p in parts:
        if isinstance(cur, list):
            try:
                idx = int(p)
                cur = cur[idx]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            if p not in cur:
                return None
            cur = cur[p]
        else:
            return None

    return str(cur) if cur is not None else None


def compute_action_fingerprint(
    agent_id: str,
    action_type: str,
    arguments: dict[str, Any],
    target: str | None,
) -> str:
    """
    Compute SHA-256 fingerprint of canonical JSON of {agent_id, action_type, arguments, target}.
    """
    obj = {
        "action_type": action_type,
        "agent_id": agent_id,
        "arguments": arguments,
        "target": target,
    }
    canon = canonical_json(obj)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()
