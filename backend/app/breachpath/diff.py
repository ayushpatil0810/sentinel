"""
BreachPath route diffing between graph versions (BP-09, BP-10).

Calculates removed, remaining, and new routes keyed by path_id.
Honest comparison_reliable flag when either side is truncated (BP-10).
"""

from __future__ import annotations

from typing import Any


def compute_route_diff(
    routes_before: list[dict[str, Any]],
    routes_after: list[dict[str, Any]],
    from_version: int,
    to_version: int,
    comparison_reliable: bool = True,
) -> dict[str, Any]:
    """
    Compute diff between two route sets (BP-09).
    Returns dict matching data-models.md §3 diff schema.
    """
    before_map = {r["path_id"]: r for r in routes_before}
    after_map = {r["path_id"]: r for r in routes_after}

    removed_ids = [pid for pid in before_map if pid not in after_map]
    remaining_ids = [pid for pid in before_map if pid in after_map]
    new_ids = [pid for pid in after_map if pid not in before_map]

    return {
        "from_version": from_version,
        "to_version": to_version,
        "comparison_reliable": comparison_reliable,
        "removed": removed_ids,
        "remaining": remaining_ids,
        "new": new_ids,
        "routes": {
            "removed": [before_map[pid] for pid in removed_ids],
            "new": [after_map[pid] for pid in new_ids],
        },
    }
