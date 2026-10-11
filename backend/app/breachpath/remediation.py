"""
BreachPath remediation candidate ranking and greedy set cover (BP-07, BP-08).

Suggestions reference only existing edges on at least one attack route (BP-07).
User decides whether to apply; preview never mutates (BP-08).
"""

from __future__ import annotations

import copy
from typing import Any

from backend.app.breachpath.diff import compute_route_diff
from backend.app.breachpath.search import find_routes


def generate_remediations(
    model: dict[str, Any],
    routes: list[dict[str, Any]],
    graph_version: int = 1,
) -> dict[str, Any]:
    """
    Generate candidate edge removals ranked by routes broken, plus a greedy set cover plan (BP-07, BP-08).
    """
    total_routes = len(routes)
    if total_routes == 0:
        return {"suggestions": [], "plan": []}

    # Map existing edge_id to set of path_ids containing it (BP-07: existing edges only)
    cover: dict[str, set[str]] = {}
    for r in routes:
        pid = r["path_id"]
        for step in r.get("steps", []):
            eid = step.get("edge_id")
            if eid:
                cover.setdefault(eid, set()).add(pid)

    # Rank candidates by: (-len(path_ids), edge_id asc)
    ranked_edge_ids = sorted(
        cover.keys(),
        key=lambda eid: (-len(cover[eid]), eid),
    )

    suggestions: list[dict[str, Any]] = []
    routes_by_id = {r["path_id"]: r for r in routes}

    for eid in ranked_edge_ids:
        affected_pids = sorted(list(cover[eid]))
        breaks_count = len(affected_pids)

        # Model minus edge
        model_minus_edge = copy.deepcopy(model)
        model_minus_edge["edges"] = [
            e for e in model_minus_edge.get("edges", []) if e.get("id") != eid
        ]

        # Preview diff
        search_res = find_routes(model_minus_edge)
        diff_res = compute_route_diff(
            routes_before=routes,
            routes_after=search_res.routes,
            from_version=graph_version,
            to_version=graph_version,  # preview, no version bump
            comparison_reliable=not search_res.truncated,
        )

        # Rationale format: spec §3.4
        first_removed_pid = diff_res["removed"][0] if diff_res["removed"] else None
        removes_detail = ""
        if first_removed_pid and first_removed_pid in routes_by_id:
            short_desc = routes_by_id[first_removed_pid].get("short", "")
            if short_desc:
                removes_detail = f" Removes: {short_desc}"

        rationale = f"Breaks {breaks_count} of {total_routes} routes.{removes_detail}"

        suggestions.append({
            "edge_id": eid,
            "type": "remove_edge",
            "breaks": breaks_count,
            "path_ids": affected_pids,
            "rationale": rationale,
            "preview": {
                "removed": diff_res["removed"],
                "remaining": diff_res["remaining"],
                "new": diff_res["new"],
            },
        })

    # Greedy set cover: minimal set found greedily, ties by edge_id (spec §3.4)
    plan: list[dict[str, Any]] = []
    uncovered = set(routes_by_id.keys())
    remaining_candidates = dict(cover)

    while uncovered and remaining_candidates:
        # Pick candidate that covers the maximum uncovered routes, tie-break by edge_id asc
        best_edge = min(
            remaining_candidates.keys(),
            key=lambda eid: (-len(remaining_candidates[eid] & uncovered), eid),
        )
        newly_covered = len(remaining_candidates[best_edge] & uncovered)
        if newly_covered == 0:
            break

        plan.append({"edge_id": best_edge, "covers": newly_covered})
        uncovered -= remaining_candidates[best_edge]
        del remaining_candidates[best_edge]

    return {
        "suggestions": suggestions,
        "plan": plan,
    }


def preview_remediation(
    model: dict[str, Any],
    edge_id: str,
    routes: list[dict[str, Any]],
    graph_version: int = 1,
) -> dict[str, Any]:
    """Preview effect of removing edge_id without mutating graph (BP-08)."""
    # Check if edge exists
    edge_exists = any(e.get("id") == edge_id for e in model.get("edges", []))
    if not edge_exists:
        raise KeyError(f"Edge '{edge_id}' not found in graph.")

    model_minus_edge = copy.deepcopy(model)
    model_minus_edge["edges"] = [
        e for e in model_minus_edge.get("edges", []) if e.get("id") != edge_id
    ]

    search_res = find_routes(model_minus_edge)
    diff_res = compute_route_diff(
        routes_before=routes,
        routes_after=search_res.routes,
        from_version=graph_version,
        to_version=graph_version,
        comparison_reliable=not search_res.truncated,
    )

    return {
        "removed": diff_res["removed"],
        "remaining": diff_res["remaining"],
        "new": diff_res["new"],
        "comparison_reliable": diff_res["comparison_reliable"],
    }
