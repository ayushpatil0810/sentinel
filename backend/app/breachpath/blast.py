"""
BreachPath blast radius computation and entry point derivation (BP-11, BP-12, X-02, X-03).

- blast_radius(node_id): attack path membership, distance to sensitive, reachable sensitivity, level.
- derive_entry_points(registry, model): marks tool nodes as derived entry points without inventing nodes.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from backend.app.breachpath.search import (
    SENSITIVITY_RANK,
    build_adjacency,
    find_routes,
)


def blast_radius(node_id: str) -> dict[str, Any]:
    """Top-level blast_radius function called by gateway and policy context (spec §3.5, BP-12)."""
    try:
        from backend.app.breachpath.store import get_current_graph
        _, model = get_current_graph()
        return compute_blast_radius(model, node_id)
    except Exception:
        return {
            "node_id": node_id,
            "on_attack_path": True,
            "paths_count": 0,
            "min_distance_to_sensitive": None,
            "max_sensitivity_reachable": "none",
            "level": "high",
            "reason": "graph_unavailable",
        }


def compute_blast_radius(
    model: dict[str, Any] | None,
    node_id: str,
    routes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Compute blast radius for node_id (BP-12, spec §3.5, architecture D-14).

    Fail-safe: unknown node or unavailable graph returns level='high' with reason.
    """
    if not model or not isinstance(model, dict):
        return {
            "node_id": node_id,
            "on_attack_path": False,
            "paths_count": 0,
            "min_distance_to_sensitive": None,
            "max_sensitivity_reachable": "none",
            "level": "high",
            "reason": "graph_unavailable",
        }

    nodes = model.get("nodes", [])
    node_map = {n["id"]: n for n in nodes}

    if node_id not in node_map:
        return {
            "node_id": node_id,
            "on_attack_path": False,
            "paths_count": 0,
            "min_distance_to_sensitive": None,
            "max_sensitivity_reachable": "none",
            "level": "high",
            "reason": "unknown_node",
        }

    # 1. Routes containing the node as entry, intermediate, or asset
    if routes is None:
        search_res = find_routes(model)
        routes = search_res.routes

    matching_routes: list[dict[str, Any]] = []
    for r in routes:
        nodes_in_route = set()
        nodes_in_route.add(r.get("entry"))
        nodes_in_route.add(r.get("asset"))
        for s in r.get("steps", []):
            nodes_in_route.add(s.get("from"))
            nodes_in_route.add(s.get("to"))
        if node_id in nodes_in_route:
            matching_routes.append(r)

    paths_count = len(matching_routes)
    on_attack_path = paths_count > 0

    # 2. Forward traversal distance and reachable sensitive nodes (within max_depth)
    settings = model.get("settings", {})
    max_depth = settings.get("max_depth", 4)
    sensitive_min = settings.get("sensitive_min", "medium")
    min_rank = SENSITIVITY_RANK.get(sensitive_min, 2)

    target_nodes = {
        n["id"]: n.get("sensitivity", "none")
        for n in nodes
        if SENSITIVITY_RANK.get(n.get("sensitivity", "none"), 0) >= min_rank
    }

    target_node = node_map[node_id]
    own_sens = target_node.get("sensitivity", "none")

    min_distance: int | None = None
    max_sens = own_sens if SENSITIVITY_RANK.get(own_sens, 0) >= min_rank else "none"

    if node_id in target_nodes:
        min_distance = 0
    else:
        # BFS traversal using graph adjacency
        adj = build_adjacency(model)
        queue: deque[tuple[str, int]] = deque([(node_id, 0)])
        visited: set[str] = {node_id}

        while queue:
            cur, dist = queue.popleft()
            if dist >= max_depth:
                continue

            for _, nxt, _ in adj.get(cur, []):
                if nxt in visited:
                    continue
                visited.add(nxt)
                new_dist = dist + 1

                if nxt in target_nodes:
                    if min_distance is None:
                        min_distance = new_dist
                    nxt_sens = target_nodes[nxt]
                    if SENSITIVITY_RANK.get(nxt_sens, 0) > SENSITIVITY_RANK.get(max_sens, 0):
                        max_sens = nxt_sens
                else:
                    queue.append((nxt, new_dist))

    # 3. Determine Level per D-14:
    # high if on an attack path and a high or critical asset is reachable.
    # medium if on a path, or if a sensitive asset is reachable but the node is on no path.
    # Otherwise low.
    max_sens_rank = SENSITIVITY_RANK.get(max_sens, 0)
    high_or_critical = max_sens_rank >= SENSITIVITY_RANK["high"]

    if on_attack_path and high_or_critical:
        level = "high"
    elif on_attack_path or min_distance is not None:
        level = "medium"
    else:
        level = "low"

    return {
        "node_id": node_id,
        "on_attack_path": on_attack_path,
        "paths_count": paths_count,
        "min_distance_to_sensitive": min_distance,
        "max_sensitivity_reachable": max_sens,
        "level": level,
        "reason": None,
    }


def derive_entry_points(
    action_type_registry: dict[str, Any],
    model: dict[str, Any],
) -> tuple[dict[str, Any], bool, list[dict[str, str]]]:
    """
    Derive entry points from action types that ingest untrusted content (BP-11, X-03).
    Returns (updated_model, changed_bool, warnings). Never creates missing nodes.
    """
    import copy
    updated = copy.deepcopy(model)
    warnings: list[dict[str, str]] = []
    changed = False

    node_map = {n["id"]: n for n in updated.get("nodes", [])}

    # Action types that ingest untrusted content
    untrusted_tool_nodes: set[str] = set()
    for at_name, at_def in action_type_registry.items():
        if at_def.get("ingests_untrusted"):
            tn = at_def.get("tool_node")
            if tn:
                untrusted_tool_nodes.add(tn)
                if tn not in node_map:
                    warnings.append({
                        "code": "W_TOOL_NODE_MISSING",
                        "message": f"Action type '{at_name}' references tool node '{tn}', which does not exist in the graph.",
                    })

    # Update nodes
    for n in updated.get("nodes", []):
        nid = n["id"]
        if nid in untrusted_tool_nodes:
            if (not n.get("entry_point") or n.get("entry_source") != "derived") and n.get("entry_source") != "manual":
                n["entry_point"] = True
                n["entry_source"] = "derived"
                attrs = n.setdefault("attrs", {})
                if attrs.get("badge") != "derived":
                    attrs["badge"] = "derived"
                changed = True
        else:
            # If was derived but no longer in untrusted_tool_nodes, clear it
            if n.get("entry_source") == "derived":
                n["entry_point"] = False
                n["entry_source"] = None
                attrs = n.get("attrs", {})
                if "badge" in attrs and attrs["badge"] == "derived":
                    del attrs["badge"]
                changed = True

    return updated, changed, warnings
