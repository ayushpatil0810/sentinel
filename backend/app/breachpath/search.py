"""
BreachPath route search and path enumeration (BP-03..BP-06, BP-10, BP-18).

- Cycle safety via visited sets (simple paths only, BP-03).
- Configurable max_depth (1..8, default 4, BP-04).
- Deterministic traversal order (edges sorted by ID, BP-05).
- Plain-language explanation templates (BP-06).
- Stable path IDs: p_<sha256[:12]> (BP-05).
- Truncation caps for max_paths and time_budget_ms (BP-10).
- Edge reversal for ingests_from and trusts (BP-18).
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

SENSITIVITY_RANK = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

REVERSE_EDGE_TYPES = {"ingests_from", "trusts"}

EXPLANATION_TEMPLATES = {
    "member_of": "{from} is a member of {to}, so it inherits what {to} can do.",
    "can_assume": "{from} can assume {to} and act with its permissions.",
    "can_invoke": "{from} can invoke {to}.",
    "can_read": "{from} can read {to}.",
    "can_write": "{from} can write to {to}.",
    "network_reachable": "{from} can reach {to} over the network.",
    "calls": "{from} calls {to}.",
    "ingests_from": "Content controlled at {from} is ingested by {to}, so whoever controls it can steer {to}.",
    "trusts": "{to} trusts {from}, so a compromise of {from} can be used to act toward {to}.",
}

VERB_PHRASES = {
    "can_invoke": "can invoke {to}",
    "can_read": "can read {to}",
    "can_write": "can write to {to}",
    "calls": "calls {to}",
    "can_assume": "can assume {to}",
    "network_reachable": "can reach {to} over the network",
    "member_of": "is a member of {to}",
    "trusts": "trusts {to}",
    "ingests_from": "ingests from {to}",
}


def compute_path_id(edge_ids: list[str]) -> str:
    """Compute stable path ID p_<sha256[:12]> from ordered edge IDs (data-models.md §4)."""
    joined = "|".join(edge_ids)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:12]
    return f"p_{digest}"


def build_step_text(edge_type: str, from_name: str, to_name: str, reversed_edge: bool) -> str:
    """Generate plain-language explanation for a single step (spec §3.6)."""
    template = EXPLANATION_TEMPLATES.get(edge_type, "{from} reaches {to}.")
    return template.format(**{"from": from_name, "to": to_name})


def build_short_text(steps: list[dict[str, Any]], node_map: dict[str, dict[str, Any]]) -> str:
    """
    Generate the 'short' field joining step clauses as 'X can invoke Y, which can read Z.'
    If step 0 is reversed ingestion, short starts at the ingested agent/service (spec §3.6).
    """
    if not steps:
        return ""

    first_step = steps[0]
    if first_step.get("reversed") and first_step.get("edge_type") == "ingests_from" and len(steps) > 1:
        # Attacker steers step[0].to, forward chain starts from step 1
        forward_steps = steps[1:]
    else:
        forward_steps = steps

    if not forward_steps:
        return str(steps[0].get("text", ""))

    # Subject is the 'from' node of the first forward step
    start_from = forward_steps[0]["from"]
    start_name = node_map.get(start_from, {}).get("name", start_from)

    clauses: list[str] = []
    for i, step in enumerate(forward_steps):
        etype = step["edge_type"]
        to_nid = step["to"]
        to_name = node_map.get(to_nid, {}).get("name", to_nid)
        phrase_template = VERB_PHRASES.get(etype, f"reaches {to_name}")
        phrase = phrase_template.format(to=to_name)

        if i == 0:
            clauses.append(f"{start_name} {phrase}")
        else:
            clauses.append(f", which {phrase}")

    return "".join(clauses) + "."


def build_adjacency(
    model: dict[str, Any],
    edge_traversal_policy: dict[str, bool] | None = None,
) -> dict[str, list[tuple[dict[str, Any], str, bool]]]:
    """
    Build deterministic adjacency list.
    Edges are sorted by edge ID ascending (spec §3.3).
    Returns mapping: node_id -> list of (edge_dict, next_node_id, reversed_bool).
    """
    adj: dict[str, list[tuple[dict[str, Any], str, bool]]] = {}
    nodes = model.get("nodes", [])
    for n in nodes:
        adj[n["id"]] = []

    # Sort edges by id ascending for determinism
    edges = sorted(model.get("edges", []), key=lambda e: e.get("id", ""))
    policy = edge_traversal_policy or {}

    for e in edges:
        eid = e.get("id")
        etype = e.get("type")
        src = e.get("src")
        dst = e.get("dst")

        if not eid or not etype or not src or not dst:
            continue
        if src == dst:
            # Self-loops ignored in search (spec §3.2)
            continue
        if not policy.get(etype, True):
            # Traversal disabled for this edge type
            continue

        if etype in REVERSE_EDGE_TYPES:
            # Reversal: traversal goes from dst to src
            if dst in adj:
                adj[dst].append((e, src, True))
        else:
            # Forward: traversal goes from src to dst
            if src in adj:
                adj[src].append((e, dst, False))

    return adj


class SearchResult:
    def __init__(
        self,
        routes: list[dict[str, Any]],
        truncated: bool,
        truncation_reason: str | None = None,
        warning: str | None = None,
    ) -> None:
        self.routes = routes
        self.truncated = truncated
        self.truncation_reason = truncation_reason
        self.warning = warning

    def to_dict(self, graph_version: int, max_depth: int) -> dict[str, Any]:
        return {
            "graph_version": graph_version,
            "max_depth": max_depth,
            "truncated": self.truncated,
            "truncation_reason": self.truncation_reason,
            "warning": self.warning,
            "routes": self.routes,
        }


def find_routes(
    model: dict[str, Any],
    max_depth: int | None = None,
    max_paths: int | None = None,
    time_budget_ms: int | None = None,
    edge_traversal_policy: dict[str, bool] | None = None,
) -> SearchResult:
    """
    Find all simple attack routes from entry points to sensitive targets (BP-03..BP-05, BP-10).
    """
    settings = model.get("settings", {})
    depth_limit = max_depth if max_depth is not None else settings.get("max_depth", 4)
    paths_limit = max_paths if max_paths is not None else settings.get("max_paths", 1000)
    budget_ms = time_budget_ms if time_budget_ms is not None else settings.get("time_budget_ms", 2000)
    sensitive_min = settings.get("sensitive_min", "medium")
    min_rank = SENSITIVITY_RANK.get(sensitive_min, 2)

    nodes = model.get("nodes", [])
    node_map = {n["id"]: n for n in nodes}

    targets = {
        n["id"]
        for n in nodes
        if SENSITIVITY_RANK.get(n.get("sensitivity", "none"), 0) >= min_rank
    }

    adj = build_adjacency(model, edge_traversal_policy=edge_traversal_policy)
    entries = sorted([n["id"] for n in nodes if n.get("entry_point")])

    routes: list[dict[str, Any]] = []
    start_time = time.monotonic()
    deadline = start_time + (budget_ms / 1000.0)

    for entry in entries:
        # DFS stack: (current_node, current_steps, visited_nodes)
        stack: list[tuple[str, list[dict[str, Any]], set[str]]] = [(entry, [], {entry})]
        while stack:
            cur, path, visited = stack.pop()
            if len(path) >= depth_limit:
                continue

            # reversed so ascending edge_id is popped first (spec §3.3)
            for edge, nxt, reversed_edge in reversed(adj.get(cur, [])):
                if nxt in visited:
                    continue  # Simple paths only (BP-03)

                cur_name = node_map.get(cur, {}).get("name", cur)
                nxt_name = node_map.get(nxt, {}).get("name", nxt)
                step_text = build_step_text(edge["type"], cur_name, nxt_name, reversed_edge)

                step = {
                    "from": cur,
                    "edge_id": edge["id"],
                    "edge_type": edge["type"],
                    "to": nxt,
                    "reversed": reversed_edge,
                    "text": step_text,
                }
                newpath = path + [step]

                if nxt in targets:
                    # Route ends at the first sensitive node
                    edge_ids = [s["edge_id"] for s in newpath]
                    pid = compute_path_id(edge_ids)
                    asset_node = node_map.get(nxt, {})
                    entry_node = node_map.get(entry, {})
                    asset_name = asset_node.get("name", nxt)
                    entry_name = entry_node.get("name", entry)
                    asset_sens = asset_node.get("sensitivity", "none")
                    route_len = len(newpath)

                    summary = f"From {entry_name} to {asset_name} ({asset_sens}) in {route_len} steps."
                    short = build_short_text(newpath, node_map)

                    # Build multi-line full explanation
                    explanation_lines = [summary]
                    for idx, s in enumerate(newpath, 1):
                        explanation_lines.append(f"{idx}. {s['text']}")
                    explanation_lines.append(f"Short: {short}")
                    explanation = "\n".join(explanation_lines)

                    route_obj = {
                        "path_id": pid,
                        "entry": entry,
                        "asset": nxt,
                        "asset_sensitivity": asset_sens,
                        "length": route_len,
                        "steps": newpath,
                        "summary": summary,
                        "short": short,
                        "explanation": explanation,
                    }
                    routes.append(route_obj)

                    if len(routes) >= paths_limit:
                        return SearchResult(
                            routes=routes,
                            truncated=True,
                            truncation_reason="max_paths",
                            warning=f"Path search truncated: reached maximum limit of {paths_limit} paths.",
                        )
                else:
                    stack.append((nxt, newpath, visited | {nxt}))

            if time.monotonic() > deadline:
                return SearchResult(
                    routes=routes,
                    truncated=True,
                    truncation_reason="time_budget",
                    warning=f"Path search truncated: exceeded time budget of {budget_ms} ms.",
                )

    return SearchResult(routes=routes, truncated=False)
