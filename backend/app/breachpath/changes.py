"""
BreachPath graph change operations (BP-14, BP-17, spec §3.1, §3.2).

Supported ops:
- add_node
- remove_node (rejected if edges reference it: E_NODE_IN_USE)
- update_node
- add_edge
- remove_edge
- update_edge
- set_entry_point
- set_sensitivity
- set_settings
"""

from __future__ import annotations

import copy
from typing import Any

from backend.app.breachpath.validation import (
    ID_REGEX,
    VALID_SENSITIVITIES,
    validate_graph_dict,
)


class GraphChangeError(Exception):
    def __init__(self, code: str, pointer: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.pointer = pointer
        self.message = message

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "pointer": self.pointer, "message": self.message}


def apply_graph_changes(
    model: dict[str, Any],
    changes: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """
    Apply a sequence of graph change operations atomically (BP-17).
    Returns (new_model, errors). If errors is non-empty, changes were not applied.
    """
    updated = copy.deepcopy(model)
    nodes: list[dict[str, Any]] = updated.setdefault("nodes", [])
    edges: list[dict[str, Any]] = updated.setdefault("edges", [])
    settings: dict[str, Any] = updated.setdefault("settings", {})

    node_map = {n["id"]: n for n in nodes}
    edge_map = {e["id"]: e for e in edges}

    for i, chg in enumerate(changes):
        ptr = f"/changes/{i}"
        op = chg.get("op")

        if op == "add_node":
            node = chg.get("node")
            if not isinstance(node, dict):
                raise GraphChangeError("E_TYPE", f"{ptr}/node", "Node must be an object.")
            nid = node.get("id")
            if not nid or not ID_REGEX.match(nid):
                raise GraphChangeError("E_BAD_ID", f"{ptr}/node/id", f"Invalid node ID '{nid}'.")
            if nid in node_map:
                raise GraphChangeError("E_DUP_NODE_ID", f"{ptr}/node/id", f"Duplicate node ID '{nid}'.")
            node_map[nid] = node
            nodes.append(node)

        elif op == "remove_node":
            nid = chg.get("node_id")
            if not nid or nid not in node_map:
                raise GraphChangeError("E_BAD_ID", f"{ptr}/node_id", f"Node '{nid}' not found.")
            # BP-17: rejected if edges reference it, E_NODE_IN_USE
            referencing = [e["id"] for e in edges if e.get("src") == nid or e.get("dst") == nid]
            if referencing:
                raise GraphChangeError(
                    "E_NODE_IN_USE",
                    ptr,
                    f"Cannot remove node '{nid}' because edges {referencing} reference it. Remove referencing edges first.",
                )
            nodes[:] = [n for n in nodes if n["id"] != nid]
            del node_map[nid]

        elif op == "update_node":
            node = chg.get("node")
            nid = chg.get("node_id") or (node.get("id") if isinstance(node, dict) else None)
            if not nid or nid not in node_map:
                raise GraphChangeError("E_BAD_ID", f"{ptr}/node_id", f"Node '{nid}' not found.")
            if isinstance(node, dict):
                node_map[nid].update(node)

        elif op == "add_edge":
            edge = chg.get("edge")
            if not isinstance(edge, dict):
                raise GraphChangeError("E_TYPE", f"{ptr}/edge", "Edge must be an object.")
            eid = edge.get("id")
            if not eid or not ID_REGEX.match(eid):
                raise GraphChangeError("E_BAD_ID", f"{ptr}/edge/id", f"Invalid edge ID '{eid}'.")
            if eid in edge_map:
                raise GraphChangeError("E_DUP_EDGE_ID", f"{ptr}/edge/id", f"Duplicate edge ID '{eid}'.")
            src = edge.get("src")
            dst = edge.get("dst")
            if not src or src not in node_map:
                raise GraphChangeError("E_DANGLING_SRC", f"{ptr}/edge/src", f"Source '{src}' does not exist.")
            if not dst or dst not in node_map:
                raise GraphChangeError("E_DANGLING_DST", f"{ptr}/edge/dst", f"Destination '{dst}' does not exist.")
            edge_map[eid] = edge
            edges.append(edge)

        elif op == "remove_edge":
            eid = chg.get("edge_id")
            if not eid or eid not in edge_map:
                raise GraphChangeError("E_BAD_ID", f"{ptr}/edge_id", f"Edge '{eid}' not found.")
            edges[:] = [e for e in edges if e["id"] != eid]
            del edge_map[eid]

        elif op == "update_edge":
            edge = chg.get("edge")
            eid = chg.get("edge_id") or (edge.get("id") if isinstance(edge, dict) else None)
            if not eid or eid not in edge_map:
                raise GraphChangeError("E_BAD_ID", f"{ptr}/edge_id", f"Edge '{eid}' not found.")
            if isinstance(edge, dict):
                edge_map[eid].update(edge)

        elif op == "set_entry_point":
            nid = chg.get("node_id")
            val = chg.get("value")
            if not nid or nid not in node_map:
                raise GraphChangeError("E_BAD_ID", f"{ptr}/node_id", f"Node '{nid}' not found.")
            node_map[nid]["entry_point"] = bool(val)
            node_map[nid]["entry_source"] = "manual" if val else None

        elif op == "set_sensitivity":
            nid = chg.get("node_id")
            val = chg.get("value")
            if not nid or nid not in node_map:
                raise GraphChangeError("E_BAD_ID", f"{ptr}/node_id", f"Node '{nid}' not found.")
            if val not in VALID_SENSITIVITIES:
                raise GraphChangeError("E_BAD_SENSITIVITY", f"{ptr}/value", f"Invalid sensitivity '{val}'.")
            node_map[nid]["sensitivity"] = val

        elif op == "set_settings":
            new_settings = chg.get("settings")
            if isinstance(new_settings, dict):
                settings.update(new_settings)

        else:
            raise GraphChangeError("E_UNKNOWN_OP", ptr, f"Unknown operation '{op}'.")

    # Run full graph validation on updated model to verify consistency
    val_res = validate_graph_dict(updated)
    if not val_res.valid:
        return model, val_res.errors

    return updated, []
