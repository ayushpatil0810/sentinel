"""
BreachPath graph model validation (BP-01, BP-02, BP-15, spec.md §3.2).

Returns all validation errors and warnings. Never auto-creates missing elements.
"""

from __future__ import annotations

import re
from typing import Any

ID_REGEX = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")

VALID_NODE_TYPES = {"user", "role", "service", "agent", "tool", "asset", "external"}
VALID_EDGE_TYPES = {
    "member_of", "can_assume", "can_invoke", "can_read", "can_write",
    "trusts", "network_reachable", "ingests_from", "calls",
}
VALID_SENSITIVITIES = {"none", "low", "medium", "high", "critical"}


class ValidationErrorItem:
    def __init__(self, code: str, pointer: str, message: str) -> None:
        self.code = code
        self.pointer = pointer
        self.message = message

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "pointer": self.pointer, "message": self.message}


class ValidationResult:
    def __init__(self, valid: bool, errors: list[dict[str, str]], warnings: list[dict[str, str]]) -> None:
        self.valid = valid
        self.errors = errors
        self.warnings = warnings

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def validate_graph_dict(data: Any) -> ValidationResult:
    """
    Validate graph JSON dict against schema, limits, referential constraints.
    Returns ValidationResult with all errors and warnings.
    """
    errors: list[ValidationErrorItem] = []
    warnings: list[ValidationErrorItem] = []

    if not isinstance(data, dict):
        return ValidationResult(False, [ValidationErrorItem("E_TYPE", "", "Root must be an object").to_dict()], [])

    # Schema limit checks (BP-15)
    nodes = data.get("nodes")
    edges = data.get("edges")
    settings = data.get("settings", {})

    if nodes is None:
        errors.append(ValidationErrorItem("E_MISSING_FIELD", "/nodes", "Required field 'nodes' is missing."))
    elif not isinstance(nodes, list):
        errors.append(ValidationErrorItem("E_TYPE", "/nodes", "'nodes' must be a list."))
    elif len(nodes) > 500:
        errors.append(ValidationErrorItem("E_LIMIT", "/nodes", f"Node count {len(nodes)} exceeds maximum of 500."))

    if edges is None:
        errors.append(ValidationErrorItem("E_MISSING_FIELD", "/edges", "Required field 'edges' is missing."))
    elif not isinstance(edges, list):
        errors.append(ValidationErrorItem("E_TYPE", "/edges", "'edges' must be a list."))
    elif len(edges) > 2000:
        errors.append(ValidationErrorItem("E_LIMIT", "/edges", f"Edge count {len(edges)} exceeds maximum of 2000."))

    # Settings validation
    if isinstance(settings, dict):
        max_depth = settings.get("max_depth")
        if max_depth is not None and (not isinstance(max_depth, int) or not (1 <= max_depth <= 8)):
            errors.append(ValidationErrorItem("E_BAD_SETTINGS", "/settings/max_depth", "max_depth must be integer 1..8."))

        max_paths = settings.get("max_paths")
        if max_paths is not None and (not isinstance(max_paths, int) or not (1 <= max_paths <= 10000)):
            errors.append(ValidationErrorItem("E_BAD_SETTINGS", "/settings/max_paths", "max_paths must be integer 1..10000."))

        time_budget = settings.get("time_budget_ms")
        if time_budget is not None and (not isinstance(time_budget, int) or not (100 <= time_budget <= 10000)):
            errors.append(ValidationErrorItem("E_BAD_SETTINGS", "/settings/time_budget_ms", "time_budget_ms must be integer 100..10000."))

    node_ids: set[str] = set()
    has_entry = False
    has_target = False

    # Validate Nodes
    if isinstance(nodes, list):
        for i, n in enumerate(nodes):
            ptr = f"/nodes/{i}"
            if not isinstance(n, dict):
                errors.append(ValidationErrorItem("E_TYPE", ptr, "Node must be an object."))
                continue

            # ID
            nid = n.get("id")
            if nid is None:
                errors.append(ValidationErrorItem("E_MISSING_FIELD", f"{ptr}/id", "Node missing required field 'id'."))
            elif not isinstance(nid, str) or not ID_REGEX.match(nid):
                errors.append(ValidationErrorItem("E_BAD_ID", f"{ptr}/id", f"Invalid node ID '{nid}'."))
            elif nid in node_ids:
                errors.append(ValidationErrorItem("E_DUP_NODE_ID", f"{ptr}/id", f"Duplicate node ID '{nid}'."))
            else:
                node_ids.add(nid)

            # Type
            ntype = n.get("type")
            if ntype is None:
                errors.append(ValidationErrorItem("E_MISSING_FIELD", f"{ptr}/type", f"Node '{nid or i}' has no 'type'."))
            elif ntype not in VALID_NODE_TYPES:
                errors.append(ValidationErrorItem("E_UNKNOWN_NODE_TYPE", f"{ptr}/type", f"Unknown node type '{ntype}'."))

            # Name
            name = n.get("name")
            if name is None:
                errors.append(ValidationErrorItem("E_MISSING_FIELD", f"{ptr}/name", f"Node '{nid or i}' has no 'name'."))
            elif not isinstance(name, str) or len(name) > 200:
                errors.append(ValidationErrorItem("E_LIMIT", f"{ptr}/name", "Node name exceeds 200 characters."))

            # Entry point
            if n.get("entry_point"):
                has_entry = True

            # Sensitivity
            sens = n.get("sensitivity", "none")
            if sens not in VALID_SENSITIVITIES:
                errors.append(ValidationErrorItem("E_BAD_SENSITIVITY", f"{ptr}/sensitivity", f"'{sens}' is not one of none, low, medium, high, critical."))
            elif sens in ("medium", "high", "critical"):
                has_target = True

            # Attrs
            attrs = n.get("attrs")
            if attrs is not None and (not isinstance(attrs, dict) or len(attrs) > 20):
                errors.append(ValidationErrorItem("E_LIMIT", f"{ptr}/attrs", "Node attrs exceeds 20 keys."))

    edge_ids: set[str] = set()

    # Validate Edges
    if isinstance(edges, list):
        for i, e in enumerate(edges):
            ptr = f"/edges/{i}"
            if not isinstance(e, dict):
                errors.append(ValidationErrorItem("E_TYPE", ptr, "Edge must be an object."))
                continue

            # ID
            eid = e.get("id")
            if eid is None:
                errors.append(ValidationErrorItem("E_MISSING_FIELD", f"{ptr}/id", "Edge missing required field 'id'."))
            elif not isinstance(eid, str) or not ID_REGEX.match(eid):
                errors.append(ValidationErrorItem("E_BAD_ID", f"{ptr}/id", f"Invalid edge ID '{eid}'."))
            elif eid in edge_ids:
                errors.append(ValidationErrorItem("E_DUP_EDGE_ID", f"{ptr}/id", f"Duplicate edge ID '{eid}'."))
            else:
                edge_ids.add(eid)

            # Type
            etype = e.get("type")
            if etype is None:
                errors.append(ValidationErrorItem("E_MISSING_FIELD", f"{ptr}/type", f"Edge '{eid or i}' has no 'type'."))
            elif etype not in VALID_EDGE_TYPES:
                errors.append(ValidationErrorItem("E_UNKNOWN_EDGE_TYPE", f"{ptr}/type", f"Unknown edge type '{etype}'."))

            # Source
            src = e.get("src")
            if src is None:
                errors.append(ValidationErrorItem("E_MISSING_FIELD", f"{ptr}/src", "Edge missing required field 'src'."))
            elif src not in node_ids:
                errors.append(ValidationErrorItem("E_DANGLING_SRC", f"{ptr}/src", f"Edge {eid} refers to source \"{src}\", which is not defined in nodes. Sentinel does not create missing nodes."))

            # Destination
            dst = e.get("dst")
            if dst is None:
                errors.append(ValidationErrorItem("E_MISSING_FIELD", f"{ptr}/dst", "Edge missing required field 'dst'."))
            elif dst not in node_ids:
                errors.append(ValidationErrorItem("E_DANGLING_DST", f"{ptr}/dst", f"Edge {eid} refers to destination \"{dst}\", which is not defined in nodes. Sentinel does not create missing nodes."))

            # Self loop warning
            if src and dst and src == dst:
                warnings.append(ValidationErrorItem("W_SELF_LOOP", ptr, f"Self-loop edge on node '{src}'."))

    # Warnings
    if not has_entry:
        warnings.append(ValidationErrorItem("W_NO_ENTRY", "", "No entry points defined in the graph."))
    if not has_target:
        warnings.append(ValidationErrorItem("W_NO_TARGET", "", "No sensitive target assets defined in the graph."))

    return ValidationResult(
        valid=len(errors) == 0,
        errors=[e.to_dict() for e in errors],
        warnings=[w.to_dict() for w in warnings],
    )
