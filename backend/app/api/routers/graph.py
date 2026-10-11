"""
BreachPath API Router (/api/v1/graph/*) — spec §3, api.md §2.6.

Human plane only (agent credentials return 403 auth.wrong_plane via auth dependencies).
Prefix: /graph (mounted under /api/v1 in main.py).
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from backend.app.actiongate.registries import get_action_type_registry
from backend.app.breachpath.blast import compute_blast_radius, derive_entry_points
from backend.app.breachpath.changes import GraphChangeError, apply_graph_changes
from backend.app.breachpath.diff import compute_route_diff
from backend.app.breachpath.remediation import generate_remediations, preview_remediation
from backend.app.breachpath.search import find_routes
from backend.app.breachpath.store import (
    get_current_graph,
    list_graph_versions,
    save_graph_version,
)
from backend.app.breachpath.validation import validate_graph_dict
from backend.app.core import ledger
from backend.app.core.auth import HumanIdentity, require_human, require_role
from backend.app.core.errors import SentinelError

router = APIRouter(prefix="/graph", tags=["breachpath"])


def _ledger_event(event_type: str, subject: str, outcome: str, reason: str, payload: dict[str, Any] | None = None) -> None:
    ledger.append(
        module="breachpath",
        event_type=event_type,
        subject=subject,
        outcome=outcome,
        reason=reason,
        rule_ids=[],
        decision_path="rules",
        policy_version=1,
        payload=payload or {},
    )


@router.get("")
def get_graph(human: HumanIdentity = Depends(require_human)) -> dict[str, Any]:
    """Get active access graph model with version and warnings (api.md §2.6)."""
    version, model = get_current_graph()
    val_res = validate_graph_dict(model)
    return {
        "graph_version": version,
        "name": model.get("name", ""),
        "settings": model.get("settings", {}),
        "nodes": model.get("nodes", []),
        "edges": model.get("edges", []),
        "warnings": val_res.warnings,
    }


@router.get("/versions")
def get_versions(human: HumanIdentity = Depends(require_human)) -> list[dict[str, Any]]:
    """List historical graph versions (api.md §2.6)."""
    return list_graph_versions()


@router.post("/validate")
async def validate_graph_upload(
    request: Request,
    human: HumanIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Dry run validation of uploaded graph model without state change (api.md §2.6)."""
    body_bytes = await request.body()
    if len(body_bytes) > 1024 * 1024:
        raise SentinelError(413, "graph.too_large", "Uploaded model exceeds maximum size of 1 MiB.")

    try:
        data = json.loads(body_bytes.decode("utf-8"))
    except Exception as exc:
        raise SentinelError(422, "E_UNREADABLE", f"Graph file is unreadable: {exc}") from exc

    val_res = validate_graph_dict(data)
    if not val_res.valid:
        return {"valid": False, "errors": val_res.errors, "warnings": val_res.warnings}
    return {"valid": True, "errors": [], "warnings": val_res.warnings}


@router.put("")
async def upload_graph(
    request: Request,
    format: str = Query("json"),
    human: HumanIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Upload new graph model (admin only, api.md §2.6)."""
    actor = f"user:{human.user_id}"
    body_bytes = await request.body()

    if len(body_bytes) > 1024 * 1024:
        raise SentinelError(413, "graph.too_large", "Uploaded model exceeds maximum size of 1 MiB.")

    try:
        data = json.loads(body_bytes.decode("utf-8"))
    except Exception as exc:
        _ledger_event(
            event_type="graph.upload_rejected",
            subject=actor,
            outcome="block",
            reason="unreadable_json",
            payload={"error": str(exc)},
        )
        raise SentinelError(422, "E_UNREADABLE", f"Graph file is unreadable: {exc}") from exc

    val_res = validate_graph_dict(data)
    if not val_res.valid:
        _ledger_event(
            event_type="graph.upload_rejected",
            subject=actor,
            outcome="block",
            reason="validation_failed",
            payload={"errors": val_res.errors},
        )
        raise SentinelError(
            422,
            "graph.invalid",
            f"The model was rejected: {len(val_res.errors)} errors. Nothing was changed.",
            details={"errors": val_res.errors},
        )

    cur_version, _ = get_current_graph()
    next_ver = save_graph_version(
        model=data,
        parent_version=cur_version,
        change_summary="upload",
        created_by=human.user_id,
    )

    _ledger_event(
        event_type="graph.changed",
        subject=actor,
        outcome="allow",
        reason="graph_uploaded",
        payload={
            "from_version": cur_version,
            "to_version": next_ver,
            "changes": "upload",
        },
    )

    return {"graph_version": next_ver, "warnings": val_res.warnings}


@router.post("/changes")
def post_changes(
    payload: dict[str, Any],
    human: HumanIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Apply atomic list of graph changes (admin only, api.md §2.6, BP-17)."""
    expected_version = payload.get("expected_version")
    changes = payload.get("changes")

    if not isinstance(changes, list):
        raise SentinelError(422, "graph.invalid", "Field 'changes' must be a list.")

    cur_version, model = get_current_graph()
    if expected_version is not None and expected_version != cur_version:
        raise SentinelError(
            409,
            "graph.stale_version",
            f"Expected graph version {expected_version} does not match active version {cur_version}.",
        )

    old_routes = find_routes(model).routes

    try:
        new_model, errors = apply_graph_changes(model, changes)
    except GraphChangeError as exc:
        raise SentinelError(
            422,
            "graph.invalid",
            f"Graph change rejected: {exc.message}",
            details={"errors": [exc.to_dict()]},
        ) from exc

    if errors:
        raise SentinelError(
            422,
            "graph.invalid",
            f"Graph changes resulted in invalid graph: {len(errors)} errors.",
            details={"errors": errors},
        )

    new_search = find_routes(new_model)
    new_routes = new_search.routes

    diff = compute_route_diff(
        routes_before=old_routes,
        routes_after=new_routes,
        from_version=cur_version,
        to_version=cur_version + 1,
        comparison_reliable=not new_search.truncated,
    )

    next_ver = save_graph_version(
        model=new_model,
        parent_version=cur_version,
        change_summary=changes,
        created_by=human.user_id,
    )

    _ledger_event(
        event_type="graph.changed",
        subject=f"user:{human.user_id}",
        outcome="allow",
        reason="changes_applied",
        payload={
            "from_version": cur_version,
            "to_version": next_ver,
            "changes": changes,
            "diff": {
                "removed": diff["removed"],
                "remaining": diff["remaining"],
                "new": diff["new"],
            },
        },
    )

    return {
        "graph_version": next_ver,
        "diff": diff,
        "routes_summary": {"count": len(new_routes)},
    }


@router.get("/routes")
def get_routes(
    max_depth: int | None = Query(None),
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Find all simple attack routes within max_depth (api.md §2.6, BP-03..BP-05)."""
    if max_depth is not None and (max_depth < 1 or max_depth > 8):
        raise SentinelError(422, "E_BAD_SETTINGS", "max_depth must be an integer between 1 and 8.")

    version, model = get_current_graph()
    depth = max_depth if max_depth is not None else model.get("settings", {}).get("max_depth", 4)
    res = find_routes(model, max_depth=depth)
    return res.to_dict(graph_version=version, max_depth=depth)


@router.get("/routes/{path_id}")
def get_route_by_id(
    path_id: str,
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Get single attack route with full plain-language explanation (api.md §2.6)."""
    _, model = get_current_graph()
    res = find_routes(model)
    for r in res.routes:
        if r["path_id"] == path_id:
            return r
    raise SentinelError(404, "route.not_found", f"Route '{path_id}' not found in active graph.")


@router.get("/remediations")
def get_remediations(
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Get remediation candidates ranked by broken routes and greedy set cover plan (api.md §2.6, BP-07)."""
    version, model = get_current_graph()
    routes = find_routes(model).routes
    return generate_remediations(model, routes, graph_version=version)


@router.post("/remediations/{edge_id}/preview")
def preview_edge_remediation(
    edge_id: str,
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Dry run preview of removing an edge (any human, api.md §2.6, BP-08)."""
    version, model = get_current_graph()
    routes = find_routes(model).routes
    try:
        return preview_remediation(model, edge_id, routes, graph_version=version)
    except KeyError:
        raise SentinelError(404, "edge.not_found", f"Edge '{edge_id}' not found in active graph.") from None


@router.post("/remediations/{edge_id}/apply")
def apply_edge_remediation(
    edge_id: str,
    payload: dict[str, Any],
    human: HumanIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Apply edge removal remediation (admin only, api.md §2.6, BP-08)."""
    expected_version = payload.get("expected_version")
    cur_version, model = get_current_graph()

    if expected_version is not None and expected_version != cur_version:
        raise SentinelError(
            409,
            "graph.stale_version",
            f"Expected graph version {expected_version} does not match active version {cur_version}.",
        )

    # Check edge exists
    edge_exists = any(e.get("id") == edge_id for e in model.get("edges", []))
    if not edge_exists:
        raise SentinelError(404, "edge.not_found", f"Edge '{edge_id}' not found in active graph.")

    routes_before = find_routes(model).routes
    # Check if edge is on at least one route
    edge_on_route = any(
        any(s.get("edge_id") == edge_id for s in r.get("steps", []))
        for r in routes_before
    )
    if not edge_on_route:
        raise SentinelError(
            409,
            "graph.edge_not_on_route",
            f"Edge '{edge_id}' is not part of any attack route.",
        )

    # Apply change
    new_model, errors = apply_graph_changes(
        model,
        [{"op": "remove_edge", "edge_id": edge_id}],
    )
    if errors:
        raise SentinelError(422, "graph.invalid", "Failed to remove edge.", details={"errors": errors})

    routes_after = find_routes(new_model).routes
    diff = compute_route_diff(
        routes_before=routes_before,
        routes_after=routes_after,
        from_version=cur_version,
        to_version=cur_version + 1,
    )

    next_ver = save_graph_version(
        model=new_model,
        parent_version=cur_version,
        change_summary=[{"op": "remove_edge", "edge_id": edge_id}],
        created_by=human.user_id,
    )

    actor = f"user:{human.user_id}"
    _ledger_event(
        event_type="graph.remediation_applied",
        subject=actor,
        outcome="allow",
        reason="remediation_applied",
        payload={
            "edge_id": edge_id,
            "from_version": cur_version,
            "to_version": next_ver,
            "diff": {
                "removed": diff["removed"],
                "remaining": diff["remaining"],
                "new": diff["new"],
            },
        },
    )

    return {
        "graph_version": next_ver,
        "diff": diff,
    }


@router.get("/blast/{node_id}")
def get_node_blast(
    node_id: str,
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Get blast radius metrics for a node (api.md §2.6, BP-12)."""
    _, model = get_current_graph()
    return compute_blast_radius(model, node_id)


@router.post("/derive-entry-points")
def post_derive_entry_points(
    human: HumanIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Derive entry points from action type registry (admin only, api.md §2.6, BP-11, X-03)."""
    cur_version, model = get_current_graph()
    act_reg = get_action_type_registry()
    updated_model, changed, warnings = derive_entry_points(act_reg, model)

    if changed:
        next_ver = save_graph_version(
            model=updated_model,
            parent_version=cur_version,
            change_summary=[{"op": "derive_entry_points"}],
            created_by=human.user_id,
        )
        _ledger_event(
            event_type="graph.derived_entry_points",
            subject=f"user:{human.user_id}",
            outcome="allow",
            reason="derived_entry_points_updated",
            payload={"graph_version": next_ver, "warnings": warnings},
        )
        return {
            "changed": True,
            "graph_version": next_ver,
            "warnings": warnings,
        }

    return {
        "changed": False,
        "graph_version": cur_version,
        "warnings": warnings,
    }
