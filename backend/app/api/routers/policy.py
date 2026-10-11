"""
Policy router (/api/v1/policy/*) — PE-04..PE-06, X-07, api.md §2.5.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, cast

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import BaseModel

from backend.app.actiongate.approvals import create_approval
from backend.app.core import ledger
from backend.app.core.auth import HumanIdentity, require_human, require_role
from backend.app.core.canonical import canonical_json
from backend.app.core.errors import SentinelError
from backend.app.core.ids import next_id
from backend.app.core.policy import get_engine, lint_policy
from backend.app.db import fetchall, fetchone, get_connection

router = APIRouter(prefix="/policy", tags=["policy"])


def json_diff(doc_a: Any, doc_b: Any, path: str = "") -> list[dict[str, Any]]:
    """Compute RFC 6902-style JSON diff ops between two data structures."""
    ops: list[dict[str, Any]] = []
    if type(doc_a) is not type(doc_b):
        ops.append({"op": "replace", "path": path or "/", "value": doc_b})
        return ops

    if isinstance(doc_a, dict):
        all_keys = set(doc_a.keys()) | set(doc_b.keys())
        for k in sorted(all_keys):
            if k.startswith("_"):
                continue
            subpath = f"{path}/{k}"
            if k not in doc_a:
                ops.append({"op": "add", "path": subpath, "value": doc_b[k]})
            elif k not in doc_b:
                ops.append({"op": "remove", "path": subpath})
            else:
                ops.extend(json_diff(doc_a[k], doc_b[k], subpath))
    elif isinstance(doc_a, list):
        min_len = min(len(doc_a), len(doc_b))
        for i in range(min_len):
            ops.extend(json_diff(doc_a[i], doc_b[i], f"{path}/{i}"))
        if len(doc_b) > len(doc_a):
            for i in range(min_len, len(doc_b)):
                ops.append({"op": "add", "path": f"{path}/{i}", "value": doc_b[i]})
        elif len(doc_a) > len(doc_b):
            for i in reversed(range(min_len, len(doc_a))):
                ops.append({"op": "remove", "path": f"{path}/{i}"})
    else:
        if doc_a != doc_b:
            ops.append({"op": "replace", "path": path or "/", "value": doc_b})
    return ops


class PolicyProposalRequest(BaseModel):
    base_version: int
    policy: dict[str, Any]
    note: str = ""


@router.get("")
def get_active_policy(human: HumanIdentity = Depends(require_human)) -> dict[str, Any]:
    """Retrieve currently active policy document and version (api.md §2.5)."""
    engine = get_engine()
    doc = engine.load_active_policy()
    ver = engine.active_version()
    res = dict(doc)
    res["version"] = ver
    res["policy"] = doc
    return res


@router.get("/versions")
def list_policy_versions(human: HumanIdentity = Depends(require_human)) -> list[dict[str, Any]]:
    """List all policy versions in chronological order."""
    conn = get_connection()
    rows = fetchall(
        conn,
        "SELECT version, created_by, approved_by, activated_at, content_hash "
        "FROM policy_versions ORDER BY version ASC",
    )
    return [
        {
            "version": r["version"],
            "created_by": r["created_by"],
            "approved_by": r["approved_by"],
            "activated_at": r["activated_at"],
            "content_hash": r["content_hash"],
        }
        for r in rows
    ]


@router.get("/versions/{v}")
def get_policy_version(v: int, human: HumanIdentity = Depends(require_human)) -> dict[str, Any]:
    """Retrieve a specific policy version document."""
    conn = get_connection()
    row = fetchone(conn, "SELECT version, content_json FROM policy_versions WHERE version = ?", (v,))
    if not row:
        raise SentinelError(404, "policy.version_not_found", f"Policy version {v} not found.")
    doc = cast(dict[str, Any], json.loads(row["content_json"]))
    doc["version"] = row["version"]
    return doc


@router.get("/diff")
def diff_policy_versions(
    from_ver: int = Query(..., alias="from"),
    to_ver: int = Query(..., alias="to"),
    human: HumanIdentity = Depends(require_human),
) -> list[dict[str, Any]]:
    """Compute RFC 6902-style diff between two policy versions."""
    conn = get_connection()
    row_from = fetchone(conn, "SELECT content_json FROM policy_versions WHERE version = ?", (from_ver,))
    if not row_from:
        raise SentinelError(404, "policy.version_not_found", f"Policy version {from_ver} not found.")
    row_to = fetchone(conn, "SELECT content_json FROM policy_versions WHERE version = ?", (to_ver,))
    if not row_to:
        raise SentinelError(404, "policy.version_not_found", f"Policy version {to_ver} not found.")

    doc_from = json.loads(row_from["content_json"])
    doc_to = json.loads(row_to["content_json"])
    return json_diff(doc_from, doc_to)


@router.post("/proposals", status_code=status.HTTP_202_ACCEPTED)
def propose_policy_change(
    req: PolicyProposalRequest,
    response: Response,
    human: HumanIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Propose a policy modification requiring second-admin approval (PE-06, X-07)."""
    engine = get_engine()
    cur_ver = engine.active_version()

    if req.base_version != cur_ver:
        raise SentinelError(
            409,
            "policy.stale_base",
            f"Base version {req.base_version} does not match active version {cur_ver}.",
        )

    errors = lint_policy(req.policy)
    if errors:
        raise SentinelError(
            422,
            "policy.lint_failed",
            f"Policy failed lint: {len(errors)} error(s).",
            details={"errors": errors},
        )

    base_doc = engine.load_active_policy()
    diff_ops = json_diff(base_doc, req.policy)

    clean_doc = {k: v for k, v in req.policy.items() if not k.startswith("_")}
    fp = hashlib.sha256(canonical_json(clean_doc).encode("utf-8")).hexdigest()

    conn = get_connection()
    proposal_id = next_id("prop_")
    while fetchone(conn, "SELECT 1 FROM policy_proposals WHERE proposal_id = ?", (proposal_id,)):
        proposal_id = next_id("prop_")

    ap = create_approval(
        kind="policy.update",
        fingerprint=fp,
        requester=human.user_id,
        action_id=proposal_id,
    )
    approval_id = ap["approval_id"]

    from backend.app.core.clock import get_clock
    now_iso = get_clock().now_iso()

    conn.execute(
        """
        INSERT INTO policy_proposals
        (proposal_id, base_version, content_json, diff_json, fingerprint, note, proposed_by, approval_id, created_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        """,
        (
            proposal_id,
            req.base_version,
            json.dumps(clean_doc),
            json.dumps(diff_ops),
            fp,
            req.note,
            human.user_id,
            approval_id,
            now_iso,
        ),
    )
    conn.commit()

    ledger.append(
        module="policy",
        event_type="policy.proposed",
        subject=f"proposal:{proposal_id}",
        outcome="hold",
        reason=req.note or "Policy change proposed",
        rule_ids=["PC-R-001"],
        decision_path="rules",
        policy_version=req.base_version,
        payload={
            "proposal_id": proposal_id,
            "approval_id": approval_id,
            "base_version": req.base_version,
            "fingerprint": fp,
            "diff_size": len(diff_ops),
            "proposed_by": human.user_id,
        },
    )

    response.status_code = status.HTTP_202_ACCEPTED
    return {
        "proposal_id": proposal_id,
        "approval_id": approval_id,
        "outcome": "hold",
        "rule_ids": ["PC-R-001"],
        "fingerprint": fp,
        "diff": diff_ops,
    }
