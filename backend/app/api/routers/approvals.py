"""
Human plane Approvals router (AG-06, AG-07, AG-15, PS-15, api.md §2.4).

Endpoints:
  GET  /api/v1/approvals
  GET  /api/v1/approvals/{id}
  POST /api/v1/approvals/{id}/decision
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from backend.app.actiongate.approvals import decide_approval, get_approval
from backend.app.core.auth import HumanIdentity, require_human
from backend.app.core.errors import NotFound
from backend.app.db import fetchall, fetchone, get_connection

router = APIRouter(prefix="/approvals", tags=["approvals"])


class DecisionRequest(BaseModel):
    decision: str  # 'approve' | 'reject'
    comment: str = ""


@router.get("")
def list_approvals(
    status: str = Query("", description="Filter by status (pending, approved, rejected, expired, consumed)"),
    kind: str = Query("", description="Filter by kind (action, ingress_review, policy.update)"),
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """List approvals with optional filters."""
    conn = get_connection()
    conditions: list[str] = []
    params: list[Any] = []

    if status:
        conditions.append("status = ?")
        params.append(status)
    if kind:
        conditions.append("kind = ?")
        params.append(kind)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
        SELECT approval_id, kind, status, requester, created_at, expires_at, action_id
        FROM approvals
        {where}
        ORDER BY created_at DESC
    """
    rows = fetchall(conn, sql, tuple(params))
    items = []
    for r in rows:
        summary = f"Approval for {r['kind']}"
        if r["kind"] == "action" and r["action_id"]:
            act = fetchone(
                conn,
                "SELECT action_type, target FROM actions WHERE action_id = ?",
                (r["action_id"],),
            )
            if act:
                summary = (
                    f"{act['action_type']} to {act['target']}"
                    if act["target"]
                    else act["action_type"]
                )
        elif r["kind"] == "policy.update":
            prop = fetchone(
                conn,
                "SELECT note FROM policy_proposals WHERE approval_id = ?",
                (r["approval_id"],),
            )
            if prop and prop["note"]:
                summary = f"Policy proposal: {prop['note']}"
        elif r["kind"] == "ingress_review":
            summary = f"Ingress review: {r['action_id']}"

        items.append({
            "approval_id": r["approval_id"],
            "kind": r["kind"],
            "status": r["status"],
            "requester": r["requester"],
            "created_at": r["created_at"],
            "expires_at": r["expires_at"],
            "summary": summary,
        })

    return {"items": items}


@router.get("/{approval_id}")
def get_approval_details(
    approval_id: str,
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Get full approval record with reviewer view (AG-15)."""
    conn = get_connection()
    ap = get_approval(approval_id)
    if not ap:
        raise NotFound("approval.not_found", f"Approval '{approval_id}' not found.")

    review: dict[str, Any] = {}

    if ap["kind"] == "action" and ap["action_id"]:
        act_row = fetchone(conn, "SELECT * FROM actions WHERE action_id = ?", (ap["action_id"],))
        if act_row:
            signals = json.loads(act_row["signals_json"]) if act_row["signals_json"] else {}
            llm_sig = signals.get("llm")
            if llm_sig:
                llm_summary = {
                    "text": llm_sig.get("summary", ""),
                    "summary": llm_sig.get("summary", ""),
                    "risk_flags": llm_sig.get("risk_flags", []),
                    "suggested_outcome": llm_sig.get("suggested_outcome", "hold"),
                    "label": "advisory",
                    "available": True,
                }
            else:
                llm_summary = {
                    "text": "unavailable (decided by rules)",
                    "label": "advisory",
                    "available": False,
                }

            rule_ids = json.loads(act_row["rule_ids_json"])
            rule_reasons: dict[str, str] = {}
            try:
                from backend.app.core.policy import get_engine
                pol = get_engine().load_active_policy()
                all_rules = {r.get("id"): r.get("reason", "") for r in (pol.get("action_rules", []) + pol.get("policy_rules", []))}
                rule_reasons = {rid: all_rules.get(rid, "") for rid in rule_ids if rid in all_rules}
            except Exception:
                pass

            review = {
                "action": {
                    "action_id": act_row["action_id"],
                    "action_type": act_row["action_type"],
                    "arguments": json.loads(act_row["arguments_json"]),
                    "target": act_row["target"],
                },
                "fingerprint": act_row["fingerprint"],
                "decision_path": act_row["decision_path"],
                "llm_summary": llm_summary,
                "llm": llm_sig,
                "rule_ids": rule_ids,
                "rule_reasons": rule_reasons,
                "taint_level": signals.get("taint_level", 0),
                "blast": signals.get("blast", {}),
            }

    elif ap["kind"] == "policy.update":
        prop = fetchone(conn, "SELECT * FROM policy_proposals WHERE approval_id = ?", (approval_id,))
        if prop:
            review = {
                "diff": json.loads(prop["diff_json"]),
                "note": prop["note"],
                "fingerprint": prop["fingerprint"],
            }

    elif ap["kind"] == "ingress_review":
        rev = fetchone(conn, "SELECT * FROM ingress_reviews WHERE review_id = ?", (ap["action_id"],))
        if rev:
            review = {
                "findings": json.loads(rev["findings_json"]),
                "text_redacted": rev["text_encrypted_or_plain"],
            }

    res = dict(ap)
    res["used"] = bool(res["used"])
    res["review"] = review

    # Retrieve comment from decision ledger entry if decided
    res["comment"] = None
    if res.get("status") in ("approved", "rejected", "consumed"):
        ledg_row = fetchone(
            conn,
            """SELECT reason FROM ledger 
               WHERE subject = ? AND event_type IN ('approval.granted', 'approval.rejected')
               ORDER BY seq DESC LIMIT 1""",
            (f"approval:{approval_id}",),
        )
        if ledg_row and ledg_row["reason"]:
            res["comment"] = ledg_row["reason"]

    return res


@router.post("/{approval_id}/decision")
def submit_approval_decision(
    approval_id: str,
    req: DecisionRequest,
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Submit approval decision (approve or reject). Checks self-approval and roles."""
    return decide_approval(
        approval_id=approval_id,
        decision=req.decision,
        approver_id=human.user_id,
        approver_roles=human.roles,
        comment=req.comment,
    )
