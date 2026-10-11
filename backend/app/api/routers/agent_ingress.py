"""
Agent plane Ingress screening router (POST /agent/v1/ingress) — PS-01..PS-16, api.md §1.2.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from backend.app.actiongate.registries import list_action_types
from backend.app.core import session as session_core
from backend.app.core.auth import AgentIdentity, require_agent
from backend.app.core.errors import NotFound, SentinelError
from backend.app.promptshield.shield import screen_text

router = APIRouter(prefix="/ingress", tags=["ingress"])

TOOL_TO_TIER = {
    "read_reviews": "tool_output",
    "browse_page": "retrieved_document",
    "web.fetch": "retrieved_document",
    "reviews.read": "tool_output",
    "query_customers": "tool_output",
    "db.read": "tool_output",
}

TAINT_LABELS = {
    0: "clean",
    1: "untrusted_present",
    2: "flagged",
}


@router.post("")
def agent_ingress(
    payload: dict[str, Any],
    agent: AgentIdentity = Depends(require_agent),
) -> dict[str, Any]:
    """Agent plane input screening (api.md §1.2, PS-01..PS-16)."""
    # Reject source_tier in body (PS-01, T-PS-01)
    if "source_tier" in payload:
        st = payload["source_tier"]
        if st == "developer":
            raise SentinelError(422, "ingress.tier_forbidden", "source_tier: developer is forbidden on the agent plane.")
        raise SentinelError(422, "validation.failed", "Field 'source_tier' is forbidden in ingress body; use 'origin' or 'tool'.")

    session_id = payload.get("session_id")
    if not session_id:
        raise SentinelError(422, "validation.failed", "Field 'session_id' is required.")

    sess = session_core.get_session(session_id)
    if not sess or sess.agent_id != agent.agent_id:
        raise NotFound("session.not_found", f"Session '{session_id}' not found for agent '{agent.agent_id}'.")

    text = payload.get("text", "")
    if len(text.encode("utf-8")) > 256 * 1024:
        from backend.app.core import ledger
        ledger.append(
            module="promptshield",
            event_type="ingress.rejected",
            subject=session_id,
            outcome="block",
            reason="Input exceeds 256 KiB limit",
            rule_ids=["PS-16"],
            decision_path="rules",
            policy_version=1,
            payload={"bytes": len(text.encode("utf-8"))},
        )
        raise SentinelError(413, "ingress.too_large", "Input exceeds maximum allowed size of 256 KiB.")

    source_ref = payload.get("source_ref", "inline")
    tool = payload.get("tool")
    origin = payload.get("origin")

    # Derive tier from origin or tool (PS-01, D-16)
    if origin == "user":
        tier = "user"
    elif tool:
        # Check tool in TOOL_TO_TIER or registry
        tier = TOOL_TO_TIER.get(tool, "tool_output")
        for at in list_action_types():
            if at.get("tool_node") == f"tool:{tool}" or at.get("action_type") == tool:
                tier = at.get("output_tier", tier)
                break
    else:
        tier = "user"

    res = screen_text(tier=tier, text=text, session_id=session_id, source_ref=source_ref)

    # Get updated session taint
    updated_sess = session_core.get_session(session_id)
    taint_level = updated_sess.taint_level if updated_sess else 0
    taint_label = TAINT_LABELS.get(taint_level, "clean")

    return {
        "request_id": res.request_id,
        "outcome": res.outcome,
        "reason": res.reason,
        "rule_ids": res.rule_ids,
        "decision_path": res.decision_path,
        "policy_version": res.policy_version,
        "text_for_model": res.text_for_model,
        "findings": res.findings,
        "session": {
            "taint_level": taint_level,
            "taint_label": taint_label,
        },
        "review_id": res.review_id,
    }
