"""
Agent plane Actions router (AG-01..AG-16, AU-01, api.md §1.3..1.5).

Endpoints:
  POST /agent/v1/actions
  GET  /agent/v1/actions/{action_id}
  POST /agent/v1/actions/{action_id}/execute
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from backend.app.actiongate.approvals import get_approval_for_action
from backend.app.actiongate.gateway import execute_action, propose_action
from backend.app.core import ledger
from backend.app.core.auth import AgentIdentity, require_agent
from backend.app.core.errors import NotFound, UnprocessableEntity
from backend.app.db import fetchone, get_connection

router = APIRouter(prefix="/actions", tags=["agent-actions"])


class ProposeActionRequest(BaseModel):
    session_id: str
    action_type: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ExecuteActionRequest(BaseModel):
    action_type: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)


@router.post("")
async def propose_agent_action(
    raw_request: Request,
    agent: AgentIdentity = Depends(require_agent),
) -> dict[str, Any]:
    """
    Propose an action through ActionGate.
    Rejects any request body containing 'agent_id' (AU-01).
    """
    try:
        body = await raw_request.json()
    except Exception:
        raise UnprocessableEntity("validation.failed", "Malformed JSON body.") from None

    # AU-01 rule: reject agent_id in body
    if "agent_id" in body:
        ledger.append(
            module="auth",
            event_type="auth.refused",
            subject=f"agent:{agent.agent_id}",
            outcome="block",
            reason="agent_id in body is forbidden",
            rule_ids=[],
            decision_path="rules",
            policy_version=1,
            payload={"reason": "agent_id_present_in_body"},
        )
        raise UnprocessableEntity("agent_id.forbidden", "Body field 'agent_id' is forbidden on the agent plane.")

    if not isinstance(body, dict) or "session_id" not in body or "action_type" not in body or "arguments" not in body:
        raise UnprocessableEntity("validation.failed", "Missing required fields: session_id, action_type, arguments.")

    return propose_action(
        agent_id=agent.agent_id,
        session_id=body["session_id"],
        action_type=body["action_type"],
        arguments=body["arguments"],
    )


@router.get("/{action_id}")
def get_agent_action(
    action_id: str,
    agent: AgentIdentity = Depends(require_agent),
) -> dict[str, Any]:
    """Get status and details of an action owned by the authenticated agent."""
    conn = get_connection()
    row = fetchone(conn, "SELECT * FROM actions WHERE action_id = ?", (action_id,))
    if not row or row["agent_id"] != agent.agent_id:
        raise NotFound("action.not_found", f"Action '{action_id}' not found.")

    ap = get_approval_for_action(action_id)
    approval_info = None
    if ap:
        approval_info = {
            "approval_id": ap["approval_id"],
            "status": ap["status"],
            "expires_at": ap["expires_at"],
        }

    return {
        "action_id": row["action_id"],
        "outcome": row["outcome"],
        "status": row["status"],
        "approval": approval_info,
    }


@router.post("/{action_id}/execute")
def execute_agent_action(
    action_id: str,
    req: ExecuteActionRequest,
    agent: AgentIdentity = Depends(require_agent),
) -> dict[str, Any]:
    """Execute an approved action."""
    return execute_action(
        agent_id=agent.agent_id,
        action_id=action_id,
        submitted_action=req.dict(),
    )
