"""
Human plane Sessions router (SS-01..SS-04, api.md §2.2).

Endpoints:
  POST /api/v1/sessions              (any human)
  GET  /api/v1/sessions/{id}         (any human)
  POST /api/v1/sessions/{id}/taint/reset (approver, admin)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from backend.app.core import session as session_core
from backend.app.core.auth import HumanIdentity, require_human
from backend.app.core.errors import NotFound

router = APIRouter(prefix="/sessions", tags=["sessions"])


class CreateSessionRequest(BaseModel):
    agent_id: str


class ResetTaintRequest(BaseModel):
    reason: str


@router.post("", status_code=status.HTTP_201_CREATED)
def create_session(
    req: CreateSessionRequest,
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Create a new session for an agent, owned by the authenticated human."""
    sess = session_core.create_session(
        agent_id=req.agent_id,
        owner_user_id=human.user_id,
    )
    return {
        "session_id": sess.session_id,
        "owner_user_id": sess.owner_user_id,
        "taint_level": sess.taint_level,
    }


@router.get("/{session_id}")
def get_session(
    session_id: str,
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Get session details including taint history."""
    sess = session_core.get_session(session_id)
    if not sess:
        raise NotFound("session.not_found", f"Session '{session_id}' not found.")
    return sess.to_dict()


@router.post("/{session_id}/taint/reset")
def reset_taint(
    session_id: str,
    req: ResetTaintRequest,
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Reset session taint level to 0 (clean). Approver or admin role required."""
    sess = session_core.reset_taint(
        session_id=session_id,
        actor_user_id=human.user_id,
        actor_roles=human.roles,
        reason=req.reason,
    )
    return {"taint_level": sess.taint_level}
