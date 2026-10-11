"""
Agent plane Sessions router (AU-01, SS-04, api.md §1.1).

Endpoint:
  GET /agent/v1/sessions/{session_id}
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from backend.app.core import session as session_core
from backend.app.core.auth import AgentIdentity, require_agent
from backend.app.core.errors import NotFound

router = APIRouter(prefix="/sessions", tags=["agent-sessions"])


@router.get("/{session_id}")
def get_agent_session(
    session_id: str,
    agent: AgentIdentity = Depends(require_agent),
) -> dict[str, Any]:
    """
    Get session info for the authenticated agent.
    If session belongs to another agent, returns 404 session.not_found (SS-04).
    """
    sess = session_core.get_session(session_id)
    if not sess or sess.agent_id != agent.agent_id:
        raise NotFound("session.not_found", f"Session '{session_id}' not found.")

    return {
        "session_id": sess.session_id,
        "agent_id": sess.agent_id,
        "taint_level": sess.taint_level,
        "taint_label": sess.taint_label,
    }
