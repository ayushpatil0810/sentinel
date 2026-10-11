"""
LLM Mock Mode router (LA-05, api.md §2.9).

Endpoints:
  GET  /api/v1/llm/mode
  POST /api/v1/llm/mode  (sets mock mode, ledgers llm.mode_changed)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backend.app.core import ledger, llm
from backend.app.core.auth import HumanIdentity, require_human
from backend.app.core.errors import UnprocessableEntity

router = APIRouter(prefix="/llm", tags=["llm"])

VALID_MODES = {"ok", "says_safe_always", "timeout", "garbage", "down"}


class SetModeRequest(BaseModel):
    mode: str


@router.get("/mode")
def get_llm_mode(human: HumanIdentity = Depends(require_human)) -> dict[str, Any]:
    """Get current LLM adapter mode and circuit breaker state."""
    return llm.get_mode_status()


@router.post("/mode")
def set_llm_mode(
    req: SetModeRequest,
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Switch LLM adapter mock mode (the 'kill the LLM' toggle)."""
    if req.mode not in VALID_MODES:
        raise UnprocessableEntity("validation.failed", f"Unknown mode '{req.mode}'. Valid: {list(VALID_MODES)}")

    old_mode = llm.get_mode()
    llm.set_mode(req.mode)

    ledger.append(
        module="policy",
        event_type="llm.mode_changed",
        subject="llm:mock_adapter",
        outcome="allow",
        reason=f"Mode changed from {old_mode} to {req.mode} by {human.user_id}",
        rule_ids=[],
        decision_path="rules",
        policy_version=1,
        payload={"old_mode": old_mode, "new_mode": req.mode, "changed_by": human.user_id},
    )

    return llm.get_mode_status()
