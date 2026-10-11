"""
Registries router (api.md §2.9).

Endpoints:
  GET /api/v1/registries/agents
  GET /api/v1/registries/action-types
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from backend.app.actiongate.registries import list_action_types, list_agents
from backend.app.core.auth import HumanIdentity, require_human

router = APIRouter(prefix="/registries", tags=["registries"])


@router.get("/agents")
def get_agents(human: HumanIdentity = Depends(require_human)) -> list[dict[str, Any]]:
    """Return registered agents."""
    return list_agents()


@router.get("/action-types")
def get_action_types(human: HumanIdentity = Depends(require_human)) -> list[dict[str, Any]]:
    """Return registered action types."""
    return list_action_types()
