"""
System Status and Admin LLM Settings Router (AU-03, AU-05, LA-10, api.md §2.9).

Provides:
- GET /api/v1/system/status: System operational status (any human)
- GET /api/v1/admin/llm/settings: LLM configuration settings (admin only)
- PUT /api/v1/admin/llm/settings: Update LLM configuration settings (admin only)
- POST /api/v1/admin/llm/test: Round-trip connectivity test probe (admin only)
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from backend.app.config import settings
from backend.app.core import ledger, llm, policy
from backend.app.core.auth import HumanIdentity, require_human, require_roles
from backend.app.core.clock import get_clock
from backend.app.core.errors import UnprocessableEntity as ValidationFailed
from backend.app.db import get_connection

router = APIRouter(tags=["system"])


class LLMSettingsUpdateRequest(BaseModel):
    agent_mode: str | None = Field(default=None, description="'live' or 'simulation'")
    guard_mode: str | None = Field(default=None, description="'live' or 'rules_only'")
    model: str | None = Field(default=None, description="Model identifier e.g. gpt-4o-mini")
    timeout_seconds: float | None = Field(default=None, description="Timeout in seconds")


@router.get("/system/status")
def get_system_status(_human: HumanIdentity = Depends(require_human)) -> dict[str, Any]:
    """Return operational status across agent and guard planes (api.md §2.9)."""
    provider_inst = llm.get_provider()
    provider_name = "scripted_agent" if settings.agent_mode == "simulation" else "openai"
    if hasattr(provider_inst, "mode"):
        provider_name = "mock"

    mode_status = llm.get_mode_status()
    is_down = mode_status.get("mode") == "down" or mode_status.get("breaker") == "open"
    health = "degraded" if is_down else "ok"

    return {
        "agent_mode": settings.agent_mode,
        "guard_mode": settings.guard_mode,
        "provider": provider_name,
        "provider_health": health,
        "last_error": "LLM provider is currently set to down" if is_down else None,
        "active_model": settings.openai_model if settings.agent_mode == "live" else "scripted-agent",
    }


@router.get("/admin/llm/settings")
def get_admin_llm_settings(human: HumanIdentity = Depends(require_roles("admin"))) -> dict[str, Any]:
    """Retrieve LLM runtime configuration (admin only). Omit API keys strictly."""
    return {
        "agent_mode": settings.agent_mode,
        "guard_mode": settings.guard_mode,
        "model": settings.openai_model,
        "timeout_seconds": settings.llm_timeout_seconds,
        "has_api_key": bool(settings.openai_api_key and settings.openai_api_key.strip()),
    }


@router.put("/admin/llm/settings")
def update_admin_llm_settings(
    req: LLMSettingsUpdateRequest,
    human: HumanIdentity = Depends(require_roles("admin")),
) -> dict[str, Any]:
    """Update runtime LLM settings and ledger changes (admin only)."""
    changes: dict[str, Any] = {}

    if req.agent_mode is not None:
        if req.agent_mode not in ("live", "simulation"):
            raise ValidationFailed(
                "validation.failed",
                "agent_mode must be 'live' or 'simulation'",
                details={"field": "agent_mode", "value": req.agent_mode},
            )
        settings.agent_mode = req.agent_mode
        changes["agent_mode"] = req.agent_mode

    if req.guard_mode is not None:
        if req.guard_mode not in ("live", "rules_only"):
            raise ValidationFailed(
                "validation.failed",
                "guard_mode must be 'live' or 'rules_only'",
                details={"field": "guard_mode", "value": req.guard_mode},
            )
        settings.guard_mode = req.guard_mode
        changes["guard_mode"] = req.guard_mode

    if req.model is not None:
        if not req.model.strip():
            raise ValidationFailed("validation.failed", "model cannot be empty", details={"field": "model"})
        settings.openai_model = req.model.strip()
        changes["model"] = req.model.strip()

    if req.timeout_seconds is not None:
        if req.timeout_seconds <= 0:
            raise ValidationFailed(
                "validation.failed",
                "timeout_seconds must be positive",
                details={"field": "timeout_seconds", "value": str(req.timeout_seconds)},
            )
        settings.llm_timeout_seconds = float(req.timeout_seconds)
        changes["timeout_seconds"] = int(round(req.timeout_seconds))

    # Persist in system_settings table
    conn = get_connection()
    clk = get_clock()
    now_iso = clk.now_iso()
    stored_val = {
        "agent_mode": settings.agent_mode,
        "guard_mode": settings.guard_mode,
        "model": settings.openai_model,
        "timeout_seconds": settings.llm_timeout_seconds,
    }
    conn.execute(
        """
        INSERT OR REPLACE INTO system_settings (setting_key, setting_value_json, updated_by, updated_at)
        VALUES ('llm_settings', ?, ?, ?)
        """,
        (json.dumps(stored_val), human.user_id, now_iso),
    )
    conn.commit()

    pol_ver = 1
    with contextlib.suppress(Exception):
        pol_ver = policy.get_engine().active_version()

    ledger.append(
        module="policy",
        event_type="llm.settings_changed",
        subject="settings:llm",
        outcome="allow",
        reason="Admin updated LLM configuration",
        rule_ids=[],
        decision_path="rules",
        policy_version=pol_ver,
        payload={"updated_by": human.user_id, "changes": changes},
    )

    return {
        "agent_mode": settings.agent_mode,
        "guard_mode": settings.guard_mode,
        "model": settings.openai_model,
        "timeout_seconds": settings.llm_timeout_seconds,
        "has_api_key": bool(settings.openai_api_key and settings.openai_api_key.strip()),
    }


@router.post("/admin/llm/test")
def test_admin_llm_connection(human: HumanIdentity = Depends(require_roles("admin"))) -> dict[str, Any]:
    """Test round-trip connectivity to the active LLM provider (LA-10)."""
    provider_inst = llm.get_provider()
    test_res = provider_inst.test_connection()

    pol_ver = 1
    with contextlib.suppress(Exception):
        pol_ver = policy.get_engine().active_version()

    outcome = "allow" if test_res.success else "block"
    reason = "Connection test successful" if test_res.success else (test_res.error or "Connection test failed")

    ledger.append(
        module="policy",
        event_type="llm.connection_tested",
        subject="provider:llm",
        outcome=outcome,
        reason=reason,
        rule_ids=[],
        decision_path="rules",
        policy_version=pol_ver,
        payload={
            "tested_by": human.user_id,
            "success": test_res.success,
            "latency_ms": test_res.latency_ms,
            "model": test_res.model,
            "error": test_res.error,
        },
    )

    return {
        "success": test_res.success,
        "latency_ms": test_res.latency_ms,
        "model": test_res.model,
        "error": test_res.error,
    }
