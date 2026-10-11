"""
PromptShield Lab router (/api/v1/promptshield/*) — PS-06, PS-08, api.md §2.7.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from backend.app.core import policy
from backend.app.core.auth import HumanIdentity, require_human
from backend.app.core.errors import SentinelError
from backend.app.promptshield.shield import DEFAULT_INGRESS_TABLE, screen_text

router = APIRouter(prefix="/promptshield", tags=["promptshield"])


@router.post("/scan")
def promptshield_lab_scan(
    payload: dict[str, Any],
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Human plane test scan (api.md §2.7, PS-06)."""
    tier = payload.get("source_tier")
    if not tier or tier == "developer":
        raise SentinelError(422, "validation.failed", "source_tier: developer is forbidden in lab scan.")

    text = payload.get("text", "")
    if len(text.encode("utf-8")) > 256 * 1024:
        raise SentinelError(413, "ingress.too_large", "Input exceeds maximum allowed size of 256 KiB.")

    res = screen_text(tier=tier, text=text, is_lab=True)
    return res.to_dict()


@router.get("/policy")
def get_promptshield_policy(
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Get active ingress table and thresholds (api.md §2.7)."""
    engine = policy.get_engine()
    table = DEFAULT_INGRESS_TABLE
    try:
        pol_doc = engine.load_active_policy()
        table = pol_doc.get("ingress_rules", {}).get("table", DEFAULT_INGRESS_TABLE)
    except Exception:
        pass

    return {
        "ingress_table": table,
        "thresholds": {
            "weak_max": 39,
            "low_conf_min": 40,
            "low_conf_max": 59,
            "actionable_min": 60,
        },
    }
