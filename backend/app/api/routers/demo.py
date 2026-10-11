"""
Demo-only administrative tamper endpoint (LG-03, DEMO-01, demo-script.md §S8).

Allows simulating an insider attacker by mutating a ledger row directly in SQL,
verifying that Sentinel's hash-chained audit ledger detects the tampering immediately.
Disabled whenever DEMO_MODE is off.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header
from pydantic import BaseModel, Field

from backend.app.config import settings
from backend.app.core import errors
from backend.app.core.auth import authenticate_human
from backend.app.db import get_connection

router = APIRouter(prefix="/demo", tags=["demo"])

_ALLOWED_TAMPER_FIELDS = {"outcome", "reason", "subject", "decision_path"}


class TamperRequest(BaseModel):
    seq: int = Field(..., ge=1)
    field: str = Field(..., min_length=1)
    value: str = Field(...)


@router.post("/tamper")
def post_demo_tamper(
    req: TamperRequest,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Tamper directly with a ledger row in SQL to simulate an insider attack."""
    if not settings.demo_mode:
        raise errors.SentinelError(
            code="demo.disabled",
            status_code=404,
            message="Demo endpoints are disabled.",
        )

    user = authenticate_human(authorization)
    if "admin" not in user.get("roles", []):
        raise errors.SentinelError(
            code="auth.forbidden_role",
            status_code=403,
            message="Admin role required for demo tamper.",
        )

    if req.field not in _ALLOWED_TAMPER_FIELDS:
        raise errors.SentinelError(
            code="validation.failed",
            status_code=422,
            message=f"Field '{req.field}' cannot be tampered. Allowed fields: {sorted(_ALLOWED_TAMPER_FIELDS)}",
        )

    conn = get_connection()
    row = conn.execute("SELECT seq FROM ledger WHERE seq = ?", (req.seq,)).fetchone()
    if not row:
        raise errors.SentinelError(
            code="ledger.not_found",
            status_code=404,
            message=f"Ledger entry with seq={req.seq} not found.",
        )

    # Bypass append-only trigger by temporarily dropping and restoring it
    conn.execute("DROP TRIGGER IF EXISTS ledger_no_update")
    conn.execute(
        f"UPDATE ledger SET {req.field} = ? WHERE seq = ?",
        (req.value, req.seq),
    )
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS ledger_no_update
            BEFORE UPDATE ON ledger
        BEGIN
            SELECT RAISE(ABORT, 'ledger is append-only');
        END;
    """)
    conn.commit()

    return {"tampered_seq": req.seq}
