"""
GET /health — unauthenticated health check (api.md §2.10).

Returns:
    200: {"status": "ok", "policy_version": N, "graph_version": N,
           "ledger_head": N, "llm_mode": "ok"}
    503: {"status": "degraded", "problems": [...]}
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from backend.app.config import settings

router = APIRouter()


@router.get("/health")
def health() -> JSONResponse:
    """Health check — no auth required (api.md §2.10)."""
    problems: list[str] = []
    policy_version = 0
    graph_version = 0
    ledger_head = 0

    # Import lazily to avoid circular imports at module load time
    try:
        from backend.app.db import get_connection
        conn = get_connection()

        # Active policy version
        row = conn.execute(
            "SELECT version FROM policy_versions WHERE activated_at IS NOT NULL "
            "ORDER BY version DESC LIMIT 1"
        ).fetchone()
        if row:
            policy_version = row[0]
        else:
            problems.append("policy_missing")

        # Latest graph version
        row = conn.execute(
            "SELECT graph_version FROM graph_versions ORDER BY graph_version DESC LIMIT 1"
        ).fetchone()
        if row:
            graph_version = row[0]

        # Ledger head seq
        row = conn.execute("SELECT MAX(seq) FROM ledger").fetchone()
        if row and row[0] is not None:
            ledger_head = row[0]

    except Exception as exc:
        problems.append(f"db_error: {exc}")

    if problems:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "problems": problems},
        )

    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "policy_version": policy_version,
            "graph_version": graph_version,
            "ledger_head": ledger_head,
            "llm_mode": settings.llm_mode,
            "demo_mode": settings.demo_mode,
        },
    )
