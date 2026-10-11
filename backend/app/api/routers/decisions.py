"""
Decisions feed router (UI-02, api.md §2.3).

Provides:
- GET /api/v1/decisions: polling feed of decision events with cursor pagination.
- GET /api/v1/stream: Server-Sent Events (SSE) live feed of decision entries.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import StreamingResponse

from backend.app.core import errors
from backend.app.core.auth import authenticate_human
from backend.app.db import get_connection

router = APIRouter(tags=["decisions"])


def _extract_session_taint(conn: sqlite3.Connection, payload_ref: str | None, subject: str) -> int:
    """Extract session taint level for a decision entry."""
    if not payload_ref:
        return 0

    try:
        row = conn.execute(
            "SELECT payload_json FROM ledger_payloads WHERE payload_id = ?",
            (payload_ref,),
        ).fetchone()
        if not row:
            return 0
        payload = json.loads(row[0])
        # Direct taint dict in ingress (before/after)
        if "taint" in payload and isinstance(payload["taint"], dict):
            return int(payload["taint"].get("after", 0))
        # Signals in actiongate
        if "signals" in payload and isinstance(payload["signals"], dict):
            return int(payload["signals"].get("taint", 0))
        # Fallback to session_id in payload
        sess_id = payload.get("session_id")
        if sess_id:
            s_row = conn.execute(
                "SELECT taint_level FROM sessions WHERE session_id = ?",
                (sess_id,),
            ).fetchone()
            if s_row:
                return int(s_row[0])
    except Exception:
        pass
    return 0


@router.get("/decisions")
def get_decisions(
    since_seq: int = Query(0, ge=0),
    module: str = Query(""),
    outcome: str = Query(""),
    limit: int = Query(100),
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Poll feed of ingress and action decisions."""
    authenticate_human(authorization)

    if limit < 1 or limit > 500:
        raise errors.SentinelError(
            code="validation.failed",
            status_code=422,
            message="Limit must be between 1 and 500.",
            details={"field": "limit", "value": limit},
        )

    conn = get_connection()
    conditions = ["seq > ?"]
    params: list[Any] = [since_seq]

    if module:
        conditions.append("module = ?")
        params.append(module)
    if outcome:
        conditions.append("outcome = ?")
        params.append(outcome)

    where_clause = " AND ".join(conditions)
    params.append(limit)

    rows = conn.execute(
        f"""SELECT seq, ts, module, event_type, subject, outcome, reason,
                  rule_ids_json, decision_path, payload_ref
           FROM ledger
           WHERE {where_clause}
           ORDER BY seq ASC
           LIMIT ?""",
        params,
    ).fetchall()

    items = []
    for r in rows:
        rule_ids = json.loads(r["rule_ids_json"]) if r["rule_ids_json"] else []
        session_taint = _extract_session_taint(conn, r["payload_ref"], r["subject"])
        items.append({
            "seq": r["seq"],
            "ts": r["ts"],
            "module": r["module"],
            "event_type": r["event_type"],
            "subject": r["subject"],
            "outcome": r["outcome"],
            "reason": r["reason"],
            "rule_ids": rule_ids,
            "decision_path": r["decision_path"],
            "session_taint": session_taint,
        })

    max_head_row = conn.execute("SELECT MAX(seq) FROM ledger").fetchone()
    current_head = max_head_row[0] if max_head_row and max_head_row[0] is not None else 0

    next_seq = items[-1]["seq"] + 1 if items else max(since_seq, current_head) + 1

    return {
        "items": items,
        "next_seq": next_seq,
    }


@router.get("/stream")
async def stream_decisions(
    request: Request,
    authorization: str | None = Header(None),
) -> StreamingResponse:
    """SSE live decisions stream (UI-02, architecture.md §3)."""
    authenticate_human(authorization)

    async def event_generator() -> AsyncIterator[str]:
        last_seq = 0
        conn = get_connection()
        head_row = conn.execute("SELECT MAX(seq) FROM ledger").fetchone()
        if head_row and head_row[0]:
            last_seq = max(0, head_row[0] - 10)

        while True:
            if await request.is_disconnected():
                break

            rows = conn.execute(
                """SELECT seq, ts, module, event_type, subject, outcome, reason,
                          rule_ids_json, decision_path, payload_ref
                   FROM ledger
                   WHERE seq > ?
                   ORDER BY seq ASC
                   LIMIT 50""",
                (last_seq,),
            ).fetchall()

            for r in rows:
                last_seq = r["seq"]
                entry = {
                    "seq": r["seq"],
                    "ts": r["ts"],
                    "module": r["module"],
                    "event_type": r["event_type"],
                    "subject": r["subject"],
                    "outcome": r["outcome"],
                    "reason": r["reason"],
                    "rule_ids": json.loads(r["rule_ids_json"]) if r["rule_ids_json"] else [],
                    "decision_path": r["decision_path"],
                    "session_taint": _extract_session_taint(conn, r["payload_ref"], r["subject"]),
                }
                yield f"data: {json.dumps(entry)}\n\n"

            await asyncio.sleep(1.0)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
