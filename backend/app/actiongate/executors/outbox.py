"""
Simulated Outbox executor for email.send (AG-11, AU-04).
Imported only by actiongate/gateway.py.
"""

from __future__ import annotations

import json
from typing import Any

from backend.app.core.auth import verify_execution_token
from backend.app.core.clock import Clock, get_clock
from backend.app.db import get_connection


def execute_email_send(
    action_id: str,
    arguments: dict[str, Any],
    token: dict[str, Any] | str,
    fingerprint: str,
    clock: Clock | None = None,
) -> dict[str, Any]:
    """Execute email.send side effect after verifying execution token."""
    clk = clock or get_clock()
    verify_execution_token(token, action_id, fingerprint, clock=clk)

    to_list = arguments.get("to", [])
    subject = arguments.get("subject", "")
    body = arguments.get("body", "")
    body_excerpt = body[:80]
    ts = clk.now_iso()

    conn = get_connection()
    cur = conn.execute(
        """
        INSERT INTO outbox (action_id, ts, to_json, subject, body_excerpt, simulated)
        VALUES (?, ?, ?, ?, ?, 1)
        """,
        (action_id, ts, json.dumps(to_list), subject, body_excerpt),
    )
    conn.commit()

    return {"outbox_id": cur.lastrowid}
