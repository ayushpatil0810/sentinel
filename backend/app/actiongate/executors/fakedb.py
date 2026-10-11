"""
Simulated DB executor for db.read, db.update, db.delete (AG-11, AU-04).
Imported only by actiongate/gateway.py.
"""

from __future__ import annotations

from typing import Any

from backend.app.core.auth import verify_execution_token
from backend.app.core.clock import Clock, get_clock
from backend.app.db import get_connection


def execute_db_op(
    action_type: str,
    action_id: str,
    arguments: dict[str, Any],
    token: dict[str, Any] | str,
    fingerprint: str,
    clock: Clock | None = None,
) -> dict[str, Any]:
    """Execute simulated database operation after verifying execution token."""
    clk = clock or get_clock()
    verify_execution_token(token, action_id, fingerprint, clock=clk)

    resource = arguments.get("resource", "")
    ts = clk.now_iso()
    conn = get_connection()

    if action_type == "db.read":
        limit = arguments.get("limit", 20)
        # Query customers without internal_notes (D-22)
        rows = conn.execute(
            "SELECT customer_id, name, email, phone, order_total_cents FROM customers ORDER BY customer_id ASC LIMIT ?",
            (limit,),
        ).fetchall()
        records = [
            {
                "customer_id": r[0],
                "name": r[1],
                "email": r[2],
                "phone": r[3],
                "order_total_cents": r[4],
            }
            for r in rows
        ]
        count = len(records)
        cur = conn.execute(
            """INSERT INTO fakedb_ops (action_id, ts, op, resource, record_count, simulated)
               VALUES (?, ?, 'read', ?, ?, 1)""",
            (action_id, ts, resource, count),
        )
        conn.commit()
        return {"op_id": cur.lastrowid, "count": count, "records": records}

    elif action_type == "db.update":
        record_ids = arguments.get("record_ids", [])
        count = len(record_ids)
        cur = conn.execute(
            """INSERT INTO fakedb_ops (action_id, ts, op, resource, record_count, simulated)
               VALUES (?, ?, 'update', ?, ?, 1)""",
            (action_id, ts, resource, count),
        )
        conn.commit()
        return {"op_id": cur.lastrowid, "updated": count}

    elif action_type == "db.delete":
        record_ids = arguments.get("record_ids", [])
        count = len(record_ids)
        cur = conn.execute(
            """INSERT INTO fakedb_ops (action_id, ts, op, resource, record_count, simulated)
               VALUES (?, ?, 'delete', ?, ?, 1)""",
            (action_id, ts, resource, count),
        )
        conn.commit()
        return {"op_id": cur.lastrowid, "deleted": count}

    elif action_type in ("web.fetch", "reviews.read"):
        return {"status": "ok", "action_type": action_type}

    else:
        raise ValueError(f"Unsupported action type for DB executor: {action_type}")
