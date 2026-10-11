"""
Audit Ledger router (LG-01..LG-07, api.md §2.8).

Endpoints:
  GET  /api/v1/ledger         (any human)
  GET  /api/v1/ledger/{seq}   (any human)
  GET  /api/v1/ledger/verify  (any human)
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query

from backend.app.core import ledger
from backend.app.core.auth import HumanIdentity, require_human
from backend.app.core.errors import NotFound, UnprocessableEntity
from backend.app.db import fetchall, fetchone, get_connection

router = APIRouter(prefix="/ledger", tags=["ledger"])


@router.get("")
def list_ledger_entries(
    module: str = Query("", description="Filter by module"),
    event_type: str = Query("", description="Filter by event_type"),
    subject: str = Query("", description="Filter by subject"),
    outcome: str = Query("", description="Filter by outcome"),
    from_seq: int | None = Query(None, description="Starting seq number"),
    limit: int = Query(100, description="Max entries to return"),
    human: HumanIdentity = Depends(require_human),
) -> list[dict[str, Any]]:
    """List ledger entries with optional filters."""
    if limit < 1 or limit > 1000:
        raise UnprocessableEntity("validation.failed", "Limit must be between 1 and 1000.")

    conn = get_connection()
    conditions: list[str] = []
    params: list[Any] = []

    if module:
        conditions.append("module = ?")
        params.append(module)
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if subject:
        conditions.append("subject = ?")
        params.append(subject)
    if outcome:
        conditions.append("outcome = ?")
        params.append(outcome)
    if from_seq is not None:
        conditions.append("seq >= ?")
        params.append(from_seq)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
        SELECT seq, ts, module, event_type, subject, outcome, reason,
               rule_ids_json, decision_path, policy_version,
               payload_ref, payload_digest, prev_hash, hash
        FROM ledger
        {where}
        ORDER BY seq ASC
        LIMIT ?
    """
    params.append(limit)

    rows = fetchall(conn, sql, tuple(params))
    return [
        {
            "seq": r["seq"],
            "ts": r["ts"],
            "module": r["module"],
            "event_type": r["event_type"],
            "subject": r["subject"],
            "outcome": r["outcome"],
            "reason": r["reason"],
            "rule_ids": json.loads(r["rule_ids_json"]),
            "decision_path": r["decision_path"],
            "policy_version": r["policy_version"],
            "payload_ref": r["payload_ref"],
            "payload_digest": r["payload_digest"],
            "prev_hash": r["prev_hash"],
            "hash": r["hash"],
        }
        for r in rows
    ]


@router.get("/verify")
def verify_ledger(
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Walk and verify the hash chain integrity."""
    return ledger.verify()


@router.get("/{seq}")
def get_ledger_entry(
    seq: int,
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Get a single ledger entry with its payload."""
    conn = get_connection()
    row = fetchone(
        conn,
        """
        SELECT seq, ts, module, event_type, subject, outcome, reason,
               rule_ids_json, decision_path, policy_version,
               payload_ref, payload_digest, prev_hash, hash
        FROM ledger WHERE seq = ?
        """,
        (seq,),
    )
    if not row:
        raise NotFound("ledger.not_found", f"Ledger entry with seq {seq} not found.")

    entry: dict[str, Any] = {
        "seq": row["seq"],
        "ts": row["ts"],
        "module": row["module"],
        "event_type": row["event_type"],
        "subject": row["subject"],
        "outcome": row["outcome"],
        "reason": row["reason"],
        "rule_ids": json.loads(row["rule_ids_json"]),
        "decision_path": row["decision_path"],
        "policy_version": row["policy_version"],
        "payload_ref": row["payload_ref"],
        "payload_digest": row["payload_digest"],
        "prev_hash": row["prev_hash"],
        "hash": row["hash"],
        "payload": None,
    }

    if row["payload_ref"]:
        prow = fetchone(
            conn,
            "SELECT payload_json FROM ledger_payloads WHERE payload_id = ?",
            (row["payload_ref"],),
        )
        if prow:
            entry["payload"] = json.loads(prow["payload_json"])

    return entry
