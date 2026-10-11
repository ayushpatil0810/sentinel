"""
Session store and taint tracking (SS-01..SS-04).

Design (spec.md §1.4):
  Session fields: session_id, agent_id, owner_user_id, taint_level,
                  taint_reasons (JSON array, max 50), created_at.
  Taint is monotonic (SS-02): taint_level = max(old, new).
  Every taint change appends a reason and writes session.taint_changed to ledger.
  Only approver or admin can reset taint (SS-03), writing session.taint_reset.
  Sessions created only on human plane (SS-04).
"""

from __future__ import annotations

import json
from typing import Any

from backend.app.core import ledger
from backend.app.core.clock import Clock, get_clock
from backend.app.core.errors import Forbidden, NotFound
from backend.app.core.ids import next_id
from backend.app.db import execute, fetchone, get_connection

TAINT_CLEAN = 0
TAINT_UNTRUSTED_PRESENT = 1
TAINT_FLAGGED = 2

TAINT_LABELS = {
    0: "clean",
    1: "untrusted_present",
    2: "flagged",
}

MAX_TAINT_REASONS = 50


class Session:
    def __init__(
        self,
        session_id: str,
        agent_id: str,
        owner_user_id: str,
        taint_level: int = 0,
        taint_reasons: list[dict[str, Any]] | None = None,
        created_at: str = "",
    ) -> None:
        self.session_id = session_id
        self.agent_id = agent_id
        self.owner_user_id = owner_user_id
        self.taint_level = taint_level
        self.taint_reasons = taint_reasons or []
        self.created_at = created_at

    @property
    def taint_label(self) -> str:
        return TAINT_LABELS.get(self.taint_level, "unknown")

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "owner_user_id": self.owner_user_id,
            "taint_level": self.taint_level,
            "taint_label": self.taint_label,
            "taint_reasons": self.taint_reasons,
            "created_at": self.created_at,
        }


def create_session(
    agent_id: str,
    owner_user_id: str,
    clock: Clock | None = None,
) -> Session:
    """Create a new session on the human plane (SS-04)."""
    clk = clock or get_clock()
    conn = get_connection()

    # Verify agent exists
    agent_row = fetchone(conn, "SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,))
    if not agent_row:
        raise NotFound("agent.not_found", f"Agent '{agent_id}' does not exist.")

    session_id = next_id("sess_")
    created_at = clk.now_iso()
    reasons_json = "[]"

    execute(
        conn,
        """
        INSERT INTO sessions (session_id, agent_id, owner_user_id, taint_level, taint_reasons_json, created_at)
        VALUES (?, ?, ?, 0, ?, ?)
        """,
        (session_id, agent_id, owner_user_id, reasons_json, created_at),
    )
    conn.commit()

    return Session(
        session_id=session_id,
        agent_id=agent_id,
        owner_user_id=owner_user_id,
        taint_level=0,
        taint_reasons=[],
        created_at=created_at,
    )


def get_session(session_id: str) -> Session | None:
    """Load a session by ID. Returns None if not found."""
    conn = get_connection()
    row = fetchone(
        conn,
        "SELECT session_id, agent_id, owner_user_id, taint_level, taint_reasons_json, created_at FROM sessions WHERE session_id = ?",
        (session_id,),
    )
    if not row:
        return None

    reasons = json.loads(row["taint_reasons_json"]) if row["taint_reasons_json"] else []
    return Session(
        session_id=row["session_id"],
        agent_id=row["agent_id"],
        owner_user_id=row["owner_user_id"],
        taint_level=row["taint_level"],
        taint_reasons=reasons,
        created_at=row["created_at"],
    )


def update_taint(
    session_id: str,
    new_level: int,
    source_ref: str,
    cause: str,
    policy_version: int = 1,
    clock: Clock | None = None,
) -> Session:
    """
    Update session taint monotonically: taint_level = max(old, new) (SS-02).
    Appends reason and writes session.taint_changed to ledger.
    """
    clk = clock or get_clock()
    sess = get_session(session_id)
    if not sess:
        raise NotFound("session.not_found", f"Session '{session_id}' not found.")

    old_level = sess.taint_level
    target_level = max(old_level, new_level)

    # If taint did not increase, do not append a new reason or ledger event
    if target_level <= old_level and old_level > 0:
        return sess

    ts = clk.now_iso()
    conn = get_connection()

    # Append ledger entry for taint change
    ledger_entry = ledger.append(
        module="promptshield",
        event_type="session.taint_changed",
        subject=f"session:{session_id}",
        outcome=TAINT_LABELS.get(target_level, str(target_level)),
        reason=cause,
        rule_ids=[],
        decision_path="rules",
        policy_version=policy_version,
        payload={
            "session_id": session_id,
            "old_level": old_level,
            "new_level": target_level,
            "source_ref": source_ref,
            "cause": cause,
        },
        clock=clk,
    )

    new_reason = {
        "ts": ts,
        "source_ref": source_ref,
        "cause": cause,
        "ledger_seq": ledger_entry["seq"],
    }
    reasons = sess.taint_reasons + [new_reason]
    if len(reasons) > MAX_TAINT_REASONS:
        reasons = reasons[-MAX_TAINT_REASONS:]

    execute(
        conn,
        "UPDATE sessions SET taint_level = ?, taint_reasons_json = ? WHERE session_id = ?",
        (target_level, json.dumps(reasons), session_id),
    )
    conn.commit()

    sess.taint_level = target_level
    sess.taint_reasons = reasons
    return sess


def reset_taint(
    session_id: str,
    actor_user_id: str,
    actor_roles: list[str],
    reason: str,
    policy_version: int = 1,
    clock: Clock | None = None,
) -> Session:
    """
    Reset taint to 0 (clean).
    Only human with role 'approver' or 'admin' can reset (SS-03).
    """
    if "approver" not in actor_roles and "admin" not in actor_roles:
        raise Forbidden("auth.forbidden_role", "Only approvers and admins can reset session taint.")

    clk = clock or get_clock()
    sess = get_session(session_id)
    if not sess:
        raise NotFound("session.not_found", f"Session '{session_id}' not found.")

    conn = get_connection()
    execute(
        conn,
        "UPDATE sessions SET taint_level = 0 WHERE session_id = ?",
        (session_id,),
    )
    conn.commit()

    ledger.append(
        module="promptshield",
        event_type="session.taint_reset",
        subject=f"session:{session_id}",
        outcome="clean",
        reason=reason,
        rule_ids=[],
        decision_path="rules",
        policy_version=policy_version,
        payload={
            "session_id": session_id,
            "actor": actor_user_id,
            "reason": reason,
        },
        clock=clk,
    )

    sess.taint_level = 0
    return sess
