"""
Approval state machine and decision logic (AG-06, AG-07, AG-14..AG-16).

State transitions:
  pending -> approved | rejected | expired
  approved -> consumed | expired
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from backend.app.core import ledger
from backend.app.core.auth import sign_approval
from backend.app.core.clock import Clock, get_clock
from backend.app.core.errors import Conflict, Forbidden, NotFound
from backend.app.core.ids import next_id
from backend.app.db import execute, fetchone, get_connection


def create_approval(
    kind: str,
    fingerprint: str,
    requester: str,
    action_id: str | None = None,
    ttl_s: int = 900,
    clock: Clock | None = None,
) -> dict[str, Any]:
    """Create a pending approval record."""
    clk = clock or get_clock()
    conn = get_connection()
    approval_id = next_id("apr_")
    created_at = clk.now_iso()

    # Compute expires_at (default 900s)
    exp_dt = datetime.fromtimestamp(clk.timestamp() + ttl_s, UTC)
    ms = exp_dt.microsecond // 1000
    expires_at = exp_dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"

    execute(
        conn,
        """
        INSERT INTO approvals
        (approval_id, kind, action_id, fingerprint, requester, approver, decision, status, created_at, ts, expires_at, used, signature)
        VALUES (?, ?, ?, ?, ?, NULL, NULL, 'pending', ?, NULL, ?, 0, NULL)
        """,
        (approval_id, kind, action_id, fingerprint, requester, created_at, expires_at),
    )
    conn.commit()

    ledger.append(
        module="actiongate",
        event_type="approval.requested",
        subject=f"approval:{approval_id}",
        outcome="hold",
        reason="Human approval required",
        rule_ids=[],
        decision_path="rules",
        policy_version=1,
        payload={
            "approval_id": approval_id,
            "action_id": action_id,
            "kind": kind,
            "requester": requester,
            "fingerprint": fingerprint,
            "expires_at": expires_at,
        },
        clock=clk,
    )

    return {
        "approval_id": approval_id,
        "kind": kind,
        "action_id": action_id,
        "fingerprint": fingerprint,
        "requester": requester,
        "status": "pending",
        "created_at": created_at,
        "expires_at": expires_at,
    }


def get_approval(approval_id: str) -> dict[str, Any] | None:
    """Fetch approval by ID or action_id/review_id."""
    conn = get_connection()
    row = fetchone(conn, "SELECT * FROM approvals WHERE approval_id = ? OR action_id = ?", (approval_id, approval_id))
    if not row:
        return None
    return dict(row)


def get_approval_for_action(action_id: str) -> dict[str, Any] | None:
    """Fetch approval associated with an action_id."""
    conn = get_connection()
    row = fetchone(conn, "SELECT * FROM approvals WHERE action_id = ? ORDER BY created_at DESC LIMIT 1", (action_id,))
    if not row:
        return None
    return dict(row)


def decide_approval(
    approval_id: str,
    decision: str,  # 'approve' | 'reject'
    approver_id: str,
    approver_roles: list[str],
    comment: str = "",
    clock: Clock | None = None,
) -> dict[str, Any]:
    """
    Decide an approval with checks per spec.md §2.3.
    """
    clk = clock or get_clock()
    conn = get_connection()

    ap = get_approval(approval_id)
    if not ap:
        raise NotFound("approval.not_found", f"Approval '{approval_id}' not found.")

    # 1. Status pending check
    if ap["status"] != "pending":
        raise Conflict("approval.not_pending", f"Approval is not pending (status: {ap['status']}).")

    # Expiry check
    now_iso = clk.now_iso()
    if now_iso > ap["expires_at"]:
        execute(conn, "UPDATE approvals SET status = 'expired' WHERE approval_id = ?", (approval_id,))
        conn.commit()
        ledger.append(
            module="actiongate",
            event_type="approval.expired",
            subject=f"approval:{approval_id}",
            outcome="block",
            reason="Approval has expired",
            rule_ids=[],
            decision_path="rules",
            policy_version=1,
            payload={"approval_id": approval_id},
            clock=clk,
        )
        raise Conflict("approval.expired", "Approval has expired.")

    # 2. No self-approval check (AG-07)
    if approver_id == ap["requester"]:
        ledger.append(
            module="actiongate",
            event_type="approval.refused.self",
            subject=f"approval:{approval_id}",
            outcome="block",
            reason="Self-approval refused",
            rule_ids=[],
            decision_path="rules",
            policy_version=1,
            payload={"approval_id": approval_id, "requester": ap["requester"]},
            clock=clk,
        )
        raise Forbidden("approval.self_approval", "Requesters cannot approve their own requests.")

    # 3. Approver role check
    required_role = "admin" if ap["kind"] == "policy.update" else "approver"
    if required_role not in approver_roles and "admin" not in approver_roles:
        ledger.append(
            module="actiongate",
            event_type="approval.refused.role",
            subject=f"approval:{approval_id}",
            outcome="block",
            reason=f"User lacks required role '{required_role}'",
            rule_ids=[],
            decision_path="rules",
            policy_version=1,
            payload={"approval_id": approval_id, "user": approver_id, "required_role": required_role},
            clock=clk,
        )
        raise Forbidden("auth.forbidden_role", f"User does not have role '{required_role}'.")

    # 4. Fingerprint integrity check (guards DB tampering)
    if ap["action_id"]:
        act = fetchone(conn, "SELECT fingerprint FROM actions WHERE action_id = ?", (ap["action_id"],))
        if act and act["fingerprint"] != ap["fingerprint"]:
            raise Conflict("approval.fingerprint_mismatch", "Approval fingerprint does not match stored action.")

    new_status = "approved" if decision == "approve" else "rejected"
    sig = sign_approval(
        approval_id=approval_id,
        action_id=ap["action_id"],
        fingerprint=ap["fingerprint"],
        requester=ap["requester"],
        approver=approver_id,
        decision=decision,
        ts=now_iso,
        expires_at=ap["expires_at"],
    )

    execute(
        conn,
        """
        UPDATE approvals
        SET status = ?, approver = ?, decision = ?, ts = ?, signature = ?
        WHERE approval_id = ?
        """,
        (new_status, approver_id, decision, now_iso, sig, approval_id),
    )
    conn.commit()

    # If ingress_review, update ingress_reviews table and log with promptshield module
    if ap["kind"] == "ingress_review" and ap["action_id"]:
        new_rev_status = "released" if decision == "approve" else "rejected"
        execute(
            conn,
            "UPDATE ingress_reviews SET status = ? WHERE review_id = ?",
            (new_rev_status, ap["action_id"]),
        )
        conn.commit()
        event = "ingress.review.released" if decision == "approve" else "ingress.review.rejected"
        mod = "promptshield"
    elif ap["kind"] == "policy.update":
        prop = fetchone(conn, "SELECT * FROM policy_proposals WHERE approval_id = ? OR proposal_id = ?", (approval_id, ap["action_id"]))
        if prop and decision == "approve":
            from backend.app.core.policy import get_engine
            eng = get_engine()
            cur_ver = eng.active_version() if eng else 1
            if cur_ver != prop["base_version"]:
                raise Conflict("policy.stale_base", "Base policy version is no longer active.")
            latest_row = fetchone(conn, "SELECT MAX(version) FROM policy_versions")
            max_ver = latest_row[0] if (latest_row and latest_row[0] is not None) else prop["base_version"]
            new_ver = max(prop["base_version"] + 1, max_ver + 1)
            execute(
                conn,
                """
                INSERT INTO policy_versions
                (version, parent_version, content_json, content_hash, created_by, approved_by, created_at, activated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_ver,
                    prop["base_version"],
                    prop["content_json"],
                    prop["fingerprint"],
                    prop["proposed_by"],
                    approver_id,
                    prop["created_at"],
                    now_iso,
                ),
            )
            execute(conn, "UPDATE policy_proposals SET status = 'activated' WHERE proposal_id = ?", (prop["proposal_id"],))
            conn.commit()
            eng.invalidate_cache()
            ledger.append(
                module="policy",
                event_type="policy.activated",
                subject=f"policy:v{new_ver}",
                outcome="allow",
                reason=f"Policy v{new_ver} approved and activated by {approver_id}",
                rule_ids=[],
                decision_path="rules",
                policy_version=new_ver,
                payload={
                    "version": new_ver,
                    "parent_version": prop["base_version"],
                    "proposed_by": prop["proposed_by"],
                    "approved_by": approver_id,
                    "fingerprint": prop["fingerprint"],
                },
                clock=clk,
            )
        elif prop and decision == "reject":
            execute(conn, "UPDATE policy_proposals SET status = 'rejected' WHERE proposal_id = ?", (prop["proposal_id"],))
            conn.commit()
            ledger.append(
                module="policy",
                event_type="policy.proposal_rejected",
                subject=f"proposal:{prop['proposal_id']}",
                outcome="block",
                reason=comment or f"Proposal rejected by {approver_id}",
                rule_ids=[],
                decision_path="rules",
                policy_version=prop["base_version"],
                payload={"proposal_id": prop["proposal_id"], "rejected_by": approver_id},
                clock=clk,
            )
        event = "approval.granted" if decision == "approve" else "approval.rejected"
        mod = "actiongate"
    else:
        event = "approval.granted" if decision == "approve" else "approval.rejected"
        mod = "actiongate"

    ledger.append(
        module=mod,
        event_type=event,
        subject=f"approval:{approval_id}",
        outcome=decision,
        reason=comment or f"Approval {new_status} by {approver_id}",
        rule_ids=[],
        decision_path="rules",
        policy_version=1,
        payload={
            "approval_id": approval_id,
            "action_id": ap["action_id"],
            "approver": approver_id,
            "decision": decision,
            "fingerprint": ap["fingerprint"],
        },
        clock=clk,
    )

    return {
        "approval_id": approval_id,
        "status": new_status,
        "approver": approver_id,
        "signature": sig,
    }


def consume_approval(approval_id: str, clock: Clock | None = None) -> bool:
    """
    Atomically consume an approved approval for execution (AG-14).
    Returns True if consumed successfully, False if already used or not approved.
    """
    clk = clock or get_clock()
    now_iso = clk.now_iso()
    conn = get_connection()

    cur = execute(
        conn,
        """
        UPDATE approvals
        SET status = 'consumed', used = 1, used_at = ?
        WHERE approval_id = ? AND status = 'approved' AND used = 0
        """,
        (now_iso, approval_id),
    )
    conn.commit()
    return cur.rowcount == 1
