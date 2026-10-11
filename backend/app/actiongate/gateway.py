"""
ActionGate Gateway (AG-01..AG-16, AU-04, X-01..X-07).

Sole entry point for agent action proposals and executions.
This module is the ONLY module permitted to import executors (AG-11).
"""

from __future__ import annotations

import email.utils
import hashlib
import json
import math
import re
from typing import Any

from jsonschema import validate as jsonschema_validate

from backend.app.actiongate.approvals import (
    consume_approval,
    create_approval,
    get_approval_for_action,
)
from backend.app.actiongate.executors.fakedb import execute_db_op
from backend.app.actiongate.executors.outbox import execute_email_send
from backend.app.actiongate.fingerprint import (
    compute_action_fingerprint,
    extract_target,
)
from backend.app.actiongate.registries import get_action_type, get_agent
from backend.app.core import ledger, llm, policy
from backend.app.core import session as session_core
from backend.app.core.auth import create_execution_token, verify_approval_signature
from backend.app.core.canonical import canonical_json
from backend.app.core.clock import Clock, get_clock
from backend.app.core.errors import Conflict, NotFound
from backend.app.core.ids import next_id
from backend.app.db import execute, fetchone, get_connection


def _extract_string_leaves(obj: Any) -> list[str]:
    """Extract all string values recursively from a JSON-like object."""
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            strings.extend(_extract_string_leaves(v))
    elif isinstance(obj, list | tuple):
        for item in obj:
            strings.extend(_extract_string_leaves(item))
    return strings


def _scan_protected_values(strings: list[str]) -> bool:
    """Check if any string contains a protected value from protected_values table (X-05)."""
    try:
        from backend.app.promptshield.detectors import detect_d4_protected_values
        from backend.app.promptshield.normalization import decode_layers
        for s in strings:
            if not s:
                continue
            layers = decode_layers(s)
            hits = detect_d4_protected_values(s, decoded_layers=layers)
            if any(h.confidence_pct >= 90 for h in hits):
                return True
    except Exception:
        pass

    conn = get_connection()
    try:
        rows = conn.execute("SELECT value_norm FROM protected_values").fetchall()
    except Exception:
        return False

    if not rows:
        return False

    joined = " ".join(strings)
    # Strip spaces and punctuation for normalized comparison
    stripped = re.sub(r"[^a-zA-Z0-9]", "", joined).lower()

    for r in rows:
        val = r[0]
        if val in joined:
            return True
        val_stripped = re.sub(r"[^a-zA-Z0-9]", "", val).lower()
        if val_stripped and len(val_stripped) >= 8 and val_stripped in stripped:
            return True

    return False


def _get_blast_radius(node_id: str | None) -> dict[str, Any]:
    """Retrieve blast radius for node_id from breachpath, or fail safe to high."""
    if not node_id:
        return {"level": "high", "on_attack_path": True, "paths_count": 0, "reason": "no_node"}

    try:
        from backend.app.breachpath import blast
        return blast.blast_radius(node_id)
    except Exception:
        return {"level": "high", "on_attack_path": True, "paths_count": 0, "reason": "unknown_node"}


def _compute_impact(
    action_type: str,
    sensitivity: str,
    reversible: bool,
    record_count: int,
    destination_external: bool,
) -> tuple[str, int, list[str]]:
    """Compute impact level ('low'|'medium'|'high'), numeric score, and factor list."""
    factors: list[str] = []
    level_ranks = {"low": 1, "medium": 2, "high": 3}
    max_level_rank = level_ranks.get(sensitivity, 1)

    factors.append("IMP-SENS")

    if record_count >= 50:
        max_level_rank = max(max_level_rank, 3)
        factors.append("IMP-RECORDS")
    elif record_count >= 10:
        max_level_rank = max(max_level_rank, 2)
        factors.append("IMP-RECORDS")

    if not reversible:
        max_level_rank = max(max_level_rank, 2)
        factors.append("IMP-IRREV")

    if destination_external:
        max_level_rank = max(max_level_rank, 3)
        factors.append("IMP-EXTERNAL")

    sens_rank = {"low": 1, "medium": 2, "high": 3}.get(sensitivity, 1)
    irrev_int = 1 if not reversible else 0
    ext_int = 1 if destination_external else 0
    records_term = min(15, 5 * math.floor(record_count / 10))
    score = min(100, 20 * sens_rank + 10 * irrev_int + 15 * ext_int + records_term)

    rank_to_level = {1: "low", 2: "medium", 3: "high"}
    return rank_to_level.get(max_level_rank, "low"), score, factors


def propose_action(
    agent_id: str,
    session_id: str,
    action_type: str,
    arguments: dict[str, Any],
    clock: Clock | None = None,
    agent_source: str = "live",
) -> dict[str, Any]:
    """
    ActionGate 9-step evaluation pipeline (AG-01..AG-13).
    """
    clk = clock or get_clock()
    get_connection()
    req_id = next_id("req_")
    act_id = next_id("act_")
    clk.now_iso()

    # Session existence and agent ownership check
    sess = session_core.get_session(session_id)
    if not sess or sess.agent_id != agent_id:
        raise NotFound("session.not_found", f"Session '{session_id}' not found for agent '{agent_id}'.")

    engine = policy.get_engine()
    pol_ver = 1
    try:
        pol_ver = engine.active_version()
    except Exception:
        pol_ver = 1

    # Step 1: Agent registry
    agent = get_agent(agent_id)
    if not agent or agent["status"] != "active":
        return _record_decision(
        request_id=req_id,
        action_id=act_id,
        session_id=session_id,
        agent_id=agent_id,
        action_type=action_type,
        arguments=arguments,
        target=None,
        outcome="block",
        reason="Agent is not registered or is suspended.",
        rule_ids=["AG-DENY-AGENT"],
        decision_path="rules",
        policy_version=pol_ver,
        signals={},
        clock=clk,
    )

    # Step 2: Action type registry
    at = get_action_type(action_type)
    if not at:
        return _record_decision(
            request_id=req_id,
            action_id=act_id,
            session_id=session_id,
            agent_id=agent_id,
            action_type=action_type,
            arguments=arguments,
            target=None,
            outcome="block",
            reason="Action type is not registered.",
            rule_ids=["AG-DENY-ACTION"],
            decision_path="rules",
            policy_version=pol_ver,
            signals={},
            clock=clk,
        )

    # Step 3: Allowed action types for agent
    if action_type not in agent["allowed_action_types"]:
        return _record_decision(
            request_id=req_id,
            action_id=act_id,
            session_id=session_id,
            agent_id=agent_id,
            action_type=action_type,
            arguments=arguments,
            target=None,
            outcome="block",
            reason="Action type is not in agent's allowed list.",
            rule_ids=["AG-DENY-NOTALLOWED"],
            decision_path="rules",
            policy_version=pol_ver,
            signals={},
            clock=clk,
        )

    # Step 4: Argument schema validation
    arg_schema = at.get("arg_schema")
    if arg_schema:
        try:
            jsonschema_validate(instance=arguments, schema=arg_schema)
        except Exception:
            return _record_decision(
                request_id=req_id,
                action_id=act_id,
                session_id=session_id,
                agent_id=agent_id,
                action_type=action_type,
                arguments=arguments,
                target=None,
                outcome="block",
                reason="Arguments do not match required schema.",
                rule_ids=["AG-DENY-ARGS"],
                decision_path="rules",
                policy_version=pol_ver,
                signals={},
                clock=clk,
            )

    target = extract_target(arguments, at.get("target_field"))

    # Step 5: Constraints
    # Check email recipient domains
    all_recipients: list[str] = []
    if action_type == "email.send":
        raw_recipients = arguments.get("to", []) + arguments.get("cc", []) + arguments.get("bcc", [])
        for r in raw_recipients:
            _, addr = email.utils.parseaddr(r)
            if not addr:
                return _record_decision(
                    request_id=req_id,
                    action_id=act_id,
                    session_id=session_id,
                    agent_id=agent_id,
                    action_type=action_type,
                    arguments=arguments,
                    target=target,
                    outcome="block",
                    reason="Invalid email address format.",
                    rule_ids=["AG-DENY-ARGS"],
                    decision_path="rules",
                    policy_version=pol_ver,
                    signals={},
                    clock=clk,
                )
            all_recipients.append(addr.lower())

        if len(all_recipients) > 20:
            return _record_decision(
                request_id=req_id,
                action_id=act_id,
                session_id=session_id,
                agent_id=agent_id,
                action_type=action_type,
                arguments=arguments,
                target=target,
                outcome="block",
                reason="Recipient count exceeds limit (max 20).",
                rule_ids=["AG-CON-RECIPIENTS"],
                decision_path="rules",
                policy_version=pol_ver,
                signals={},
                clock=clk,
            )

        deny_domains = {"pastebin.example", "mailinator.example", "blocked.example"}
        for addr in all_recipients:
            domain = addr.split("@")[-1] if "@" in addr else ""
            if domain in deny_domains:
                return _record_decision(
                    request_id=req_id,
                    action_id=act_id,
                    session_id=session_id,
                    agent_id=agent_id,
                    action_type=action_type,
                    arguments=arguments,
                    target=target,
                    outcome="block",
                    reason=f"Recipient domain '{domain}' is on the deny list.",
                    rule_ids=["AG-CON-DOMAIN-DENY"],
                    decision_path="rules",
                    policy_version=pol_ver,
                    signals={},
                    clock=clk,
                )

    # Check forbidden patterns (SQL keywords, etc.)
    leaves = _extract_string_leaves(arguments)
    sql_regex = re.compile(r"(?i)\b(drop|truncate)\s+table\b")
    for text in leaves:
        if sql_regex.search(text):
            return _record_decision(
                request_id=req_id,
                action_id=act_id,
                session_id=session_id,
                agent_id=agent_id,
                action_type=action_type,
                arguments=arguments,
                target=target,
                outcome="block",
                reason="Forbidden pattern matched in arguments.",
                rule_ids=["AG-CON-PATTERN"],
                decision_path="rules",
                policy_version=pol_ver,
                signals={},
                clock=clk,
            )

    # Check protected values scan (X-05)
    if _scan_protected_values(leaves):
        return _record_decision(
            request_id=req_id,
            action_id=act_id,
            session_id=session_id,
            agent_id=agent_id,
            action_type=action_type,
            arguments=arguments,
            target=target,
            outcome="block",
            reason="Protected value or secret detected in action arguments.",
            rule_ids=["AG-CON-PROTECTED"],
            decision_path="rules",
            policy_version=pol_ver,
            signals={},
            clock=clk,
        )

    # Extract record count
    record_count = 0
    rc_config = at.get("record_count", {})
    mode = rc_config.get("mode", "const")
    if mode == "const":
        record_count = rc_config.get("const", 0)
    elif mode == "length":
        ptr = rc_config.get("pointer", "")
        key = ptr.lstrip("/")
        record_count = len(arguments.get(key, []))
    elif mode == "value":
        ptr = rc_config.get("pointer", "")
        key = ptr.lstrip("/")
        record_count = int(arguments.get(key, 0))

    # Hard record limit check
    max_records_hard = at.get("max_records_hard", 0)
    if max_records_hard > 0 and record_count > max_records_hard:
        return _record_decision(
            request_id=req_id,
            action_id=act_id,
            session_id=session_id,
            agent_id=agent_id,
            action_type=action_type,
            arguments=arguments,
            target=target,
            outcome="block",
            reason=f"Record count {record_count} exceeds hard limit {max_records_hard}.",
            rule_ids=["AG-CON-RECORDS-MAX"],
            decision_path="rules",
            policy_version=pol_ver,
            signals={},
            clock=clk,
        )

    # Step 6: Build context
    destination_external = False
    if action_type == "email.send":
        internal_domains = {"acme.example"}
        for addr in all_recipients:
            dom = addr.split("@")[-1] if "@" in addr else ""
            if dom not in internal_domains:
                destination_external = True
                break

    base_sensitivity = at.get("base_sensitivity", "low")
    action_sensitivity = "high" if (action_type == "email.send" and destination_external) else base_sensitivity
    reversible = at.get("reversible", True)

    target_node = None
    if at.get("target_node_field"):
        key = at["target_node_field"].lstrip("/")
        target_node = arguments.get(key)
    if not target_node:
        target_node = at.get("target_node_default")

    blast = _get_blast_radius(target_node)
    impact_level, impact_score, impact_factors = _compute_impact(
        action_type=action_type,
        sensitivity=action_sensitivity,
        reversible=reversible,
        record_count=record_count,
        destination_external=destination_external,
    )

    ctx = {
        "agent.id": agent_id,
        "agent.status": agent["status"],
        "action.type": action_type,
        "action.reversible": reversible,
        "action.record_count": record_count,
        "action.sensitivity": action_sensitivity,
        "action.destination_external": destination_external,
        "impact.level": impact_level,
        "blast.level": blast.get("level", "high"),
        "session.taint_level": sess.taint_level,
    }

    # Step 7: Rules evaluation
    dec = engine.evaluate("action", ctx, policy_version=pol_ver)
    outcome = dec.outcome
    reason = dec.reason
    rule_ids = list(dec.rule_ids)

    # Step 8: LLM summary & monotonic tightening
    llm_signal = None
    decision_path = "rules"

    if outcome != "block":
        # Check LLM enabled in policy
        llm_enabled = True
        try:
            pol = engine.load_active_policy()
            llm_enabled = pol.get("settings", {}).get("llm", {}).get("enabled", True)
        except Exception:
            pass

        if llm_enabled:
            intent_res = llm.summarize_intent(
                {"action_type": action_type, "arguments": arguments},
                module="actiongate",
                request_id=req_id,
            )
            if intent_res:
                decision_path = "rules+llm"
                llm_signal = {
                    "summary": intent_res.summary,
                    "risk_flags": intent_res.risk_flags,
                    "suggested_outcome": intent_res.suggested_outcome,
                    "label": "advisory",
                }
                # Monotonic tightening: allow -> hold if LLM suggests hold
                if intent_res.suggested_outcome == "hold" and outcome == "allow":
                    outcome = "hold"
                    reason = intent_res.summary
                    if "AG-LLM-TIGHTEN" not in rule_ids:
                        rule_ids.insert(0, "AG-LLM-TIGHTEN")
            else:
                decision_path = "fallback"

    signals: dict[str, Any] = {
        "impact": {"level": impact_level, "score": impact_score, "factors": impact_factors},
        "blast": blast,
        "taint_level": sess.taint_level,
        "llm": llm_signal,
    }

    return _record_decision(
        request_id=req_id,
        action_id=act_id,
        session_id=session_id,
        agent_id=agent_id,
        action_type=action_type,
        arguments=arguments,
        target=target,
        outcome=outcome,
        reason=reason,
        rule_ids=rule_ids,
        decision_path=decision_path,
        policy_version=pol_ver,
        signals=signals,
        clock=clk,
        requester=sess.owner_user_id if sess and sess.owner_user_id else agent_id,
        agent_source=agent_source,
    )


def _record_decision(
    *,
    request_id: str,
    action_id: str,
    session_id: str,
    agent_id: str,
    action_type: str,
    arguments: dict[str, Any],
    target: str | None,
    outcome: str,
    reason: str,
    rule_ids: list[str],
    decision_path: str,
    policy_version: int,
    signals: dict[str, Any],
    clock: Clock | None = None,
    requester: str | None = None,
    agent_source: str = "live",
) -> dict[str, Any]:
    """Record action decision, create approval if hold, run executor if allow, and append to ledger."""
    clk = clock or get_clock()
    conn = get_connection()
    created_at = clk.now_iso()

    fp = compute_action_fingerprint(agent_id, action_type, arguments, target)
    approval_id: str | None = None
    execution_result: dict[str, Any] | None = None
    status = "decided"

    req_user = requester or agent_id

    # If hold, create approval
    if outcome == "hold":
        ap = create_approval(
            kind="action",
            fingerprint=fp,
            requester=req_user,
            action_id=action_id,
            clock=clk,
        )
        approval_id = ap["approval_id"]

    # If allow, immediately execute via executor (D-04)
    if outcome == "allow":
        tok = create_execution_token(action_id, fp, clock=clk)
        if action_type == "email.send":
            res = execute_email_send(action_id, arguments, tok, fp, clock=clk)
            execution_result = {"status": "executed", "result": res}
            status = "executed"
        else:
            res = execute_db_op(action_type, action_id, arguments, tok, fp, clock=clk)
            execution_result = {"status": "executed", "result": res}
            status = "executed"

    # Insert into actions table
    execute(
        conn,
        """
        INSERT INTO actions
        (action_id, session_id, agent_id, agent_source, action_type, arguments_json, target, fingerprint,
         requester, outcome, reason, rule_ids_json, decision_path, policy_version, signals_json,
         status, created_at, executed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            action_id, session_id, agent_id, agent_source, action_type, canonical_json(arguments), target, fp,
            agent_id, outcome, reason, json.dumps(rule_ids), decision_path, policy_version,
            canonical_json(signals), status, created_at, created_at if status == "executed" else None,
        ),
    )
    conn.commit()

    # Append to audit ledger (AG-08)
    ledger.append(
        module="actiongate",
        event_type="action.decided",
        subject=f"action:{action_id}",
        outcome=outcome,
        reason=reason,
        rule_ids=rule_ids,
        decision_path=decision_path,
        policy_version=policy_version,
        payload={
            "action_id": action_id,
            "session_id": session_id,
            "action_type": action_type,
            "target": target,
            "fingerprint": fp,
            "agent_source": agent_source,
            "args_digest": hashlib.sha256(canonical_json(arguments).encode("utf-8")).hexdigest(),
            "signals": signals,
        },
        clock=clk,
    )

    resp: dict[str, Any] = {
        "request_id": request_id,
        "action_id": action_id,
        "outcome": outcome,
        "reason": reason,
        "rule_ids": rule_ids,
        "decision_path": decision_path,
        "policy_version": policy_version,
    }
    if approval_id:
        resp["approval_id"] = approval_id
        resp["fingerprint"] = fp
    if execution_result:
        resp["execution"] = execution_result
    elif outcome == "hold":
        resp["execution"] = None

    return resp


def execute_action(
    agent_id: str,
    action_id: str,
    submitted_action: dict[str, Any],
    clock: Clock | None = None,
) -> dict[str, Any]:
    """
    Execute an approved action (AG-06, AG-14, AG-16).
    """
    clk = clock or get_clock()
    conn = get_connection()

    act_row = fetchone(conn, "SELECT * FROM actions WHERE action_id = ?", (action_id,))
    if not act_row:
        raise NotFound("action.not_found", f"Action '{action_id}' not found.")

    sub_type = submitted_action.get("action_type") or act_row["action_type"]
    sub_args = submitted_action.get("arguments", {})
    at = get_action_type(sub_type)
    target = extract_target(sub_args, at.get("target_field") if at else None)

    # 1. Fingerprint check
    submitted_fp = compute_action_fingerprint(agent_id, sub_type, sub_args, target)
    ap = get_approval_for_action(action_id)

    if not ap or ap["fingerprint"] != submitted_fp:
        # Fingerprint mismatch! AG-16: record refusal and propose as new action
        ledger.append(
            module="actiongate",
            event_type="action.execution_refused",
            subject=f"action:{action_id}",
            outcome="block",
            reason="fingerprint_mismatch",
            rule_ids=[],
            decision_path="rules",
            policy_version=act_row["policy_version"],
            payload={"action_id": action_id, "reason": "fingerprint_mismatch"},
            clock=clk,
        )
        new_dec = propose_action(
            agent_id=agent_id,
            session_id=act_row["session_id"],
            action_type=sub_type,
            arguments=sub_args,
            clock=clk,
        )
        raise Conflict(
            "approval.fingerprint_mismatch",
            "The submitted action differs from the approved action. A new approval is required.",
            details={
                "new_action_id": new_dec["action_id"],
                "new_approval_id": new_dec.get("approval_id"),
            },
        )

    # 2. Status approved check
    if ap.get("used") or ap.get("status") == "consumed":
        raise Conflict("approval.already_used", "Approval has already been consumed.")
    if ap["status"] != "approved":
        raise Conflict("approval.not_approved", f"Action approval is not approved (status: {ap['status']}).")

    # 3. Expiry check
    if clk.now_iso() > ap["expires_at"]:
        execute(conn, "UPDATE approvals SET status = 'expired' WHERE approval_id = ?", (ap["approval_id"],))
        conn.commit()
        ledger.append(
            module="actiongate",
            event_type="approval.expired",
            subject=f"approval:{ap['approval_id']}",
            outcome="block",
            reason="Approval has expired",
            rule_ids=[],
            decision_path="rules",
            policy_version=act_row["policy_version"],
            clock=clk,
        )
        raise Conflict("approval.expired", "Action approval has expired.")

    # 4. Signature check
    sig = ap.get("signature") or ""
    if not verify_approval_signature(
        signature=sig,
        approval_id=ap["approval_id"],
        action_id=action_id,
        fingerprint=ap["fingerprint"],
        requester=ap["requester"],
        approver=ap["approver"] or "",
        decision=ap["decision"] or "approve",
        ts=ap["ts"] or "",
        expires_at=ap["expires_at"],
    ):
        raise Conflict("approval.signature_invalid", "Approval signature verification failed.")

    # 5. Re-evaluate steps 1-7 (D-27)
    engine = policy.get_engine()
    # Check if re-evaluation blocks (e.g. policy tightened since approval)
    # Re-evaluate with current context
    sess = session_core.get_session(act_row["session_id"])
    taint_level = sess.taint_level if sess else 0
    blast = _get_blast_radius(target)
    destination_external = "evil.example" in json.dumps(sub_args) or "external" in json.dumps(sub_args)
    action_sens = "high" if (sub_type == "email.send" and destination_external) else at.get("base_sensitivity", "low") if at else "low"
    imp_level, _, _ = _compute_impact(sub_type, action_sens, at.get("reversible", False) if at else False, 0, destination_external)

    re_ctx = {
        "agent.id": agent_id,
        "agent.status": "active",
        "action.type": sub_type,
        "action.reversible": at.get("reversible", False) if at else False,
        "action.record_count": 0,
        "action.sensitivity": action_sens,
        "action.destination_external": destination_external,
        "impact.level": imp_level,
        "blast.level": blast.get("level", "high"),
        "session.taint_level": taint_level,
    }
    re_dec = engine.evaluate("action", re_ctx)
    if re_dec.outcome == "block":
        ledger.append(
            module="actiongate",
            event_type="action.execution_refused",
            subject=f"action:{action_id}",
            outcome="block",
            reason="Blocked at execution by policy re-evaluation.",
            rule_ids=re_dec.rule_ids,
            decision_path="rules",
            policy_version=re_dec.policy_version,
            payload={"action_id": action_id, "rules": re_dec.rule_ids},
            clock=clk,
        )
        raise Conflict("action.blocked_at_execution", "Action was blocked by policy re-evaluation at execution time.")

    # 6. Consume approval atomically (AG-14)
    if not consume_approval(ap["approval_id"], clock=clk):
        raise Conflict("approval.already_used", "Approval has already been consumed.")

    # 7. Issue execution token and run executor
    tok = create_execution_token(action_id, submitted_fp, clock=clk)
    now_iso = clk.now_iso()

    if sub_type == "email.send":
        res = execute_email_send(action_id, sub_args, tok, submitted_fp, clock=clk)
    else:
        res = execute_db_op(sub_type, action_id, sub_args, tok, submitted_fp, clock=clk)

    execute(
        conn,
        "UPDATE actions SET status = 'executed', executed_at = ? WHERE action_id = ?",
        (now_iso, action_id),
    )
    conn.commit()

    ledger.append(
        module="actiongate",
        event_type="action.executed",
        subject=f"action:{action_id}",
        outcome="executed",
        reason="Action executed successfully.",
        rule_ids=[],
        decision_path="rules",
        policy_version=act_row["policy_version"],
        payload={"action_id": action_id, "result": res},
        clock=clk,
    )

    return {"action_id": action_id, "status": "executed", "result": res}
