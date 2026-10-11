"""
PromptShield screening pipeline (PS-01..PS-16, spec §4).

- Tiers: developer, user, retrieved_document, tool_output.
- Ingress table outcome resolution.
- LLM advisory tightening (monotonic, tighten only, PS-14).
- Sanitization with rescan and isolability checks (PS-07).
- Session taint updates (PS-10).
- Escalation review queue (PS-15).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC
from typing import Any

from backend.app.core import ledger, llm, policy
from backend.app.core import session as session_core
from backend.app.core.canonical import canonical_json
from backend.app.core.clock import get_clock
from backend.app.core.errors import SentinelError
from backend.app.core.ids import next_id
from backend.app.db import get_connection
from backend.app.promptshield.detectors import Finding, run_all_detectors
from backend.app.promptshield.sanitizer import sanitize_text

# Default ingress table (policy-spec.md §5, seed-data.md)
DEFAULT_INGRESS_TABLE = {
    "developer": {
        "override": "allow", "extraction": "allow", "exfil_target": "allow",
        "protected_value": "allow", "hidden_content": "allow", "directive": "allow",
    },
    "user": {
        "override": "block", "extraction": "block", "exfil_target": "escalate",
        "protected_value": "block", "hidden_content": "sanitize", "directive": "allow",
    },
    "retrieved_document": {
        "override": "sanitize", "extraction": "sanitize", "exfil_target": "sanitize",
        "protected_value": "sanitize", "hidden_content": "sanitize", "directive": "sanitize",
    },
    "tool_output": {
        "override": "sanitize", "extraction": "sanitize", "exfil_target": "sanitize",
        "protected_value": "sanitize", "hidden_content": "sanitize", "directive": "sanitize",
    },
}

STRICTNESS = {
    "block": 3,
    "escalate": 2,
    "hold": 2,
    "sanitize": 1,
    "allow": 0,
}


class ScreenResult:
    def __init__(
        self,
        request_id: str,
        outcome: str,
        reason: str,
        rule_ids: list[str],
        decision_path: str,
        policy_version: int,
        text_for_model: str | None,
        findings: list[dict[str, Any]],
        text_sanitized: str | None = None,
        review_id: str | None = None,
    ) -> None:
        self.request_id = request_id
        self.outcome = outcome
        self.reason = reason
        self.rule_ids = rule_ids
        self.decision_path = decision_path
        self.policy_version = policy_version
        self.text_for_model = text_for_model
        self.findings = findings
        self.text_sanitized = text_sanitized
        self.review_id = review_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "kind": "ingress",
            "outcome": self.outcome,
            "reason": self.reason,
            "rule_ids": self.rule_ids,
            "decision_path": self.decision_path,
            "policy_version": self.policy_version,
            "text_for_model": self.text_for_model,
            "text_sanitized": self.text_sanitized,
            "review_id": self.review_id,
            "findings": self.findings,
        }


def screen_text(
    tier: str,
    text: str,
    session_id: str | None = None,
    source_ref: str = "inline",
    is_lab: bool = False,
) -> ScreenResult:
    """
    Screen text through PromptShield (PS-01..PS-15).
    """
    req_id = next_id("req_")

    # Resource limit check (PS-16)
    if len(text.encode("utf-8")) > 256 * 1024:
        raise SentinelError(413, "ingress.too_large", "Input text exceeds 256 KiB limit.")

    if tier not in ("developer", "user", "retrieved_document", "tool_output"):
        raise SentinelError(422, "validation.failed", f"Invalid source tier '{tier}'.")

    # Load active ingress table from policy
    engine = policy.get_engine()
    pol_ver = 1
    table = DEFAULT_INGRESS_TABLE
    try:
        pol_doc = engine.load_active_policy()
        pol_ver = pol_doc.get("version") or engine.active_version()
        ingress_sec = pol_doc.get("ingress") or pol_doc.get("ingress_rules") or {}
        table = ingress_sec.get("table", DEFAULT_INGRESS_TABLE)
    except Exception:
        pass

    # 1. Run detectors
    raw_findings = run_all_detectors(text, tier)

    actionable: list[tuple[Finding, str, str]] = []
    recorded_findings: list[dict[str, Any]] = []

    for f in raw_findings:
        recorded_findings.append(f.to_dict())
        if f.confidence_pct < 40:
            continue
        elif f.confidence_pct < 60:
            # Low confidence band (40..59)
            if f.type in ("exfil_target", "protected_value", "extraction"):
                actionable.append((f, "escalate", "PS-R-LOWCONF-ESCALATE"))
        else:
            # High confidence >= 60
            outcome_for_cell = table.get(tier, {}).get(f.type, "allow")
            rule_id = f"PS-R-{tier.upper()}-{f.type.upper()}"
            actionable.append((f, outcome_for_cell, rule_id))

    # 2. Strictness resolution
    if not actionable:
        primary_outcome = "allow"
        primary_reason = "Input screened clean"
        rule_ids = ["PS-R-CLEAN"]
    else:
        # Sort by strictness desc, confidence desc
        actionable.sort(key=lambda item: (-STRICTNESS.get(item[1], 0), -item[0].confidence_pct))
        top_finding, top_outcome, top_rule = actionable[0]
        primary_outcome = top_outcome
        primary_reason = f"Detected {top_finding.type} ({top_finding.confidence_pct}% confidence)"
        rule_ids = [item[2] for item in actionable]

    text_out: str | None = text
    text_sanitized: str | None = None
    removed_spans: list[dict[str, Any]] = []

    # 3. Sanitizer
    if primary_outcome == "sanitize":
        findings_to_sanitize = [f for f, o, _ in actionable if o == "sanitize"]
        san_status, san_text, removed_spans = sanitize_text(text, findings_to_sanitize, tier)
        text_sanitized = san_text

        if san_status == "escalate":
            primary_outcome = "escalate"
            primary_reason = "Offending span could not be cleanly isolated"
            rule_ids.append("PS-SAN-RESIDUAL")
        elif san_status == "block":
            primary_outcome = "block"
            primary_reason = "All-offending input stripped to empty remainder"
            rule_ids.append("PS-SAN-EMPTY")
            text_out = None
        else:
            text_out = san_text

    # 4. Advisory LLM Merge (tighten only, PS-14)
    decision_path = "rules"
    if primary_outcome != "block":
        llm_enabled = True
        try:
            pol = engine.load_active_policy()
            llm_enabled = pol.get("settings", {}).get("llm", {}).get("enabled", True)
        except Exception:
            pass

        if llm_enabled:
            sig = llm.classify_input(text, tier)
            decision_path = "rules+llm" if sig else "fallback"

            if sig and sig.label == "malicious" and sig.confidence >= 70 and primary_outcome in ("allow", "sanitize"):
                primary_outcome = "escalate"
                primary_reason = f"LLM advisory tightened outcome: {sig.reason}"
                rule_ids.append("PS-LLM-TIGHTEN")

    # If blocked or escalated, model sees null
    if primary_outcome in ("block", "escalate"):
        text_out = None

    review_id: str | None = None

    # 5. Escalation Review Record (PS-15)
    if primary_outcome == "escalate":
        review_id = next_id("rev_")
        owner = "unknown"
        if session_id:
            sess = session_core.get_session(session_id)
            if sess:
                owner = sess.owner_user_id

        conn = get_connection()
        conn.execute(
            """INSERT OR REPLACE INTO ingress_reviews
               (review_id, session_id, source_tier, source_ref, text_encrypted_or_plain, findings_json, status)
               VALUES (?, ?, ?, ?, ?, ?, 'pending')""",
            (
                review_id,
                session_id or "none",
                tier,
                source_ref,
                text,
                json.dumps(recorded_findings),
            ),
        )
        # Create approval entry in approvals table for human reviewer (AG-15, PS-15)
        from datetime import datetime
        clk = get_clock()
        exp_dt = datetime.fromtimestamp(clk.timestamp() + 900, UTC)
        ms = exp_dt.microsecond // 1000
        expires_at = exp_dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"
        fp = hashlib.sha256(canonical_json({"review_id": review_id, "text": text, "tier": tier}).encode("utf-8")).hexdigest()
        conn.execute(
            """INSERT OR REPLACE INTO approvals
               (approval_id, kind, action_id, fingerprint, requester, approver, decision, status, created_at, ts, expires_at, used, signature)
               VALUES (?, 'ingress_review', ?, ?, ?, NULL, NULL, 'pending', ?, NULL, ?, 0, NULL)""",
            (
                review_id,
                review_id,
                fp,
                owner,
                clk.now_iso(),
                expires_at,
            ),
        )
        conn.commit()

    # 6. Session Taint Update (PS-10)
    sess_taint_before = 0
    sess_taint_after = 0
    if session_id and not is_lab:
        sess = session_core.get_session(session_id)
        if sess:
            sess_taint_before = sess.taint_level
            if primary_outcome in ("block", "sanitize", "escalate"):
                # Transition to flagged (2)
                f_name = actionable[0][0].type if actionable else "threat"
                sess = session_core.update_taint(session_id, 2, f"promptshield:{f_name}", primary_reason)
                sess_taint_after = 2
            elif primary_outcome == "allow" and tier in ("retrieved_document", "tool_output"):
                # Transition to at least untrusted_present (1)
                new_t = max(sess.taint_level, 1)
                sess = session_core.update_taint(session_id, new_t, f"tier:{tier}", "untrusted content ingested")
                sess_taint_after = new_t
            else:
                sess_taint_after = sess.taint_level

    # 7. Ledger Screened Event
    event_type = "promptshield.lab_scan" if is_lab else "ingress.screened"
    text_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()

    ledger.append(
        module="promptshield",
        event_type=event_type,
        subject=f"session:{session_id}" if session_id else f"tier:{tier}",
        outcome=primary_outcome,
        reason=primary_reason,
        rule_ids=rule_ids,
        decision_path=decision_path,
        policy_version=pol_ver,
        payload={
            "session_id": session_id,
            "source_tier": tier,
            "source_ref": source_ref,
            "text_digest": text_digest,
            "text_len": len(text),
            "findings": recorded_findings,
            "removed_spans": removed_spans,
            "taint": {"before": sess_taint_before, "after": sess_taint_after},
        },
    )

    return ScreenResult(
        request_id=req_id,
        outcome=primary_outcome,
        reason=primary_reason,
        rule_ids=rule_ids,
        decision_path=decision_path,
        policy_version=pol_ver,
        text_for_model=text_out,
        findings=recorded_findings,
        text_sanitized=text_sanitized,
        review_id=review_id,
    )
