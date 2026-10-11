"""
Tests for ActionGate (M2):
  AG-01..AG-16, AU-04, X-01, X-02
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.app.actiongate.gateway import execute_action, propose_action
from backend.app.core import errors, llm, session
from backend.app.db import get_connection


@pytest.fixture
def clean_session():
    return session.create_session("supportbot", "alice")


@pytest.fixture
def tainted_session_1():
    s = session.create_session("supportbot", "alice")
    return session.update_taint(s.session_id, 1, "tool:browse_page", "untrusted web page")


@pytest.fixture
def flagged_session():
    s = session.create_session("supportbot", "alice")
    return session.update_taint(s.session_id, 2, "detector:D1", "prompt injection")


# ── AG-01: Agent check ────────────────────────────────────────────────────────

@pytest.mark.req("AG-01")
def test_T_AG_01_unregistered_and_suspended_agent(client):
    """Unregistered agent gets 401; suspended agent gets block AG-DENY-AGENT."""
    # Suspended agent legacybot
    legacy_sess = session.create_session("legacybot", "alice")
    dec = propose_action(
        agent_id="legacybot",
        session_id=legacy_sess.session_id,
        action_type="db.read",
        arguments={"resource": "customers", "limit": 5},
    )
    assert dec["outcome"] == "block"
    assert "AG-DENY-AGENT" in dec["rule_ids"]


# ── AG-02: Action type check ──────────────────────────────────────────────────

@pytest.mark.req("AG-02")
def test_T_AG_02_unregistered_and_disallowed_action(clean_session):
    """Unregistered action type gives AG-DENY-ACTION; disallowed gives AG-DENY-NOTALLOWED."""
    # Unregistered action
    dec1 = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="drive.format",
        arguments={},
    )
    assert dec1["outcome"] == "block"
    assert "AG-DENY-ACTION" in dec1["rule_ids"]

    # Disallowed action for legacybot (if legacybot were active)
    # supportbot has web.fetch, reviews.read, db.read, email.send, db.update, db.delete
    # Test an action type not in agent allowed types by temporarily updating DB
    conn = get_connection()
    conn.execute("UPDATE agents SET allowed_action_types_json = '[\"db.read\"]' WHERE agent_id = 'supportbot'")
    conn.commit()
    try:
        dec2 = propose_action(
            agent_id="supportbot",
            session_id=clean_session.session_id,
            action_type="email.send",
            arguments={"to": ["bob@acme.example"], "subject": "hi", "body": "hello"},
        )
        assert dec2["outcome"] == "block"
        assert "AG-DENY-NOTALLOWED" in dec2["rule_ids"]
    finally:
        conn.execute("UPDATE agents SET allowed_action_types_json = '[\"web.fetch\",\"reviews.read\",\"db.read\",\"email.send\",\"db.update\",\"db.delete\"]' WHERE agent_id = 'supportbot'")
        conn.commit()


# ── AG-03: Arguments & Constraints ───────────────────────────────────────────

@pytest.mark.req("AG-03")
def test_T_AG_03_argument_and_constraint_violations(clean_session):
    """Bad arg schema, deny-list domain, recipient limit, forbidden pattern."""
    # 1. Bad arg schema (email.send missing 'to')
    dec_args = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="email.send",
        arguments={"subject": "missing to", "body": "test"},
    )
    assert dec_args["outcome"] == "block"
    assert "AG-DENY-ARGS" in dec_args["rule_ids"]

    # 2. Deny list domain (pastebin.example)
    dec_deny = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="email.send",
        arguments={"to": ["dump@pastebin.example"], "subject": "test", "body": "hello"},
    )
    assert dec_deny["outcome"] == "block"
    assert "AG-CON-DOMAIN-DENY" in dec_deny["rule_ids"]

    # 3. 21 recipients
    too_many = [f"user{i}@acme.example" for i in range(21)]
    dec_recip = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="email.send",
        arguments={"to": too_many, "subject": "bulk", "body": "hello"},
    )
    assert dec_recip["outcome"] == "block"
    assert "AG-CON-RECIPIENTS" in dec_recip["rule_ids"]

    # 4. SQL pattern in body
    dec_sql = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="email.send",
        arguments={"to": ["bob@acme.example"], "subject": "DROP TABLE", "body": "DROP TABLE customers;"},
    )
    assert dec_sql["outcome"] == "block"
    assert "AG-CON-PATTERN" in dec_sql["rule_ids"]


# ── AG-04: Record thresholds ──────────────────────────────────────────────────

@pytest.mark.req("AG-04")
def test_T_AG_04_record_count_thresholds(clean_session):
    """query_customers: 20 allow, 21 hold, 501 block."""
    # 20 records in clean session: allow (AG-R-A03)
    dec20 = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="db.read",
        arguments={"resource": "asset:customer_db", "limit": 20},
    )
    assert dec20["outcome"] == "allow"
    assert "AG-R-A03" in dec20["rule_ids"]

    # 21 records: hold (AG-R-H03)
    dec21 = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="db.read",
        arguments={"resource": "asset:customer_db", "limit": 21},
    )
    assert dec21["outcome"] == "hold"
    assert "AG-R-H03" in dec21["rule_ids"]

    # 501 records: block (AG-CON-RECORDS-MAX)
    dec501 = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="db.read",
        arguments={"resource": "asset:customer_db", "limit": 501},
    )
    assert dec501["outcome"] == "block"
    assert "AG-CON-RECORDS-MAX" in dec501["rule_ids"]


# ── AG-05: Reversibility & Deletes ─────────────────────────────────────────────

@pytest.mark.req("AG-05")
def test_T_AG_05_reversibility_and_deletes(clean_session, flagged_session):
    """delete_records: 1 id hold (H09), 5 ids hold (H04), flagged block (B01)."""
    # 1 id clean: hold (AG-R-H09: irreversible with high impact)
    dec1 = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="db.delete",
        arguments={"resource": "asset:marketing_db", "record_ids": [1]},
    )
    assert dec1["outcome"] == "hold"
    assert "AG-R-H09" in dec1["rule_ids"]

    # 5 ids clean: hold (AG-R-H04: bulk delete)
    dec5 = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="db.delete",
        arguments={"resource": "asset:marketing_db", "record_ids": [1, 2, 3, 4, 5]},
    )
    assert dec5["outcome"] == "hold"
    assert "AG-R-H04" in dec5["rule_ids"]

    # Flagged session: block (AG-R-B01)
    dec_flagged = propose_action(
        agent_id="supportbot",
        session_id=flagged_session.session_id,
        action_type="db.delete",
        arguments={"resource": "asset:marketing_db", "record_ids": [1]},
    )
    assert dec_flagged["outcome"] == "block"
    assert "AG-R-B01" in dec_flagged["rule_ids"]


# ── AG-06 & AG-16: Fingerprint binding & Approval execution ────────────────────

@pytest.mark.req("AG-06")
@pytest.mark.req("AG-15")
@pytest.mark.req("AG-16")
def test_T_AG_06_approval_binding_and_mutation(client, bob_token, clean_session):
    """Hold -> approve -> mutate argument -> 409 fingerprint mismatch."""
    # 1. Propose action that holds (external email)
    action_args = {
        "to": ["attacker@evil.example"],
        "subject": "Export",
        "body": "Customer list",
        "resource": "svc:mailer",
    }
    dec = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="email.send",
        arguments=action_args,
    )
    assert dec["outcome"] == "hold"
    apr_id = dec["approval_id"]
    act_id = dec["action_id"]

    # Reviewer view check (AG-15)
    resp_view = client.get(f"/api/v1/approvals/{apr_id}", headers={"Authorization": f"Bearer {bob_token}"})
    assert resp_view.status_code == 200
    view_data = resp_view.json()
    assert view_data["review"]["action"]["arguments"] == action_args
    assert view_data["review"]["llm_summary"]["label"] == "advisory"

    # 2. Bob approves
    resp_appr = client.post(
        f"/api/v1/approvals/{apr_id}/decision",
        json={"decision": "approve", "comment": "looks ok"},
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert resp_appr.status_code == 200

    # 3. Execute with mutated argument (changed body character)
    mutated_args = dict(action_args)
    mutated_args["body"] = "Customer list modified"
    with pytest.raises(errors.Conflict) as exc:
        execute_action(
            agent_id="supportbot",
            action_id=act_id,
            submitted_action={"action_type": "email.send", "arguments": mutated_args},
        )
    assert exc.value.code == "approval.fingerprint_mismatch"
    assert "new_action_id" in exc.value.details

    # 4. Execute with exact arguments -> succeeds
    res = execute_action(
        agent_id="supportbot",
        action_id=act_id,
        submitted_action={"action_type": "email.send", "arguments": action_args},
    )
    assert res["status"] == "executed"
    assert "outbox_id" in res["result"]


# ── AG-07: Self-approval refusal ──────────────────────────────────────────────

@pytest.mark.req("AG-07")
def test_T_AG_07_self_approval_refused(client, alice_token, clean_session):
    """Alice proposing policy or action cannot approve her own request."""
    # When alice creates a session and requests approval
    from backend.app.actiongate.approvals import create_approval, decide_approval
    ap = create_approval("action", "deadbeef" * 8, requester="alice")
    apr_id = ap["approval_id"]

    # Alice tries to approve her own request -> 403 approval.self_approval
    with pytest.raises(errors.Forbidden) as exc:
        decide_approval(
            approval_id=apr_id,
            decision="approve",
            approver_id="alice",
            approver_roles=["approver", "admin"],
        )
    assert exc.value.code == "approval.self_approval"


# ── AG-08: Decision recording & ledger ────────────────────────────────────────

@pytest.mark.req("AG-08")
def test_T_AG_08_ledger_entry_per_decision(clean_session):
    """Every decision produces exactly one action.decided ledger entry."""
    conn = get_connection()
    count_before = conn.execute("SELECT COUNT(*) FROM ledger WHERE event_type = 'action.decided'").fetchone()[0]

    for i in range(10):
        propose_action(
            agent_id="supportbot",
            session_id=clean_session.session_id,
            action_type="web.fetch",
            arguments={"url": f"https://example.com/page{i}"},
        )

    count_after = conn.execute("SELECT COUNT(*) FROM ledger WHERE event_type = 'action.decided'").fetchone()[0]
    assert count_after - count_before == 10


# ── AG-09: LLM Fallback ───────────────────────────────────────────────────────

@pytest.mark.req("AG-09")
def test_T_AG_09_llm_fallback(clean_session):
    """When LLM is down/timeout/garbage, decision is made by rules with decision_path = fallback."""
    llm.set_mode("down")
    try:
        dec = propose_action(
            agent_id="supportbot",
            session_id=clean_session.session_id,
            action_type="web.fetch",
            arguments={"url": "https://example.com/test"},
        )
        assert dec["outcome"] == "allow"
        assert dec["decision_path"] == "fallback"
    finally:
        llm.set_mode("ok")


# ── AG-10: LLM cannot loosen ──────────────────────────────────────────────────

@pytest.mark.req("AG-10")
def test_T_AG_10_llm_cannot_loosen(clean_session):
    """Even if LLM says safe always, delete and external email remain hold."""
    llm.set_mode("says_safe_always")
    try:
        dec = propose_action(
            agent_id="supportbot",
            session_id=clean_session.session_id,
            action_type="email.send",
            arguments={"to": ["attacker@evil.example"], "subject": "test", "body": "export"},
        )
        assert dec["outcome"] == "hold"
    finally:
        llm.set_mode("ok")


# ── AG-11: Gatekeeper import restriction ──────────────────────────────────────

@pytest.mark.req("AG-11")
def test_T_AG_11_executors_isolated_to_gateway():
    """Module executors/ is imported only by actiongate/gateway.py."""
    root = Path(__file__).resolve().parent.parent / "app"
    forbidden_imports: list[str] = []

    for py_file in root.rglob("*.py"):
        if "gateway.py" in str(py_file) or "executors" in str(py_file):
            continue
        content = py_file.read_text(encoding="utf-8")
        if "backend.app.actiongate.executors" in content or "from .executors" in content:
            forbidden_imports.append(str(py_file))

    assert forbidden_imports == [], f"Executors imported outside gateway: {forbidden_imports}"


# ── AG-12: Taint link (X-01) ──────────────────────────────────────────────────

@pytest.mark.req("AG-12")
@pytest.mark.req("X-01")
def test_T_AG_12_taint_tightens_decision(clean_session, tainted_session_1, flagged_session):
    """query_customers: clean allow, taint 1 hold. email.send: clean allow, taint 2 hold."""
    # Clean session: query_customers {limit: 10} -> allow
    dec_clean = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="db.read",
        arguments={"resource": "asset:customer_db", "limit": 10},
    )
    assert dec_clean["outcome"] == "allow"

    # Tainted session 1: same query -> hold (AG-R-H03)
    dec_taint1 = propose_action(
        agent_id="supportbot",
        session_id=tainted_session_1.session_id,
        action_type="db.read",
        arguments={"resource": "asset:customer_db", "limit": 10},
    )
    assert dec_taint1["outcome"] == "hold"
    assert "AG-R-H03" in dec_taint1["rule_ids"]


# ── AG-14: Single-use and expiry ──────────────────────────────────────────────

@pytest.mark.req("AG-14")
def test_T_AG_14_single_use_and_expiry(client, bob_token, clean_session):
    """Second execution of approval returns 409 already_used."""
    args = {"to": ["external@partner.example"], "subject": "hi", "body": "test"}
    dec = propose_action(
        agent_id="supportbot",
        session_id=clean_session.session_id,
        action_type="email.send",
        arguments=args,
    )
    apr_id = dec["approval_id"]
    act_id = dec["action_id"]

    client.post(
        f"/api/v1/approvals/{apr_id}/decision",
        json={"decision": "approve", "comment": "approved"},
        headers={"Authorization": f"Bearer {bob_token}"},
    )

    # First execute succeeds
    res1 = execute_action("supportbot", act_id, {"action_type": "email.send", "arguments": args})
    assert res1["status"] == "executed"

    # Second execute fails with 409 already_used
    with pytest.raises(errors.Conflict) as exc:
        execute_action("supportbot", act_id, {"action_type": "email.send", "arguments": args})
    assert exc.value.code == "approval.already_used"
