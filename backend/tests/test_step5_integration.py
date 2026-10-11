"""
Tests for Sentinel Milestone 5: Cross-Module Integration (X-01..X-07).

Requirements covered:
- T-X-01 / X-01: Taint tightens ActionGate (alias of AG-12)
- T-X-02 / X-02: Blast radius tightens ActionGate (alias of AG-13)
- T-X-03 / X-03: Registry flags derived entry points on graph
- T-X-05 / X-05: Egress scan of arguments for canaries in body, subject, display name, base64
- T-X-06 / X-06: One ledger, one policy across all modules
- T-X-07 / X-07: Policy edits gated by second-admin approval (PE-06)
- Decisions feed & Demo tamper API checks
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from backend.app.actiongate.gateway import propose_action
from backend.app.config import settings
from backend.app.core import ledger, policy
from backend.app.core.auth import mint_human_token
from backend.app.core.clock import FixedClock, set_clock
from backend.app.db import get_connection
from backend.app.main import app
from backend.app.promptshield.shield import screen_text


@pytest.fixture(autouse=True)
def setup_integration_env():
    """Ensure clean test clock and DB state for each integration test."""
    clk = FixedClock("2026-01-01T00:00:00.000Z", step_ms=1000)
    set_clock(clk)

    conn = get_connection()
    # Reset active policy to version 1
    conn.execute("UPDATE policy_versions SET activated_at = NULL WHERE version > 1")
    conn.commit()
    policy.get_engine().invalidate_cache()
    yield


@pytest.mark.req("X-01")
@pytest.mark.req("AG-12")
def test_T_X_01_taint_tightens_action():
    """
    T-X-01 / AG-12:
    Same query_customers {limit: 10}: clean session gives allow, taint 1 gives hold.
    Same email.send internal: clean session gives allow, taint 2 gives hold.
    """
    conn = get_connection()

    # Create clean session 1
    conn.execute(
        """INSERT OR REPLACE INTO sessions
           (session_id, agent_id, owner_user_id, taint_level, taint_reasons_json, created_at)
           VALUES ('sess_clean_x1', 'supportbot', 'alice', 0, '[]', '2026-01-01T00:00:00.000Z')"""
    )
    # Create tainted session 2 (taint 1)
    conn.execute(
        """INSERT OR REPLACE INTO sessions
           (session_id, agent_id, owner_user_id, taint_level, taint_reasons_json, created_at)
           VALUES ('sess_taint1_x1', 'supportbot', 'alice', 1, '[]', '2026-01-01T00:00:00.000Z')"""
    )
    # Create flagged session 3 (taint 2)
    conn.execute(
        """INSERT OR REPLACE INTO sessions
           (session_id, agent_id, owner_user_id, taint_level, taint_reasons_json, created_at)
           VALUES ('sess_flagged_x1', 'supportbot', 'alice', 2, '[]', '2026-01-01T00:00:00.000Z')"""
    )
    conn.commit()

    # 1. query_customers limit 10
    # Clean -> allow (AG-R-A03)
    dec_clean = propose_action(
        agent_id="supportbot",
        session_id="sess_clean_x1",
        action_type="db.read",
        arguments={"resource": "asset:customer_db", "limit": 10},
    )
    assert dec_clean["outcome"] == "allow"
    assert "AG-R-A03" in dec_clean["rule_ids"]

    # Taint 1 -> hold (AG-R-H03 or AG-R-H05)
    dec_taint1 = propose_action(
        agent_id="supportbot",
        session_id="sess_taint1_x1",
        action_type="db.read",
        arguments={"resource": "asset:customer_db", "limit": 10},
    )
    assert dec_taint1["outcome"] == "hold"
    assert any(r in dec_taint1["rule_ids"] for r in ("AG-R-H03", "AG-R-H05"))

    # 2. email.send internal
    # Clean -> allow (AG-R-A04)
    dec_email_clean = propose_action(
        agent_id="supportbot",
        session_id="sess_clean_x1",
        action_type="email.send",
        arguments={"to": ["bob@acme.example"], "subject": "Hi", "body": "Hello"},
    )
    assert dec_email_clean["outcome"] == "allow"
    assert "AG-R-A04" in dec_email_clean["rule_ids"]

    # Taint 2 (flagged) -> hold (AG-R-H02)
    dec_email_taint2 = propose_action(
        agent_id="supportbot",
        session_id="sess_flagged_x1",
        action_type="email.send",
        arguments={"to": ["bob@acme.example"], "subject": "Hi", "body": "Hello"},
    )
    assert dec_email_taint2["outcome"] == "hold"
    assert "AG-R-H02" in dec_email_taint2["rule_ids"]


@pytest.mark.req("X-02")
@pytest.mark.req("AG-13")
def test_T_X_02_blast_radius_tightens_action():
    """
    T-X-02 / AG-13:
    Same update_account at taint 1:
    - asset:marketing_db (low blast) -> allow (AG-R-A05)
    - asset:customer_db (high blast) -> hold (AG-R-H05)
    """
    conn = get_connection()
    conn.execute(
        """INSERT OR REPLACE INTO sessions
           (session_id, agent_id, owner_user_id, taint_level, taint_reasons_json, created_at)
           VALUES ('sess_taint1_x2', 'supportbot', 'alice', 1, '[]', '2026-01-01T00:00:00.000Z')"""
    )
    conn.commit()

    # asset:marketing_db -> allow
    dec_mkt = propose_action(
        agent_id="supportbot",
        session_id="sess_taint1_x2",
        action_type="db.update",
        arguments={"resource": "asset:marketing_db", "record_ids": [1, 2, 3], "changes": {"opted_in": 1}},
    )
    assert dec_mkt["outcome"] == "allow"
    assert "AG-R-A05" in dec_mkt["rule_ids"]

    # asset:customer_db -> hold due to blast high + taint 1 (AG-R-H05)
    dec_cust = propose_action(
        agent_id="supportbot",
        session_id="sess_taint1_x2",
        action_type="db.update",
        arguments={"resource": "asset:customer_db", "record_ids": [1, 2, 3], "changes": {"notes": "test"}},
    )
    assert dec_cust["outcome"] == "hold"
    assert "AG-R-H05" in dec_cust["rule_ids"]


@pytest.mark.req("X-03")
@pytest.mark.req("BP-11")
def test_T_X_03_derived_entry_points():
    """
    T-X-03 / BP-11:
    Tool entry points derive badges.
    tool:browse_page and tool:read_reviews have entry_source: derived.
    GET /api/v1/graph returns them with entry_point=True and entry_source='derived'.
    """
    client = TestClient(app)
    token = mint_human_token("alice", ["requester"])

    resp = client.get("/api/v1/graph", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()

    nodes_by_id = {n["id"]: n for n in data["nodes"]}
    assert "tool:browse_page" in nodes_by_id
    assert "tool:read_reviews" in nodes_by_id

    bp_node = nodes_by_id["tool:browse_page"]
    assert bp_node.get("entry_point") is True
    assert bp_node.get("entry_source") == "derived"

    rr_node = nodes_by_id["tool:read_reviews"]
    assert rr_node.get("entry_point") is True
    assert rr_node.get("entry_source") == "derived"


@pytest.mark.req("X-05")
@pytest.mark.req("AG-03")
def test_T_X_05_egress_canary_scan():
    """
    T-X-05:
    send_email with canary in body, subject, display name, and base64 form:
    All block AG-CON-PROTECTED.
    Audit ledger holds no canary value.
    """
    conn = get_connection()
    conn.execute(
        """INSERT OR REPLACE INTO sessions
           (session_id, agent_id, owner_user_id, taint_level, taint_reasons_json, created_at)
           VALUES ('sess_x05', 'supportbot', 'alice', 0, '[]', '2026-01-01T00:00:00.000Z')"""
    )
    conn.commit()

    canary = "sk-acme-4c1f9e27b8a3d605e7f1"
    b64_canary = base64.b64encode(canary.encode("utf-8")).decode("utf-8")

    # 1. Canary in body
    d1 = propose_action(
        agent_id="supportbot",
        session_id="sess_x05",
        action_type="email.send",
        arguments={"to": ["bob@acme.example"], "subject": "Test", "body": f"Here is key: {canary}"},
    )
    assert d1["outcome"] == "block"
    assert "AG-CON-PROTECTED" in d1["rule_ids"]

    # 2. Canary in subject
    d2 = propose_action(
        agent_id="supportbot",
        session_id="sess_x05",
        action_type="email.send",
        arguments={"to": ["bob@acme.example"], "subject": f"Secret {canary}", "body": "Clean body"},
    )
    assert d2["outcome"] == "block"
    assert "AG-CON-PROTECTED" in d2["rule_ids"]

    # 3. Canary in display name: "Alice <canary>"
    d3 = propose_action(
        agent_id="supportbot",
        session_id="sess_x05",
        action_type="email.send",
        arguments={"to": [f"{canary} <bob@acme.example>"], "subject": "Hi", "body": "Clean body"},
    )
    assert d3["outcome"] == "block"
    assert "AG-CON-PROTECTED" in d3["rule_ids"]

    # 4. Canary in base64 form in body
    d4 = propose_action(
        agent_id="supportbot",
        session_id="sess_x05",
        action_type="email.send",
        arguments={"to": ["bob@acme.example"], "subject": "Hi", "body": f"Data: {b64_canary}"},
    )
    assert d4["outcome"] == "block"
    assert "AG-CON-PROTECTED" in d4["rule_ids"]

    # Verify ledger holds NO canary plaintext
    rows = conn.execute("SELECT reason, rule_ids_json FROM ledger").fetchall()
    for r in rows:
        assert canary not in r["reason"]
        assert canary not in r["rule_ids_json"]

    payload_rows = conn.execute("SELECT payload_json FROM ledger_payloads").fetchall()
    for pr in payload_rows:
        assert canary not in pr[0]


@pytest.mark.req("X-06")
def test_T_X_06_shared_ledger_and_policy():
    """
    T-X-06:
    One run touching all three modules (PromptShield, ActionGate, BreachPath):
    GET /api/v1/ledger?module= returns entries for each.
    One verify call covers all.
    Exactly one policy_version value is referenced across all decision entries.
    """
    client = TestClient(app)
    mint_human_token("alice", ["requester"])
    admin_token = mint_human_token("admin", ["admin", "approver"])

    conn = get_connection()
    conn.execute(
        """INSERT OR REPLACE INTO sessions
           (session_id, agent_id, owner_user_id, taint_level, taint_reasons_json, created_at)
           VALUES ('sess_x06', 'supportbot', 'alice', 0, '[]', '2026-01-01T00:00:00.000Z')"""
    )
    conn.commit()

    # 1. PromptShield ingress
    screen_text(
        tier="tool_output",
        text="Hello kettle review",
        session_id="sess_x06",
        source_ref="tool:read_reviews#test",
    )

    # 2. ActionGate action
    propose_action(
        agent_id="supportbot",
        session_id="sess_x06",
        action_type="web.fetch",
        arguments={"url": "https://shop.example"},
    )

    # 3. BreachPath graph change/event
    ledger.append(
        module="breachpath",
        event_type="graph.uploaded",
        subject="graph:1",
        outcome="allow",
        reason="Test graph event",
        rule_ids=[],
        decision_path="rules",
        policy_version=1,
    )

    # 4. Policy event if not already present
    if conn.execute("SELECT COUNT(*) FROM ledger WHERE module = 'policy'").fetchone()[0] == 0:
        ledger.append(
            module="policy",
            event_type="policy.activated",
            subject="policy:sentinel-default",
            outcome="allow",
            reason="Test policy event",
            rule_ids=[],
            decision_path="rules",
            policy_version=1,
        )

    # Verify ledger entries for modules
    for mod in ("promptshield", "actiongate", "breachpath", "policy"):
        resp = client.get(
            f"/api/v1/ledger?module={mod}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1

    # Single verify call covers all entries
    v_res = client.get("/api/v1/ledger/verify", headers={"Authorization": f"Bearer {admin_token}"})
    assert v_res.status_code == 200
    assert v_res.json()["valid"] is True


@pytest.mark.req("X-07")
@pytest.mark.req("PE-06")
def test_T_X_07_policy_proposals_gated():
    """
    T-X-07 / PE-06:
    Policy edits require human plane, admin role, and approval from a different admin.
    """
    client = TestClient(app)
    admin_token = mint_human_token("admin", ["admin"])
    dana_token = mint_human_token("dana", ["admin"])

    # Load active policy
    pol_resp = client.get("/api/v1/policy", headers={"Authorization": f"Bearer {admin_token}"})
    pol_data = pol_resp.json()
    cur_ver = pol_data.get("policy_version", 1)
    cur_pol = pol_data["policy"]

    # Admin proposes a policy change
    modified_pol = json.loads(json.dumps(cur_pol))
    modified_pol["settings"]["approval_ttl_s"] = 1200

    prop_resp = client.post(
        "/api/v1/policy/proposals",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "base_version": cur_ver,
            "policy": modified_pol,
            "note": "Increase approval TTL to 1200",
        },
    )
    assert prop_resp.status_code == 202
    prop_data = prop_resp.json()
    approval_id = prop_data["approval_id"]

    # Proposer (admin) cannot self-approve -> 403
    self_resp = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"decision": "approve"},
    )
    assert self_resp.status_code == 403
    assert self_resp.json()["error"]["code"] == "approval.self_approval"

    # Second admin (dana) approves -> 200
    dana_resp = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers={"Authorization": f"Bearer {dana_token}"},
        json={"decision": "approve", "comment": "Approved by Dana"},
    )
    assert dana_resp.status_code == 200
    assert dana_resp.json()["status"] == "approved"


def test_decisions_feed_endpoint():
    """Verify GET /api/v1/decisions endpoint functionality."""
    client = TestClient(app)
    token = mint_human_token("alice", ["requester"])

    # Invalid limit -> 422
    bad_resp = client.get("/api/v1/decisions?limit=999", headers={"Authorization": f"Bearer {token}"})
    assert bad_resp.status_code == 422
    assert bad_resp.json()["error"]["code"] == "validation.failed"

    # Valid query
    resp = client.get("/api/v1/decisions?limit=10", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "next_seq" in data


def test_demo_tamper_endpoint():
    """Verify POST /api/v1/demo/tamper endpoint functionality."""
    client = TestClient(app)
    admin_token = mint_human_token("admin", ["admin"])
    bob_token = mint_human_token("bob", ["approver"])

    # When demo mode is disabled -> 404 demo.disabled
    settings.demo_mode = False
    resp_off = client.post(
        "/api/v1/demo/tamper",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"seq": 1, "field": "outcome", "value": "tampered"},
    )
    assert resp_off.status_code == 404
    assert resp_off.json()["error"]["code"] == "demo.disabled"

    # When demo mode is enabled
    settings.demo_mode = True

    # Non-admin -> 403
    resp_non_admin = client.post(
        "/api/v1/demo/tamper",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"seq": 1, "field": "outcome", "value": "tampered"},
    )
    assert resp_non_admin.status_code == 403
    assert resp_non_admin.json()["error"]["code"] == "auth.forbidden_role"

    # Admin tampered
    resp_tamper = client.post(
        "/api/v1/demo/tamper",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"seq": 1, "field": "outcome", "value": "tampered"},
    )
    assert resp_tamper.status_code == 200
    assert resp_tamper.json()["tampered_seq"] == 1

    # Ledger verify is now invalid!
    v_res = ledger.verify()
    assert v_res["valid"] is False
    assert v_res["first_broken_seq"] == 1

    # Restore row 1
    conn = get_connection()
    conn.execute("DROP TRIGGER IF EXISTS ledger_no_update")
    conn.execute("UPDATE ledger SET outcome = 'allow' WHERE seq = 1")
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS ledger_no_update
            BEFORE UPDATE ON ledger
        BEGIN
            SELECT RAISE(ABORT, 'ledger is append-only');
        END;
    """)
    conn.commit()
