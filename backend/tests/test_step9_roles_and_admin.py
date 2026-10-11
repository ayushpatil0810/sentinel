"""
Tests for Role-Based Access Control, Dual-Admin Gate, and System/LLM Admin Endpoints (AU-03..AU-07, LA-10).

Requirements covered:
- T-AU-05 / AU-05: Server-side role enforcement (403 auth.forbidden_role writes auth.refused to ledger)
- T-AU-06 / AU-06: Role-routed login redirecting to /user or /admin
- T-AU-07 / AU-07: Dual-admin policy gate (admin cannot self-approve; second admin dana can)
- T-LA-10 / LA-10: Round-trip LLM connection test endpoint (POST /api/v1/admin/llm/test)
- System status and LLM settings endpoints (GET /api/v1/system/status, GET/PUT /api/v1/admin/llm/settings)
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.core import ledger, policy
from backend.app.core.auth import mint_human_token
from backend.app.core.clock import FixedClock, set_clock
from backend.app.core.llm import set_mode
from backend.app.db import fetchone, get_connection
from backend.app.main import app


@pytest.fixture(autouse=True)
def setup_roles_env():
    """Ensure clean test environment."""
    clk = FixedClock("2026-01-01T00:00:00.000Z", step_ms=1000)
    set_clock(clk)

    conn = get_connection()
    conn.execute("UPDATE policy_versions SET activated_at = NULL WHERE version > 1")
    conn.commit()
    policy.get_engine().invalidate_cache()
    set_mode("ok")
    settings.agent_mode = "live"
    settings.guard_mode = "live"

    yield

    set_mode("ok")
    settings.agent_mode = "live"
    settings.guard_mode = "live"


@pytest.mark.req("AU-06")
def test_AU06_role_routed_login():
    """T-AU-06: Login routes requesters/approvers to /user and admins to /admin."""
    client = TestClient(app)

    # Alice (requester) -> /user
    res_alice = client.post("/api/v1/auth/login", json={"user_id": "alice", "password": "demo"})
    assert res_alice.status_code == 200
    assert res_alice.json()["redirect_to"] == "/user"

    # Bob (approver) -> /user
    res_bob = client.post("/api/v1/auth/login", json={"user_id": "bob", "password": "demo"})
    assert res_bob.status_code == 200
    assert res_bob.json()["redirect_to"] == "/user"

    # Admin -> /admin
    res_admin = client.post("/api/v1/auth/login", json={"user_id": "admin", "password": "demo"})
    assert res_admin.status_code == 200
    assert res_admin.json()["redirect_to"] == "/admin"

    # Dana (admin 2) -> /admin
    res_dana = client.post("/api/v1/auth/login", json={"user_id": "dana", "password": "demo"})
    assert res_dana.status_code == 200
    assert res_dana.json()["redirect_to"] == "/admin"


@pytest.mark.req("AU-05")
def test_AU05_system_status_and_admin_settings_rbac():
    """T-AU-05: Non-admins are rejected from admin endpoints with 403 and auth.refused ledgered."""
    client = TestClient(app)
    alice_token = mint_human_token("alice", ["requester"])
    bob_token = mint_human_token("bob", ["approver"])
    admin_token = mint_human_token("admin", ["admin", "approver"])

    # 1. System status is open to any authenticated human
    res_status = client.get("/api/v1/system/status", headers={"Authorization": f"Bearer {alice_token}"})
    assert res_status.status_code == 200
    data = res_status.json()
    assert "agent_mode" in data
    assert "guard_mode" in data
    assert "provider" in data
    assert "provider_health" in data

    # 2. Non-admin calls GET /api/v1/admin/llm/settings -> 403 auth.forbidden_role
    res_forbidden = client.get("/api/v1/admin/llm/settings", headers={"Authorization": f"Bearer {alice_token}"})
    assert res_forbidden.status_code == 403
    assert res_forbidden.json()["error"]["code"] == "auth.forbidden_role"

    res_forbidden_bob = client.get("/api/v1/admin/llm/settings", headers={"Authorization": f"Bearer {bob_token}"})
    assert res_forbidden_bob.status_code == 403
    assert res_forbidden_bob.json()["error"]["code"] == "auth.forbidden_role"

    # Verify auth.refused is logged in ledger
    refused_entries = ledger.query(module="auth", event_type="auth.refused")
    assert len(refused_entries) >= 1
    assert any(e["subject"] == "user:alice" for e in refused_entries)

    # 3. Admin calls GET /api/v1/admin/llm/settings -> 200
    res_admin = client.get("/api/v1/admin/llm/settings", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_admin.status_code == 200
    admin_data = res_admin.json()
    assert "agent_mode" in admin_data
    assert "model" in admin_data
    assert "has_api_key" in admin_data
    assert "api_key" not in admin_data  # raw secret strictly omitted


@pytest.mark.req("AU-05")
def test_AU05_admin_llm_settings_update_and_persistence():
    """Admin can update LLM settings, persisted in DB and ledgered."""
    client = TestClient(app)
    admin_token = mint_human_token("admin", ["admin", "approver"])
    bob_token = mint_human_token("bob", ["approver"])

    # Non-admin cannot update
    res_bob = client.put(
        "/api/v1/admin/llm/settings",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"agent_mode": "simulation"},
    )
    assert res_bob.status_code == 403

    # Admin updates settings
    res_update = client.put(
        "/api/v1/admin/llm/settings",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"agent_mode": "simulation", "guard_mode": "rules_only", "timeout_seconds": 5.0},
    )
    assert res_update.status_code == 200
    up_data = res_update.json()
    assert up_data["agent_mode"] == "simulation"
    assert up_data["guard_mode"] == "rules_only"
    assert up_data["timeout_seconds"] == 5.0

    # Verify persisted in database
    conn = get_connection()
    row = fetchone(conn, "SELECT setting_value_json FROM system_settings WHERE setting_key = 'llm_settings'")
    assert row is not None
    val = json.loads(row["setting_value_json"])
    assert val["agent_mode"] == "simulation"
    assert val["guard_mode"] == "rules_only"

    # Verify ledger event llm.settings_changed
    entries = ledger.query(module="policy", event_type="llm.settings_changed")
    assert len(entries) >= 1
    pref = entries[-1]["payload_ref"]
    p_row = fetchone(conn, "SELECT payload_json FROM ledger_payloads WHERE payload_id = ?", (pref,))
    assert p_row is not None
    p = json.loads(p_row["payload_json"])
    assert p["updated_by"] == "admin"


@pytest.mark.req("LA-10")
def test_LA10_admin_llm_connection_test():
    """T-LA-10: Admin connection test probe returns status, model, latency and writes ledger event."""
    client = TestClient(app)
    admin_token = mint_human_token("admin", ["admin"])
    alice_token = mint_human_token("alice", ["requester"])

    # Non-admin rejected
    res_alice = client.post("/api/v1/admin/llm/test", headers={"Authorization": f"Bearer {alice_token}"})
    assert res_alice.status_code == 403

    # Admin test
    res_test = client.post("/api/v1/admin/llm/test", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_test.status_code == 200
    t_data = res_test.json()
    assert "success" in t_data
    assert "latency_ms" in t_data
    assert "model" in t_data

    # Verify ledger entry
    entries = ledger.query(module="policy", event_type="llm.connection_tested")
    assert len(entries) >= 1
    assert entries[-1]["subject"] == "provider:llm"


@pytest.mark.req("AU-07")
def test_AU07_dual_admin_policy_gate():
    """
    T-AU-07: Dual-admin policy gate:
    1. Admin proposes a policy update.
    2. Admin self-approval is refused with 403 approval.self_approval.
    3. Dana (second admin) approves the proposal -> 200 approved, policy activated.
    """
    client = TestClient(app)
    admin_token = mint_human_token("admin", ["admin", "approver"])
    dana_token = mint_human_token("dana", ["admin", "approver"])

    # Fetch active policy
    pol_res = client.get("/api/v1/policy", headers={"Authorization": f"Bearer {admin_token}"})
    assert pol_res.status_code == 200
    active_pol = pol_res.json()
    cur_ver = active_pol["version"]
    candidate = dict(active_pol.get("policy", active_pol))
    candidate["rules"] = list(candidate.get("rules", []))
    # Add a harmless test rule
    candidate["rules"].append({
        "id": "AG-R-TEST-DUAL",
        "kind": "action",
        "description": "Dual admin test rule",
        "condition": {"fact": "action.type", "op": "==", "value": "test.dummy"},
        "outcome": "hold",
        "reason": "Test hold",
    })

    # 1. Admin proposes policy update
    prop_res = client.post(
        "/api/v1/policy/proposals",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"base_version": cur_ver, "policy": candidate, "note": "Add dual admin test rule"},
    )
    assert prop_res.status_code == 202
    prop_data = prop_res.json()
    approval_id = prop_data["approval_id"]
    assert approval_id is not None

    # 2. Admin self-approval attempt fails with 403 approval.self_approval
    self_res = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"decision": "approve", "comment": "Admin approves own proposal"},
    )
    assert self_res.status_code == 403
    assert self_res.json()["error"]["code"] == "approval.self_approval"

    # 3. Dana (second admin) approves the proposal
    dana_res = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers={"Authorization": f"Bearer {dana_token}"},
        json={"decision": "approve", "comment": "Dana verifies and approves change"},
    )
    assert dana_res.status_code == 200
    dana_data = dana_res.json()
    assert dana_data["status"] == "approved"
    assert dana_data["approver"] == "dana"

    pol_after = client.get("/api/v1/policy", headers={"Authorization": f"Bearer {admin_token}"}).json()
    assert pol_after["version"] > cur_ver
