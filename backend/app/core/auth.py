"""
Authentication and Authorization (AU-01..AU-04).

Design (spec.md §1.5, architecture.md §3):
  Two auth planes:
    - Agent plane: /agent/v1 with Authorization: Bearer agk_<agent_id>_<secret>
    - Human plane: /api/v1 with Authorization: Bearer hum.<payload_b64>.<sig>
  Agent keys on /api/v1 -> 403 auth.wrong_plane (writes auth.refused to ledger).
  Human tokens on /agent/v1 -> 403 auth.wrong_plane (writes auth.refused to ledger).
  No auth header -> 401 auth.missing.
  Invalid/expired token -> 401 auth.invalid / auth.expired.
  Agent body with agent_id -> 422 agent_id.forbidden.
  Execution tokens: HMAC(EXEC_KEY, canonical_json({action_id, fingerprint, nonce, exp})), TTL 60s, single use.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from collections.abc import Callable
from typing import Any

from fastapi import Depends, Header

from backend.app.config import settings
from backend.app.core import ledger
from backend.app.core.canonical import canonical_json
from backend.app.core.clock import Clock, get_clock
from backend.app.core.errors import Forbidden, Unauthorized
from backend.app.db import execute, fetchone, get_connection

# ── Password hashing ─────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Demo-grade password hashing using SHA-256."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest() == hashed or plain == hashed


# ── Agent API keys (AU-01) ───────────────────────────────────────────────────

def hash_agent_secret(secret: str) -> str:
    """SHA-256(pepper + secret) per architecture.md §3."""
    data = (settings.agent_pepper + secret).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class AgentIdentity:
    def __init__(self, agent_id: str, name: str, status: str, allowed_action_types: list[str], graph_node_id: str) -> None:
        self.agent_id = agent_id
        self.name = name
        self.status = status
        self.allowed_action_types = allowed_action_types
        self.graph_node_id = graph_node_id


def verify_agent_key(key: str) -> AgentIdentity:
    """Verify an agent key 'agk_<agent_id>_<secret>'. Raises Unauthorized on error."""
    if not key.startswith("agk_"):
        raise Unauthorized("auth.invalid", "Invalid agent key format.")

    rest = key[4:]  # strip 'agk_'
    if "_" not in rest:
        raise Unauthorized("auth.invalid", "Invalid agent key format.")

    agent_id, secret = rest.rsplit("_", 1)
    expected_hash = hash_agent_secret(secret)

    conn = get_connection()
    row = fetchone(
        conn,
        "SELECT agent_id, name, status, allowed_action_types_json, graph_node_id, api_key_hash FROM agents WHERE agent_id = ?",
        (agent_id,),
    )
    if not row:
        raise Unauthorized("auth.invalid", f"Agent '{agent_id}' not found.")

    if not hmac.compare_digest(row["api_key_hash"], expected_hash):
        raise Unauthorized("auth.invalid", "Invalid agent key secret.")

    return AgentIdentity(
        agent_id=row["agent_id"],
        name=row["name"],
        status=row["status"],
        allowed_action_types=json.loads(row["allowed_action_types_json"]),
        graph_node_id=row["graph_node_id"],
    )


# ── Human Bearer tokens (AU-03) ───────────────────────────────────────────────

class HumanIdentity:
    def __init__(self, user_id: str, display_name: str, roles: list[str]) -> None:
        self.user_id = user_id
        self.display_name = display_name
        self.roles = roles

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


def create_human_token(user_id: str, roles: list[str], ttl_s: int | None = None, clock: Clock | None = None) -> str:
    """Create signed human token 'hum.<payload_b64>.<sig>'."""
    clk = clock or get_clock()
    ttl = ttl_s if ttl_s is not None else settings.human_token_ttl_s
    exp = int(clk.timestamp()) + ttl

    payload = {
        "user_id": user_id,
        "roles": roles,
        "exp": exp,
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")
    signing_input = f"hum.{payload_b64}"
    sig = hmac.new(settings.human_key.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{signing_input}.{sig}"


def mint_human_token(user_id: str, roles: list[str]) -> str:
    """Helper alias for create_human_token."""
    return create_human_token(user_id=user_id, roles=roles)


def mint_agent_token(agent_id: str, secret: str = "secret123") -> str:
    """Helper to mint a valid agent key and ensure agent row matches."""
    conn = get_connection()
    conn.execute(
        "UPDATE agents SET api_key_hash = ? WHERE agent_id = ?",
        (hash_agent_secret(secret), agent_id),
    )
    conn.commit()
    return f"agk_{agent_id}_{secret}"


def verify_human_token(token: str, clock: Clock | None = None) -> HumanIdentity:
    """Verify signed human token. Raises Unauthorized on error."""
    clk = clock or get_clock()
    if not token.startswith("hum."):
        raise Unauthorized("auth.invalid", "Invalid human token format.")

    parts = token.split(".")
    if len(parts) != 3:
        raise Unauthorized("auth.invalid", "Invalid human token format.")

    signing_input = f"{parts[0]}.{parts[1]}"
    provided_sig = parts[2]
    expected_sig = hmac.new(settings.human_key.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise Unauthorized("auth.invalid", "Invalid token signature.")

    try:
        # Pad base64 if needed
        b64 = parts[1]
        b64 += "=" * ((4 - len(b64) % 4) % 4)
        raw_json = base64.urlsafe_b64decode(b64).decode("utf-8")
        payload = json.loads(raw_json)
    except Exception:
        raise Unauthorized("auth.invalid", "Malformed token payload.") from None

    exp = payload.get("exp", 0)
    if clk.timestamp() > exp:
        raise Unauthorized("auth.expired", "Human token has expired.")

    user_id = payload.get("user_id", "")
    roles = payload.get("roles", [])

    conn = get_connection()
    row = fetchone(conn, "SELECT user_id, display_name, roles_json FROM users WHERE user_id = ?", (user_id,))
    display_name = row["display_name"] if row else user_id

    return HumanIdentity(user_id=user_id, display_name=display_name, roles=roles)


# ── Execution tokens (AU-04) ──────────────────────────────────────────────────

class ExecutorRefused(Exception):
    """Raised when an executor is invoked with an invalid or missing token (AU-04)."""
    def __init__(self, reason: str) -> None:
        super().__init__(f"Executor refused: {reason}")
        self.reason = reason


def create_execution_token(action_id: str, fingerprint: str, clock: Clock | None = None, ttl_s: int = 60) -> dict[str, Any]:
    """
    Generate an execution token:
    HMAC(EXEC_KEY, canonical_json({action_id, fingerprint, nonce, exp})), TTL 60 s.
    """
    clk = clock or get_clock()
    nonce = uuid.uuid4().hex
    exp = int(clk.timestamp()) + ttl_s

    payload = {
        "action_id": action_id,
        "exp": exp,
        "fingerprint": fingerprint,
        "nonce": nonce,
    }
    canon = canonical_json(payload)
    sig = hmac.new(settings.exec_key.encode("utf-8"), canon.encode("utf-8"), hashlib.sha256).hexdigest()

    return {
        "action_id": action_id,
        "fingerprint": fingerprint,
        "nonce": nonce,
        "exp": exp,
        "sig": sig,
    }


def verify_execution_token(
    token: dict[str, Any] | str,
    expected_action_id: str,
    expected_fingerprint: str,
    clock: Clock | None = None,
) -> None:
    """
    Verify an execution token.
    Enforces signature, expiry, and single-use via exec_tokens_used.
    Raises ExecutorRefused on any failure.
    """
    clk = clock or get_clock()

    if isinstance(token, str):
        try:
            token = json.loads(token)
        except Exception:
            raise ExecutorRefused("malformed_token") from None

    if not isinstance(token, dict):
        raise ExecutorRefused("invalid_token_type")

    action_id = token.get("action_id")
    fingerprint = token.get("fingerprint")
    nonce = token.get("nonce")
    exp = token.get("exp")
    sig = token.get("sig")

    if not (action_id and fingerprint and nonce and exp and sig):
        raise ExecutorRefused("missing_token_fields")

    if action_id != expected_action_id:
        raise ExecutorRefused("action_id_mismatch")

    if fingerprint != expected_fingerprint:
        raise ExecutorRefused("fingerprint_mismatch")

    if clk.timestamp() > exp:
        raise ExecutorRefused("token_expired")

    payload = {
        "action_id": action_id,
        "exp": exp,
        "fingerprint": fingerprint,
        "nonce": nonce,
    }
    canon = canonical_json(payload)
    expected_sig = hmac.new(settings.exec_key.encode("utf-8"), canon.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(sig, expected_sig):
        raise ExecutorRefused("invalid_signature")

    # Check nonce reuse
    conn = get_connection()
    row = fetchone(conn, "SELECT nonce FROM exec_tokens_used WHERE nonce = ?", (nonce,))
    if row:
        raise ExecutorRefused("nonce_already_used")

    # Record nonce use
    used_at = clk.now_iso()
    execute(conn, "INSERT INTO exec_tokens_used (nonce, used_at) VALUES (?, ?)", (nonce, used_at))
    conn.commit()


# ── Approval signatures (D-06) ────────────────────────────────────────────────

def sign_approval(
    approval_id: str,
    action_id: str | None,
    fingerprint: str,
    requester: str,
    approver: str,
    decision: str,
    ts: str,
    expires_at: str,
) -> str:
    """HMAC-SHA256(APPROVAL_KEY, canonical_json({approval_id, action_id, fingerprint, requester, approver, decision, ts, expires_at}))."""
    obj = {
        "action_id": action_id,
        "approval_id": approval_id,
        "approver": approver,
        "decision": decision,
        "expires_at": expires_at,
        "fingerprint": fingerprint,
        "requester": requester,
        "ts": ts,
    }
    canon = canonical_json(obj)
    return hmac.new(settings.approval_key.encode("utf-8"), canon.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_approval_signature(
    signature: str,
    approval_id: str,
    action_id: str | None,
    fingerprint: str,
    requester: str,
    approver: str,
    decision: str,
    ts: str,
    expires_at: str,
) -> bool:
    expected = sign_approval(
        approval_id=approval_id,
        action_id=action_id,
        fingerprint=fingerprint,
        requester=requester,
        approver=approver,
        decision=decision,
        ts=ts,
        expires_at=expires_at,
    )
    return hmac.compare_digest(signature, expected)


# ── FastApi dependencies & plane guards ───────────────────────────────────────

def extract_bearer_token(authorization: str | None) -> str:
    """Extract token from 'Bearer <token>'. Raises Unauthorized if missing or bad format."""
    if not authorization:
        raise Unauthorized("auth.missing", "Authorization header is required.")

    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise Unauthorized("auth.invalid", "Bearer token is required.")

    return parts[1].strip()


def require_agent(authorization: str | None = Header(None)) -> AgentIdentity:
    """
    Authenticate agent on /agent/v1 routes (AU-01).
    Rejects human token with 403 auth.wrong_plane and writes auth.refused to ledger.
    """
    token = extract_bearer_token(authorization)

    if token.startswith("hum."):
        # Wrong plane! A human token was presented to agent plane
        try:
            h = verify_human_token(token)
            subj = f"user:{h.user_id}"
        except Exception:
            subj = "user:unknown"

        ledger.append(
            module="auth",
            event_type="auth.refused",
            subject=subj,
            outcome="block",
            reason="wrong_plane",
            rule_ids=[],
            decision_path="rules",
            policy_version=1,
            payload={"plane": "agent", "reason": "human_token_on_agent_plane"},
        )
        raise Forbidden("auth.wrong_plane", "Human tokens are forbidden on the agent plane.")

    return verify_agent_key(token)


def require_human(authorization: str | None = Header(None)) -> HumanIdentity:
    """
    Authenticate human on /api/v1 routes (AU-02).
    Rejects agent credential with 403 auth.wrong_plane and writes auth.refused to ledger.
    """
    token = extract_bearer_token(authorization)

    if token.startswith("agk_"):
        # Wrong plane! An agent key was presented to human plane
        parts = token.split("_", 2)
        agent_id = parts[1] if len(parts) > 1 else "unknown"
        subj = f"agent:{agent_id}"

        ledger.append(
            module="auth",
            event_type="auth.refused",
            subject=subj,
            outcome="block",
            reason="wrong_plane",
            rule_ids=[],
            decision_path="rules",
            policy_version=1,
            payload={"plane": "human", "reason": "agent_key_on_human_plane"},
        )
        raise Forbidden("auth.wrong_plane", "Agent credentials are forbidden on the human plane.")

    return verify_human_token(token)


def require_roles(*roles: str) -> Callable[[HumanIdentity], HumanIdentity]:
    """Dependency factory checking human user roles (AU-03, AU-05)."""
    def _role_checker(human: HumanIdentity = Depends(require_human)) -> HumanIdentity:
        if not any(human.has_role(r) for r in roles):
            ledger.append(
                module="auth",
                event_type="auth.refused",
                subject=f"user:{human.user_id}",
                outcome="block",
                reason="forbidden_role",
                rule_ids=[],
                decision_path="rules",
                policy_version=1,
                payload={"required_roles": list(roles), "user_roles": human.roles, "user_id": human.user_id},
            )
            raise Forbidden("auth.forbidden_role", f"User does not have required role from {roles}.")
        return human
    return _role_checker


def require_role(role: str) -> Callable[[HumanIdentity], HumanIdentity]:
    """Dependency factory checking human user role (AU-03)."""
    return require_roles(role)


require_admin = require_roles("admin")
require_approver = require_roles("approver", "admin")

authenticate_human = require_human
