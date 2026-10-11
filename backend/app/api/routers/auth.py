"""
Human plane Auth router (AU-01..AU-03, api.md §2.1).

Endpoints:
  POST /api/v1/auth/login  (public)
  GET  /api/v1/auth/me     (any human)
  GET  /api/v1/users       (any human)
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backend.app.config import settings
from backend.app.core import ledger
from backend.app.core.auth import (
    HumanIdentity,
    create_human_token,
    require_human,
    verify_password,
)
from backend.app.core.errors import Unauthorized
from backend.app.db import fetchall, fetchone, get_connection

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    user_id: str
    password: str


@router.post("/login")
def login(req: LoginRequest) -> dict[str, Any]:
    """Authenticate a human user and return a signed bearer token."""
    conn = get_connection()
    row = fetchone(
        conn,
        "SELECT user_id, display_name, roles_json, password_hash FROM users WHERE user_id = ?",
        (req.user_id,),
    )
    if not row or not verify_password(req.password, row["password_hash"]):
        # Refusal event
        ledger.append(
            module="auth",
            event_type="auth.refused",
            subject=f"user:{req.user_id}",
            outcome="block",
            reason="invalid_credentials",
            rule_ids=[],
            decision_path="rules",
            policy_version=1,
            payload={"user_id": req.user_id, "reason": "bad_password_or_user"},
        )
        raise Unauthorized("auth.invalid", "Invalid username or password.")

    roles = json.loads(row["roles_json"])
    token = create_human_token(user_id=row["user_id"], roles=roles)

    # Login event
    ledger.append(
        module="auth",
        event_type="auth.login",
        subject=f"user:{row['user_id']}",
        outcome="allow",
        reason="login ok",
        rule_ids=[],
        decision_path="rules",
        policy_version=1,
        payload={"user_id": row["user_id"]},
    )

    return {
        "token": token,
        "user": {
            "user_id": row["user_id"],
            "display_name": row["display_name"],
            "roles": roles,
        },
        "expires_in": settings.human_token_ttl_s,
    }


@router.get("/me")
def get_me(human: HumanIdentity = Depends(require_human)) -> dict[str, Any]:
    """Return the profile and roles of the currently authenticated human."""
    return {
        "user_id": human.user_id,
        "display_name": human.display_name,
        "roles": human.roles,
    }


# Users list endpoint mounted at /api/v1/users per api.md §2.1
users_router = APIRouter(tags=["users"])


@users_router.get("/users")
def list_users(human: HumanIdentity = Depends(require_human)) -> list[dict[str, Any]]:
    """Return all users for the user switcher."""
    conn = get_connection()
    rows = fetchall(conn, "SELECT user_id, display_name, roles_json FROM users ORDER BY user_id")
    return [
        {
            "user_id": r["user_id"],
            "display_name": r["display_name"],
            "roles": json.loads(r["roles_json"]),
        }
        for r in rows
    ]
