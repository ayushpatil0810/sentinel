"""
Registries for ActionGate (AG-01, AG-02, SD-04).

Manages:
  - Agent registry (table `agents`)
  - Action-type registry (table `action_types`)
"""

from __future__ import annotations

import json
from typing import Any, cast

from backend.app.db import fetchall, fetchone, get_connection

ACTION_TYPES_SEED = [
    {
        "action_type": "web.fetch",
        "reversible": True,
        "base_sensitivity": "low",
        "target_field": "/url",
        "target_node_default": "tool:browse_page",
        "target_node_field": None,
        "external_destination_fields": [],
        "record_count": {"mode": "const", "const": 0},
        "max_records_auto": 0,
        "max_records_hard": 0,
        "ingests_untrusted": True,
        "tool_node": "tool:browse_page",
        "output_tier": "retrieved_document",
        "description": "Fetch a web page",
        "arg_schema": {
            "type": "object",
            "required": ["url"],
            "additionalProperties": False,
            "properties": {
                "url": {"type": "string", "pattern": "^https://", "maxLength": 2000},
            },
        },
    },
    {
        "action_type": "reviews.read",
        "reversible": True,
        "base_sensitivity": "low",
        "target_field": "/product_id",
        "target_node_default": "tool:read_reviews",
        "target_node_field": None,
        "external_destination_fields": [],
        "record_count": {"mode": "const", "const": 0},
        "max_records_auto": 0,
        "max_records_hard": 0,
        "ingests_untrusted": True,
        "tool_node": "tool:read_reviews",
        "output_tier": "tool_output",
        "description": "Read reviews for a product",
        "arg_schema": {
            "type": "object",
            "required": ["product_id"],
            "additionalProperties": False,
            "properties": {
                "product_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
        },
    },
    {
        "action_type": "db.read",
        "reversible": True,
        "base_sensitivity": "high",
        "target_field": "/resource",
        "target_node_default": None,
        "target_node_field": "/resource",
        "external_destination_fields": [],
        "record_count": {"mode": "value", "pointer": "/limit"},
        "max_records_auto": 20,
        "max_records_hard": 500,
        "ingests_untrusted": False,
        "tool_node": None,
        "output_tier": None,
        "description": "Query customer records",
        "arg_schema": {
            "type": "object",
            "required": ["resource", "limit"],
            "additionalProperties": False,
            "properties": {
                "resource": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                "fields": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "action_type": "email.send",
        "reversible": False,
        "base_sensitivity": "medium",
        "target_field": "/to/0",
        "target_node_default": "svc:mailer",
        "target_node_field": None,
        "external_destination_fields": ["/to", "/cc", "/bcc"],
        "record_count": {"mode": "const", "const": 0},
        "max_records_auto": 0,
        "max_records_hard": 0,
        "ingests_untrusted": False,
        "tool_node": None,
        "output_tier": None,
        "description": "Send an email",
        "arg_schema": {
            "type": "object",
            "required": ["to", "subject", "body"],
            "additionalProperties": False,
            "properties": {
                "to": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                "subject": {"type": "string", "maxLength": 200},
                "body": {"type": "string", "maxLength": 20000},
                "cc": {"type": "array", "items": {"type": "string"}},
                "bcc": {"type": "array", "items": {"type": "string"}},
                "resource": {"type": "string"},
            },
        },
    },
    {
        "action_type": "db.update",
        "reversible": False,
        "base_sensitivity": "medium",
        "target_field": "/resource",
        "target_node_default": None,
        "target_node_field": "/resource",
        "external_destination_fields": [],
        "record_count": {"mode": "length", "pointer": "/record_ids"},
        "max_records_auto": 10,
        "max_records_hard": 100,
        "ingests_untrusted": False,
        "tool_node": None,
        "output_tier": None,
        "description": "Update account records",
        "arg_schema": {
            "type": "object",
            "required": ["resource", "record_ids", "changes"],
            "additionalProperties": False,
            "properties": {
                "resource": {"type": "string"},
                "record_ids": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"type": "integer"}},
                "changes": {"type": "object"},
            },
        },
    },
    {
        "action_type": "db.delete",
        "reversible": False,
        "base_sensitivity": "high",
        "target_field": "/resource",
        "target_node_default": None,
        "target_node_field": "/resource",
        "external_destination_fields": [],
        "record_count": {"mode": "length", "pointer": "/record_ids"},
        "max_records_auto": 1,
        "max_records_hard": 100,
        "ingests_untrusted": False,
        "tool_node": None,
        "output_tier": None,
        "description": "Delete records",
        "arg_schema": {
            "type": "object",
            "required": ["resource", "record_ids"],
            "additionalProperties": False,
            "properties": {
                "resource": {"type": "string"},
                "record_ids": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"type": "integer"}},
            },
        },
    },
]


def ensure_action_types_seeded() -> None:
    """Ensure standard action types exist in the database."""
    conn = get_connection()
    for at in ACTION_TYPES_SEED:
        conn.execute(
            """INSERT OR IGNORE INTO action_types (action_type, definition_json)
               VALUES (?, ?)""",
            (at["action_type"], json.dumps(at)),
        )
    conn.commit()


def get_agent(agent_id: str) -> dict[str, Any] | None:
    """Fetch agent record from DB."""
    conn = get_connection()
    row = fetchone(
        conn,
        "SELECT agent_id, name, status, allowed_action_types_json, graph_node_id FROM agents WHERE agent_id = ?",
        (agent_id,),
    )
    if not row:
        return None
    return {
        "agent_id": row["agent_id"],
        "name": row["name"],
        "status": row["status"],
        "allowed_action_types": json.loads(row["allowed_action_types_json"]),
        "graph_node_id": row["graph_node_id"],
    }


def list_agents() -> list[dict[str, Any]]:
    """List all agents."""
    conn = get_connection()
    rows = fetchall(conn, "SELECT agent_id, name, status, allowed_action_types_json, graph_node_id FROM agents")
    return [
        {
            "agent_id": r["agent_id"],
            "name": r["name"],
            "status": r["status"],
            "allowed_action_types": json.loads(r["allowed_action_types_json"]),
            "graph_node_id": r["graph_node_id"],
        }
        for r in rows
    ]


def get_action_type(action_type: str) -> dict[str, Any] | None:
    """Fetch action type definition from DB."""
    ensure_action_types_seeded()
    conn = get_connection()
    row = fetchone(
        conn,
        "SELECT action_type, definition_json FROM action_types WHERE action_type = ?",
        (action_type,),
    )
    if not row:
        return None
    return cast(dict[str, Any], json.loads(row["definition_json"]))


def list_action_types() -> list[dict[str, Any]]:
    """List all action types."""
    ensure_action_types_seeded()
    conn = get_connection()
    rows = fetchall(conn, "SELECT action_type, definition_json FROM action_types")
    return [json.loads(r["definition_json"]) for r in rows]


def get_action_type_registry() -> dict[str, Any]:
    """Return dictionary of action_type -> definition."""
    return {at["action_type"]: at for at in list_action_types()}
