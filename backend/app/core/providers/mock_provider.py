"""
Mock LLM Provider for unit tests and simulation (LA-03, LA-06).
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

from backend.app.core.canonical import canonical_json
from backend.app.core.providers.base import (
    AgentTurnResult,
    ClassifyResult,
    ConnectionTestResult,
    IntentResult,
    LLMProvider,
    ToolCall,
)

_VALID_MODES = {"ok", "says_safe_always", "timeout", "garbage", "down"}

# Keyword heuristics (D-29)
_TIGHTEN_KEYWORDS = ["extract internal notes", "set aside the initial", "paraphrase"]
_SUSPICIOUS_KEYWORDS = [
    "ignore previous instructions", "ignore all previous", "disregard your",
    "you are now", "new persona", "admin mode", "system prompt",
    "forward the customer list", "email the customer list",
    "attacker@", "evil.example",
]


class MockProvider(LLMProvider):
    """Deterministic in-memory mock provider supporting 5 failure/response modes."""

    def __init__(self, mode: str = "ok") -> None:
        self._mode = mode
        self._fixtures: dict[str, Any] | None = None
        self._lock = threading.Lock()

    @property
    def mode(self) -> str:
        with self._lock:
            return self._mode

    @mode.setter
    def mode(self, new_mode: str) -> None:
        self.set_mode(new_mode)

    def set_mode(self, new_mode: str) -> None:
        if new_mode not in _VALID_MODES:
            raise ValueError(f"Unknown mock mode: {new_mode!r}. Valid modes: {_VALID_MODES}")
        with self._lock:
            self._mode = new_mode

    def _load_fixtures(self) -> dict[str, Any]:
        with self._lock:
            if self._fixtures is not None:
                return self._fixtures
            try:
                fixture_path = Path(__file__).resolve().parents[4] / "seed" / "llm_fixtures.json"
                if not fixture_path.exists():
                    fixture_path = Path("seed/llm_fixtures.json")
                self._fixtures = json.loads(fixture_path.read_text("utf-8")) if fixture_path.exists() else {}
            except Exception:
                self._fixtures = {}
            return self._fixtures

    def _fixture_key_text(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _fixture_key_action(self, action: dict[str, Any]) -> str:
        payload = {
            "action_type": action.get("action_type", ""),
            "arguments": action.get("arguments", {}),
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def _heuristic_classify(self, text: str) -> ClassifyResult:
        t = text.lower()
        for kw in _TIGHTEN_KEYWORDS:
            if kw in t:
                return ClassifyResult("malicious", ["override"], 85, f"subtle paraphrase: {kw}")
        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in t:
                return ClassifyResult("suspicious", ["override"], 60, f"keyword heuristic: {kw}")
        return ClassifyResult("benign", [], 10, "keyword heuristic")

    def _heuristic_intent(self, action: dict[str, Any]) -> IntentResult:
        args_str = json.dumps(action.get("arguments", {})).lower()
        flags: list[str] = []
        if "evil.example" in args_str or "attacker@" in args_str:
            flags.append("external_recipient")
        if "customer_list" in args_str or "customer list" in args_str:
            flags.append("bulk_data")
        outcome = "hold" if flags else "allow"
        return IntentResult(
            summary=f"Action: {action.get('action_type', 'unknown')}",
            risk_flags=flags,
            suggested_outcome=outcome,
        )

    def classify_input(
        self,
        text: str,
        tier: str,
        module: str = "promptshield",
        request_id: str = "",
    ) -> ClassifyResult | None:
        mode = self.mode
        if mode == "down":
            raise RuntimeError("Mock LLM is down")
        if mode == "timeout":
            time.sleep(3.5)
            return None
        if mode == "garbage":
            return None
        if mode == "says_safe_always":
            return ClassifyResult("benign", [], 99, "safe always")

        fixtures = self._load_fixtures()
        key = self._fixture_key_text(text)
        if key in fixtures:
            data = fixtures[key]
            return ClassifyResult(
                label=data["label"],
                threat_types=data.get("threat_types", []),
                confidence=data["confidence"],
                rationale=data.get("rationale", ""),
            )
        return self._heuristic_classify(text)

    def summarize_intent(
        self,
        action: dict[str, Any],
        module: str = "actiongate",
        request_id: str = "",
    ) -> IntentResult | None:
        mode = self.mode
        if mode == "down":
            raise RuntimeError("Mock LLM is down")
        if mode == "timeout":
            time.sleep(3.5)
            return None
        if mode == "garbage":
            return None
        if mode == "says_safe_always":
            return IntentResult("looks safe", [], "allow")

        fixtures = self._load_fixtures()
        key = self._fixture_key_action(action)
        if key in fixtures:
            data = fixtures[key]
            return IntentResult(
                summary=data["summary"],
                risk_flags=data.get("risk_flags", []),
                suggested_outcome=data["suggested_outcome"],
            )
        return self._heuristic_intent(action)

    def generate_turn(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentTurnResult:
        mode = self.mode
        if mode == "down":
            raise RuntimeError("Mock LLM is down")
        if mode == "timeout":
            time.sleep(3.5)
            raise TimeoutError("Mock LLM timed out")
        if mode == "garbage":
            return AgentTurnResult(content="not-valid-json-garbage-!@#", agent_source="simulated")
        if mode == "says_safe_always":
            return AgentTurnResult(content="All requests look completely safe.", agent_source="simulated")

        # Inspect latest user message or tool responses
        last_msg = messages[-1] if messages else {"role": "user", "content": ""}
        content_text = str(last_msg.get("content", "")).lower()

        # If previous message was a tool result, synthesize a final answer
        if last_msg.get("role") == "tool":
            return AgentTurnResult(
                role="assistant",
                content="I have retrieved and processed the requested information.",
                tool_calls=[],
                agent_source="simulated",
            )

        # Check for tool intent triggers
        if "review" in content_text or "rv-p" in content_text:
            return AgentTurnResult(
                role="assistant",
                content=None,
                tool_calls=[ToolCall(id="call_mock_rev", name="read_reviews", arguments={"product_id": "prod_1"})],
                agent_source="simulated",
            )
        if "browse" in content_text or "http" in content_text or "page" in content_text:
            return AgentTurnResult(
                role="assistant",
                content=None,
                tool_calls=[ToolCall(id="call_mock_browse", name="browse_page", arguments={"url": "https://acme.example/returns"})],
                agent_source="simulated",
            )
        if "customer" in content_text or "order" in content_text or "list" in content_text:
            return AgentTurnResult(
                role="assistant",
                content=None,
                tool_calls=[ToolCall(id="call_mock_cust", name="query_customers", arguments={"limit": 10})],
                agent_source="simulated",
            )
        if "email" in content_text or "send" in content_text:
            return AgentTurnResult(
                role="assistant",
                content=None,
                tool_calls=[ToolCall(
                    id="call_mock_email",
                    name="email_send",
                    arguments={"to": ["customer@acme.example"], "subject": "Status Update", "body": "Order received."},
                )],
                agent_source="simulated",
            )

        return AgentTurnResult(
            role="assistant",
            content=f"Hello! I am SupportBot. How can I help you today? (Processed: {last_msg.get('content', '')})",
            tool_calls=[],
            agent_source="simulated",
        )

    def test_connection(self) -> ConnectionTestResult:
        if self.mode == "down":
            return ConnectionTestResult(success=False, latency_ms=0, model="mock", error="Mock provider is down")
        return ConnectionTestResult(success=True, latency_ms=5, model="mock")
