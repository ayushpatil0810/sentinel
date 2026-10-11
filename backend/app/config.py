"""
Application configuration loaded from environment variables.

All secrets default to demo-only values so the app starts without configuration.
Set proper values in production via environment or docker-compose.yml.
"""

from __future__ import annotations

import os

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    db: str = "sentinel.db"

    # Demo mode: enables /api/v1/demo/* and the tamper button (architecture.md §7)
    demo_mode: bool = False

    # Signing keys (four distinct keys — architecture.md §3)
    human_key: str = "demo-human-key-change-me"
    approval_key: str = "demo-approval-key-change-me"
    exec_key: str = "demo-exec-key-change-me"
    agent_pepper: str = "demo-pepper-change-me"

    # LLM mock mode (LA-03): ok | says_safe_always | timeout | garbage | down
    llm_mode: str = "ok"

    # OpenAI & LLM Provider Configuration
    openai_api_key: str = Field(
        default_factory=lambda: os.environ.get("OPENAI_API_KEY", os.environ.get("SENTINEL_OPENAI_API_KEY", "")),
    )
    openai_model: str = Field(
        default_factory=lambda: os.environ.get("OPENAI_MODEL", os.environ.get("SENTINEL_OPENAI_MODEL", "gpt-4o-mini")),
    )
    llm_timeout_seconds: float = Field(
        default_factory=lambda: float(os.environ.get("LLM_TIMEOUT_SECONDS", os.environ.get("SENTINEL_LLM_TIMEOUT_SECONDS", "3.0"))),
    )

    # Runtime modes: live | simulation (agent), live | rules_only (guard)
    agent_mode: str = Field(
        default_factory=lambda: os.environ.get("SENTINEL_AGENT_MODE", os.environ.get("AGENT_MODE", "simulation")),
    )
    guard_mode: str = Field(
        default_factory=lambda: os.environ.get("SENTINEL_GUARD_MODE", os.environ.get("GUARD_MODE", "live")),
    )

    # Random seed for deterministic data generation (SD-07)
    seed: int = 1337

    # Human token TTL in seconds
    human_token_ttl_s: int = 28800  # 8 hours

    # Testing flag: used by conftest to detect test runs
    testing: bool = False

    model_config = {"env_prefix": "SENTINEL_", "case_sensitive": False}


# Module-level singleton; tests may monkeypatch attributes
settings = Settings()

