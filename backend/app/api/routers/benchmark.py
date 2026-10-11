"""
PromptShield benchmark endpoints (PS-08, api.md §2.7).

- POST /api/v1/benchmark/run: Runs the test split (any authenticated human).
- GET /api/v1/benchmark/latest: Returns latest test split run report.
- GET /api/v1/benchmark/cases?split=dev: Inspect dev cases; test split is hidden (403).
"""

from __future__ import annotations

import json
import threading
from typing import Any, cast

from fastapi import APIRouter, Depends, Query

from backend.app.core import ledger
from backend.app.core.auth import HumanIdentity, require_human
from backend.app.core.errors import SentinelError
from backend.app.core.policy import get_engine
from backend.app.db import fetchone, get_connection
from backend.app.promptshield import bench

router = APIRouter(tags=["benchmark"])

_run_lock = threading.Lock()
_is_running = False


@router.post("/benchmark/run")
def run_benchmark_endpoint(
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Run benchmark evaluation on held-out test split (PS-08)."""
    global _is_running
    with _run_lock:
        if _is_running:
            raise SentinelError(
                status_code=409,
                code="benchmark.running",
                message="A benchmark run is already in progress.",
            )
        _is_running = True

    try:
        pol_ver = get_engine().active_version()

        report = bench.run_benchmark(split="test", policy_version=pol_ver)

        ledger.append(
            module="policy",
            event_type="benchmark.run",
            subject=report["run_id"],
            outcome="completed",
            reason=f"Benchmark run on test split completed (F1={report['f1']})",
            rule_ids=[],
            decision_path="rules",
            policy_version=pol_ver,
            payload={
                "run_id": report["run_id"],
                "split": "test",
                "n": report["n"],
                "f1": report["f1"],
                "run_by": human.user_id,
            },
        )

        return {"run_id": report["run_id"], "metrics": report}
    finally:
        with _run_lock:
            _is_running = False


@router.get("/benchmark/latest")
def get_latest_benchmark(
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """Retrieve the most recent benchmark run metrics (PS-08)."""
    conn = get_connection()
    row = fetchone(conn, "SELECT result_json FROM benchmark_runs ORDER BY ts DESC LIMIT 1")
    if not row:
        raise SentinelError(
            status_code=404,
            code="benchmark.none",
            message="No benchmark run has been completed yet.",
        )
    return cast(dict[str, Any], json.loads(row["result_json"]))


@router.get("/benchmark/cases")
def get_benchmark_cases(
    split: str = Query("dev"),
    human: HumanIdentity = Depends(require_human),
) -> dict[str, Any]:
    """
    Retrieve benchmark cases for tuning.
    Test split is strictly hidden (403 benchmark.test_split_hidden).
    """
    if split == "test":
        raise SentinelError(
            status_code=403,
            code="benchmark.test_split_hidden",
            message="Test split cases cannot be inspected via API.",
        )
    if split != "dev":
        raise SentinelError(
            status_code=400,
            code="benchmark.invalid_split",
            message=f"Invalid split '{split}'. Only 'dev' is accessible.",
        )

    if not bench.BENCHMARK_PATH.exists():
        raise SentinelError(
            status_code=500,
            code="benchmark.file_not_found",
            message="Benchmark dataset file is missing.",
        )

    with open(bench.BENCHMARK_PATH, encoding="utf-8") as f:
        all_cases = json.load(f)

    dev_cases = [c for c in all_cases if c.get("split") == "dev"]
    return {
        "split": "dev",
        "total": len(dev_cases),
        "cases": dev_cases,
    }
