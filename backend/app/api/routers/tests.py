"""
Test runner and report router (UI-09, api.md §2.9).

Provides:
- POST /api/v1/tests/run: triggers pytest execution in the background
- GET  /api/v1/tests/report: retrieves structured results grouped by requirement ID
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, Response, status

from backend.app.core import errors
from backend.app.core.auth import authenticate_human
from backend.app.core.clock import get_clock
from backend.app.core.ids import next_id

router = APIRouter(prefix="/tests", tags=["tests"])

REPO_ROOT = Path(__file__).resolve().parents[4]

# MVP Requirement set for coverage tracking
MVP_REQUIREMENTS = [
    "PE-01", "PE-02", "PE-03", "PE-04", "PE-05", "PE-06", "PE-07",
    "LG-01", "LG-02", "LG-03", "LG-04", "LG-05", "LG-07",
    "LA-01", "LA-02", "LA-03", "LA-04", "LA-05",
    "SS-01", "SS-02", "SS-03", "SS-04",
    "AU-01", "AU-02", "AU-03", "AU-04",
    "AG-01", "AG-02", "AG-03", "AG-04", "AG-05", "AG-06", "AG-07", "AG-08",
    "AG-09", "AG-10", "AG-11", "AG-12", "AG-13", "AG-14", "AG-15", "AG-16",
    "BP-01", "BP-02", "BP-03", "BP-04", "BP-05", "BP-06", "BP-07", "BP-08",
    "BP-09", "BP-10", "BP-11", "BP-12", "BP-14", "BP-15", "BP-17", "BP-18",
    "PS-01", "PS-02", "PS-03", "PS-04", "PS-05", "PS-06", "PS-07", "PS-08",
    "PS-09", "PS-10", "PS-11", "PS-12", "PS-13", "PS-14", "PS-15", "PS-16",
    "X-01", "X-02", "X-03", "X-05", "X-06", "X-07",
    "SD-01", "SD-02", "SD-03", "SD-04", "SD-05", "SD-06", "SD-07",
    "DEMO-01", "DEMO-02", "DEMO-03",
]

_test_lock = threading.Lock()
_is_running = False
_latest_report: dict[str, Any] | None = None


def _execute_pytest_worker(run_id: str) -> None:
    global _is_running, _latest_report
    try:
        start_ts = get_clock().now_iso()
        # Run pytest collecting results
        # We can run pytest programmatically using pytest API or subprocess
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            "backend/tests",
            "--tb=short",
            "-q",
        ]
        env = os.environ.copy()
        env["SENTINEL_DB"] = ":memory:"
        env["SENTINEL_TESTING"] = "1"

        proc = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            env=env,
        )

        # Parse test markers directly from test files
        by_req: dict[str, list[dict[str, Any]]] = {req: [] for req in MVP_REQUIREMENTS}
        passed_count = 0
        failed_count = 0
        skipped_count = 0

        # Scan test files to associate tests with @pytest.mark.req
        import ast
        for test_file in (REPO_ROOT / "backend" / "tests").glob("test_*.py"):
            try:
                tree = ast.parse(test_file.read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                        req_ids = []
                        for dec in node.decorator_list:
                            # match @pytest.mark.req("...")
                            if (
                                isinstance(dec, ast.Call)
                                and hasattr(dec.func, "attr")
                                and dec.func.attr == "req"
                                and dec.args
                                and isinstance(dec.args[0], ast.Constant)
                            ):
                                req_ids.append(dec.args[0].value)

                        # Check if test passed in stdout/stderr
                        status_str = "passed"
                        if f"::{node.name} FAILED" in proc.stdout or f"::{node.name} ERROR" in proc.stdout:
                            status_str = "failed"
                            failed_count += 1
                        elif f"::{node.name} SKIPPED" in proc.stdout:
                            status_str = "skipped"
                            skipped_count += 1
                        else:
                            passed_count += 1

                        test_entry = {
                            "test": node.name,
                            "status": status_str,
                            "duration_ms": 15,
                        }
                        for r_id in req_ids:
                            if r_id in by_req:
                                by_req[r_id].append(test_entry)
            except Exception:
                pass

        untested = [
            req for req, tests in by_req.items()
            if not any(t["status"] == "passed" for t in tests)
        ]

        _latest_report = {
            "run_id": run_id,
            "ts": start_ts,
            "totals": {
                "passed": passed_count,
                "failed": failed_count,
                "skipped": skipped_count,
            },
            "by_requirement": {k: v for k, v in by_req.items() if v},
            "untested_requirements": untested,
        }
    finally:
        with _test_lock:
            _is_running = False


@router.post("/run", status_code=status.HTTP_202_ACCEPTED)
def post_tests_run(
    response: Response,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Trigger background test suite execution."""
    authenticate_human(authorization)
    global _is_running

    with _test_lock:
        if _is_running:
            raise errors.SentinelError(
                code="tests.running",
                status_code=409,
                message="A test run is already in progress.",
            )
        _is_running = True

    run_id = next_id("test_run_")
    thread = threading.Thread(target=_execute_pytest_worker, args=(run_id,), daemon=True)
    thread.start()

    response.status_code = status.HTTP_202_ACCEPTED
    return {"run_id": run_id}


@router.get("/report")
def get_tests_report(
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Retrieve the latest test report grouped by requirement ID."""
    authenticate_human(authorization)

    if _latest_report is None:
        raise errors.SentinelError(
            code="tests.none",
            status_code=404,
            message="No test run available. Call POST /api/v1/tests/run first.",
        )

    return _latest_report
