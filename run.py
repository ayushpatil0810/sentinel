"""
Sentinel Unified Runner
Runs the full Sentinel application (Frontend UI + Backend API) on http://localhost:8000.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    root_dir = Path(__file__).resolve().parent
    frontend_dir = root_dir / "frontend"
    frontend_dist = frontend_dir / "dist"

    print("=" * 65)
    print("  Sentinel AI Security Control Plane")
    print("=" * 65)

    # 1. Ensure frontend is built
    if not (frontend_dist / "index.html").exists():
        print("\n[1/3] Building frontend UI bundle...")
        env = os.environ.copy()
        env["VITE_API_BASE_URL"] = "/"
        pnpm_cmd = "pnpm.cmd" if sys.platform == "win32" else "pnpm"
        try:
            subprocess.run([pnpm_cmd, "run", "build"], cwd=frontend_dir, env=env, check=True)
        except Exception:
            # Fall back to npm
            npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
            subprocess.run([npm_cmd, "run", "build"], cwd=frontend_dir, env=env, check=True)
    else:
        print("\n[1/3] Frontend assets ready.")

    # 2. Seed database if missing or empty
    print("[2/3] Checking synthetic database...")
    db_file = root_dir / "sentinel.db"
    subprocess.run(
        [sys.executable, str(root_dir / "seed" / "seed.py"), "--if-empty", "--db", str(db_file)],
        cwd=root_dir,
        check=True,
    )

    # 3. Start unified FastAPI server
    print("[3/3] Starting Sentinel on http://localhost:8000 ...")
    print("\n" + "=" * 65)
    print("  Application URL:   http://localhost:8000")
    print("  Login & Personas:  http://localhost:8000/login")
    print("  User Portal:       http://localhost:8000/user")
    print("  Admin Console:     http://localhost:8000/admin")
    print("  API Docs (Swagger):http://localhost:8000/docs")
    print("=" * 65 + "\n")

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "backend.app.main:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
    ]
    subprocess.run(cmd, cwd=root_dir)


if __name__ == "__main__":
    main()
