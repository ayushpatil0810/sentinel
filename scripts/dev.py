"""
One-command development runner for Sentinel (runs backend and frontend concurrently).
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time


def main() -> None:
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    frontend_dir = os.path.join(root_dir, "frontend")

    env = os.environ.copy()
    env["SENTINEL_DB"] = env.get("SENTINEL_DB", "sentinel.db")
    env["SENTINEL_API"] = env.get("SENTINEL_API", "http://localhost:8000")
    env["VITE_API_BASE_URL"] = env.get("VITE_API_BASE_URL", "/")

    print("Starting Sentinel backend on http://localhost:8000 ...")
    backend_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "backend.app.main:app",
        "--reload",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
    ]
    backend_proc = subprocess.Popen(backend_cmd, cwd=root_dir, env=env)

    print("Starting Sentinel frontend on http://localhost:8443 ...")
    pnpm_cmd = "pnpm.cmd" if sys.platform == "win32" else "pnpm"
    frontend_cmd = [pnpm_cmd, "run", "dev"]
    frontend_proc = subprocess.Popen(frontend_cmd, cwd=frontend_dir, env=env)

    try:
        while True:
            time.sleep(0.5)
            if backend_proc.poll() is not None:
                print("Backend stopped.")
                break
            if frontend_proc.poll() is not None:
                print("Frontend stopped.")
                break
    except KeyboardInterrupt:
        print("\nStopping Sentinel...")
    finally:
        for p in (backend_proc, frontend_proc):
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                with contextlib.suppress(Exception):
                    p.kill()


if __name__ == "__main__":
    main()
