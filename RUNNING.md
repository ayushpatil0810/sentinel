# Running Sentinel: Complete Instruction Guide

**Sentinel** is a security control plane for AI agents combining **PromptShield** (input screening), **ActionGate** (post-model action authorization), and **BreachPath** (graph-based reachability modeling) with an append-only, hash-chained audit ledger.

---

## 1. Quick Start with Docker (Recommended)

This is the fastest, one-command setup for judges and evaluators. It builds both the React frontend and FastAPI backend inside a multi-stage container and seeds the database automatically.

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) & Docker Compose (v2+)

### Run Command

```bash
docker compose up --build
```

### Access Points
- **Web UI & Control Plane:** [http://localhost:8000](http://localhost:8000)
- **Health Check:** [http://localhost:8000/health](http://localhost:8000/health)
- **Ledger Verification:** [http://localhost:8000/ledger/verify](http://localhost:8000/ledger/verify)
- **Interactive OpenAPI Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

*Note:* On initial startup, the database seeds deterministically with seed `1337` (4 users, 2 agents, default policy v1, access graph v2, and 300 customer mock records). Subsequent starts retain data in `./data`.

---

## 2. Local Development Setup (Without Docker)

If you prefer to run the backend and frontend directly on your host machine:

### Prerequisites
- **Python:** 3.11+ (Python 3.12 recommended)
- **Node.js:** 20+
- **pnpm:** 9+ (Install via `npm install -g pnpm` or `corepack enable`)
- **make:** Standard build tools (or run the equivalent Python commands on Windows)

### Step 1: Install Dependencies

```bash
make setup
```
*Equivalent manual commands:*
```bash
pip install -r requirements.txt
cd frontend && pnpm install && cd ..
```

### Step 2: Seed the Database

```bash
make seed
```
*Equivalent manual command:*
```bash
python seed/seed.py --db sentinel.db
```
This generates the initial deterministic state with ledger sequence 1 (`policy.activated`), sequence 2 (`graph.uploaded`), and sequence 3 (`graph.derived_entry_points`).

### Step 3: Start Development Servers

```bash
make dev
```
*Equivalent manual command:*
```bash
python scripts/dev.py
```
This starts both processes concurrently:
- **Backend API:** [http://localhost:8000](http://localhost:8000) (auto-reload enabled)
- **Frontend App:** [http://localhost:5173](http://localhost:5173) (or `http://localhost:8443` depending on port availability)

---

## 3. Demo Credentials & User Roles

Sentinel enforces **two strict authentication planes**: the *Agent Plane* (`/agent/v1`) and the *Human Plane* (`/api/v1`). Agent tokens cannot access human-plane administration endpoints.

Sign in using the user switcher in the top-right corner of the web interface (all default passwords are `demo`):

| User | Password | Roles | Capabilities |
| :--- | :--- | :--- | :--- |
| **Alice** | `demo` | `requester` | Initiates agent sessions, views Sandbox, loads test reviews |
| **Bob** | `demo` | `approver` | Reviews pending action proposals, approves / rejects actions |
| **Admin** | `demo` | `admin`, `approver` | Edits policies, applies BreachPath graph remediations, runs tests, tampers rows (demo) |
| **Dana** | `demo` | `admin`, `approver` | Secondary admin for two-person integrity checks on policy changes |

---

## 4. Running the 5-Minute Scripted Replay

Sentinel includes an interactive 8-step replay scenario (`demo-v1`) demonstrating how the three modules coordinate to stop prompt injection and unauthorized exfiltration:

1. Open [http://localhost:8000](http://localhost:8000) (or `http://localhost:5173` in local dev).
2. Select **Alice** in the user switcher.
3. Navigate to **Agent Sandbox**.
4. In the replay bar at the top, click **Next Step** to step through:
   - **S1 (Attack Graph):** View 7 attack routes from input sources to Customer DB; notice `derived` tool badges (`X-03`).
   - **S2 (Poisoned Review):** Load customer review `rv-p2` containing prompt injection attempting to leak the customer list.
   - **S3 (PromptShield Defense):** PromptShield sanitizes the directive and exfiltration targets (`PS-07`), raising session taint from `clean` to `flagged` (`PS-10`).
   - **S4 (ActionGate Hold):** SupportBot attempts to email customer records; ActionGate evaluates the policy and **holds** the action for human review (`AG-R-H02`).
   - **S5 (Self-Approval Refusal & Bob Approval):** Alice attempts to approve her own request and is refused (`AG-07`). Switch to **Bob** to reject or approve safely.
   - **S6 (BreachPath Remediation):** Switch to **Admin**, view remediation candidates, and preview/apply the removal of the direct read edge.
   - **S7 (LLM Fallback):** Toggle LLM to `down` or `timeout`. Gating decisions still evaluate safely using rules, recording `decision_path = fallback` (`AG-09`).
   - **S8 (Ledger Tamper Demonstration):** On the **Audit Ledger** screen, click **Tamper with row (demo only)** to simulate an insider DB modification. Click **Verify Chain** to see instant cryptographic proof of tampering (`LG-03`).

---

## 5. Automated Tests, Linters, and Benchmarks

### Full Backend Test Suite (98/98 Tests)
```bash
make test
```
*Manual command:*
```bash
pytest backend/tests -v
```
Generates `reports/last_run.json` containing test results mapped by requirement ID (`AG`, `BP`, `PS`, `X`, `PE`, `LG`, `LA`, `SS`, `AU`, `SD`, `DEMO`).

### Fast Unit Tests Only
```bash
make test-fast
```
*Manual command:*
```bash
pytest backend/tests -v -m "not e2e and not bench"
```

### Linters & Type Checking
```bash
make lint
```
*Manual commands:*
```bash
ruff check backend seed scripts
mypy backend/app seed scripts
pnpm --dir frontend exec tsc --noEmit
```

### PromptShield Benchmark Run
```bash
make bench
```
*Manual command:*
```bash
python -m backend.app.promptshield.bench --split test --out reports/benchmark.json
```
Evaluates the detector pipeline against the 40 held-out test cases, reporting accuracy, precision, recall, and $F_1$ score honestly.

---

## 6. Troubleshooting & Resetting

### Resetting to Fresh Seed State
If a test run or manual tamper modifies the database:
```bash
make seed
```
This drops and recreates `sentinel.db` with ledger head sequence 3.

### Verifying Ledger Integrity via cURL
```bash
curl http://localhost:8000/ledger/verify
```
Expected output on clean database:
```json
{"valid": true, "checked": 3, "first_broken_seq": null, "reason": null, "detail": null}
```

### Docker Port Conflict
If port `8000` is already in use by another service on your host, edit `docker-compose.yml`:
```yaml
ports:
  - "8080:8000"
```
Then visit `http://localhost:8080`.
