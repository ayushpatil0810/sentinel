# Sentinel: UI Specification

React 18, Vite, Cytoscape.js. Polling every 2 s (MVP), SSE later (Stretch). Two role-based dashboards: **User Dashboard** (for Requesters and Approvers) and **Admin Dashboard** (for Admins). Requirement IDs `UI-xx` are tested by T-UI-01 and by the replay (T-E2E-01).

## 0. Shell, auth, and global behavior (UI-10, MVP)

| Element | Behavior |
| --- | --- |
| **Authentication & Routing** | Seeded login screen (`/login`) accepts seeded users (`alice`, `bob`, `admin`, `dana` with password `demo`). On login, routes by role: `requester` and `approver` to User Dashboard (`/user`), `admin` to Admin Dashboard (`/admin`). Unauthenticated requests redirect to `/login`. |
| **Demo Quick Switch** | Behind `DEMO_MODE=1`: Quick-switch buttons appear on the login card and top bar allowing one-click role switching. When `DEMO_MODE=0`, quick-switcher is hidden and standard login is enforced. |
| **Top bar** | Product title, active user name, role chips, Mode badges, Kill the LLM toggle (admin only), policy/graph version, ledger verify dot, and Logout button. |
| **Agent Mode Badge** | Displays `AGENT: LIVE` in green or `AGENT: SIMULATED` in amber. Reflects runtime `agent_mode` and auto-fallback state. |
| **Guard Mode Badge** | Displays `GUARD: LIVE` in purple or `GUARD: RULES ONLY` in grey. Reflects runtime `guard_mode`. |
| **Kill the LLM toggle** | Switch in the top bar (admin only). Calls `POST /llm/mode` (`ok` or `down`). Dropdown exposes other modes (`says_safe_always`, `timeout`, `garbage`). Badge shows `LLM: ok` or `LLM: DOWN, rules only`. |
| Session badge | Current session ID and taint level: `clean` (green), `untrusted_present` (amber), `flagged` (red). Click shows `taint_reasons`. |
| Demo banner | Shown only when `DEMO_MODE=1`: "Demo mode: side effects are simulated". |
| Untrusted Text Escaping | All text originating from users, tools, reviews, web pages, or action arguments is strictly escaped before rendering. No raw HTML injection. |
| Errors & Loading | Toast notifications with error code, message, and copyable `request_id`. Skeleton rows during load. |

Outcome colors: `allow` green, `sanitize` blue, `hold` and `escalate` amber, `block` red. Decision path chip: `rules` grey, `rules+llm` purple, `fallback` orange. Agent source chip: `live` green, `simulated` amber.

## 1. Role-Based Dashboards

### 1.1 User Dashboard (`/user`) — For Requesters & Approvers

The User Dashboard combines agent interaction, personal request tracking, and the approvals queue:

| Section | Component | Description |
| --- | --- | --- |
| **SupportBot Chat (UI-01)** | Agent Sandbox | Chat interface with SupportBot. Each turn displays the `LIVE` or `SIMULATED` badge, inline decision chips (outcome, rule IDs, decision path), and sanitized text markers (`[removed by Sentinel: ...]`). Includes session selector, "New Session" button, "Load Poisoned Review" menu, and fake outbox tabs (Emails, DB operations). |
| **My Requests & Status** | Requests Feed | Table of all actions submitted in the user's sessions. Displays action type, arguments excerpt, outcome (`allow`, `hold`, `block`), status (`decided`, `executed`, `execution_failed`), decision path, and link to approval if held. |
| **Approvals Queue (UI-03)** | Approvals Panel | Visible to users with role `approver` (Bob, Admin, Dana). Lists pending action holds and ingress reviews. Detail panel shows exact arguments, advisory LLM summary, rule IDs, taint, and blast radius. Approve and Reject buttons with comments. Disabled with explanatory message if active user is the requester (self-approval prohibited). |

### 1.2 Admin Dashboard (`/admin`) — For Admins

The Admin Dashboard houses administrative control, security policy, access modeling, auditing, and LLM configuration:

| Section | Screen | Description |
| --- | --- | --- |
| **LLM Settings & Controls (UI-11)** | LLM Settings | Admin-only panel to manage AI runtime: <br>• Mode switches: `AGENT_MODE` (`live` vs `simulation`) and `GUARD_MODE` (`live` vs `rules_only`). <br>• Active model display (`gpt-4o-mini`) and timeout configuration. <br>• **Test Connection** button: sends diagnostic ping to provider, displays round-trip latency and health. <br>• **Kill the LLM** mode selector (`ok`, `down`, `timeout`, `garbage`, `says_safe_always`). |
| **Policy Editor (UI-07)** | Policy Management | Structured rule editor, threshold controls, ingress table (3x6 matrix). Invariant lint checks. Diff viewer. "Propose Change" button with explicit label: "Propose (a second admin must approve)". |
| **Attack Graph (UI-04)** | BreachPath Canvas | Cytoscape attack graph visualization with entry points, derived badges, and sensitive asset highlights. Routes list with max-depth control (1..8). Remediation suggestions with non-mutating preview and ledgered apply. |
| **Registries** | Agent & Action Registries | Read-only inspection of registered agents (status, allowed actions) and action types (schemas, sensitivities, record limits). |
| **Audit Ledger (UI-08)** | Immutable Ledger | Full ledger event table with seq, timestamp, module, event type, outcome, decision path, and short hash. Row drawer with redacted payload. **Verify Chain** button. Admin-only **Tamper with row (demo only)** button behind `DEMO_MODE=1`. |
| **Benchmark (UI-06)** | PromptShield Benchmark | Benchmark suite execution on held-out test split. Confusion matrix, precision, recall, F1, false-positive rate with Wilson intervals. Side-by-side comparison tabs for rules-only vs rules+llm. Full list of misses and false positives. |
| **Test Report (UI-09)** | Automated Test Suite | Live test runner (`make test`) and report view grouped by requirement IDs. Untested requirements list (must be empty). |
| **PromptShield Lab (UI-05)** | Security Lab | Interactive ingress testing tool with presets, detector finding breakdowns, and sanitization re-scan verification. |

## 2. Shared components

`OutcomeChip`, `PathChip`, `AgentSourceBadge`, `RuleChip`, `TaintBadge`, `JsonView` (read-only, copy, highlights), `HashText` (truncate, copy), `Toast`, `ConfirmDialog`, `RoleGate` (renders explanation when user lacks role), `EmptyState`, `ErrorBanner`.

## 3. Data fetching rules

* Poll `/decisions?since_seq=` and `/approvals?status=pending` every 2 s while visible.
* Poll `/api/v1/system/status` periodically to update mode badges and health.
* Never cache `/ledger/verify`. Recompute on explicit click.
* Mutations disable their button until the response returns and show server error message on failure.
* The UI never constructs agent-plane requests directly. All sandbox chat actions route through `/api/v1/sandbox/*`.

## 4. Acceptance checklist (T-UI-01 and manual)

1. Seeded login routes `alice` and `bob` to `/user`, and `admin` and `dana` to `/admin`.
2. Quick-switch is visible only when `DEMO_MODE=1`.
3. Agent Sandbox renders `AGENT: LIVE` or `AGENT: SIMULATED` badge matching runtime state.
4. If live agent provider fails, UI automatically displays `AGENT: SIMULATED` badge.
5. Approvals queue displays exact arguments and marks LLM summary as "advisory".
6. Self-approval shows server-side refusal with explanation.
7. Admin LLM Settings allows toggling `agent_mode` and `guard_mode`, and "Test Connection" displays latency.
8. Non-admins navigating to `/admin` receive access denied / 403 error.
9. Attack Graph renders routes, derived badges, and remediation diffs.
10. Audit Ledger verify button turns green on valid chain and red on tampered row.
11. Untrusted input and tool outputs are strictly HTML-escaped.
