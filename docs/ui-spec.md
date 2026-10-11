# Sentinel: UI Specification

React 18, Vite, Cytoscape.js. Polling every 2 s (MVP), SSE later (Stretch). Build order follows the brief: **Sandbox, Approvals, Attack Graph, Audit, Benchmark first**. Everything else can be simple forms. Requirement IDs `UI-xx` are tested by T-UI-01 and by the replay (T-E2E-01).

## 0. Shell and global behavior (UI-10, MVP)

| Element | Behavior |
| --- | --- |
| Top bar | Product name, **user switcher** (Alice, Bob, Admin, Dana: calls `POST /auth/login` with password `demo`, keeps the token in memory), role chips, policy version, graph version, ledger head with a small verify dot (green valid, red broken, grey unknown, refreshed on load and after Verify) |
| **Kill the LLM** toggle | Switch in the top bar. Calls `POST /llm/mode` (`ok` or `down`). A dropdown exposes the other modes (`says_safe_always`, `timeout`, `garbage`). Badge shows `LLM: ok` or `LLM: DOWN, rules only` in amber. |
| Session badge | Current session ID and taint level: `clean` (green), `untrusted_present` (amber), `flagged` (red). Click shows `taint_reasons`. |
| Demo banner | Shown only when the server reports demo mode: "Demo mode, side effects are simulated" |
| Navigation | Left rail in the order of the table in section 1 |
| Errors | API errors render a toast with `message` and `code`, and keep `request_id` copyable. Network failure shows a persistent banner with Retry. 403 on a role-gated action shows what role is needed. |
| Loading | Skeleton rows, never a blank screen |
| Accessibility | Outcome is always text plus color (never color only). Keyboard focus visible. Tables have captions. |

Outcome colors: `allow` green, `sanitize` blue, `hold` and `escalate` amber, `block` red. Decision path chip: `rules` grey, `rules+llm` purple, `fallback` orange.

## 1. Screens

| # | Screen | ID | Pri |
| --- | --- | --- | --- |
| 1 | Agent Sandbox | UI-01 | MVP |
| 2 | Live Decisions | UI-02 | MVP |
| 3 | Approvals | UI-03 | MVP |
| 4 | Attack Graph | UI-04 | MVP |
| 5 | PromptShield Lab | UI-05 | MVP |
| 6 | Benchmark | UI-06 | MVP |
| 7 | Policy Editor | UI-07 | MVP |
| 8 | Audit Ledger | UI-08 | MVP |
| 9 | Test Report | UI-09 | MVP |

### UI-01 Agent Sandbox

**Purpose:** Chat with SupportBot, run the scripted replay, see simulated side effects.

| Region | Components |
| --- | --- |
| Left: chat | Message list (user, agent, system cards), input box, Send. Each agent turn shows inline decision chips (outcome, rule IDs, path). Sanitized text shows `[removed by Sentinel: ...]` markers highlighted. |
| Center: session | "New session" button (calls `POST /sessions` for the active user), session badge, **Load poisoned review** menu (the five `rv-p*` styles), "Reset sandbox" (admin) |
| Right: fake outbox | Two tabs: **Emails** and **DB operations**. Each item labeled "SIMULATED, nothing was sent". Empty state: "Nothing has left the sandbox." |
| Bottom: replay bar | **Scripted replay** panel: step list S1..S8 with status (pending, running, matched, mismatch), **Next step** and **Auto-play** (3 s pacing), "Expected vs actual" drawer per step |

Interactions: sending a message calls `POST /sandbox/message`. Loading a review calls `POST /sandbox/load-review`. A `hold` result shows a link to the approval. A `block` shows the rule ID and reason.

States: no session (prompt to create one), LLM down (amber badge, still works), 503 `ledger.unavailable` (red card "Decision could not be recorded, nothing was executed").

### UI-02 Live Decisions

Feed of every ingress and action decision, newest first. Columns: time, module, subject, input or action summary, **outcome**, reason, rule IDs (chips with tooltip text of the rule reason), path, session taint at decision time. Filters: module, outcome, path, subject. Row click opens a drawer with the redacted payload and the ledger entry (`GET /ledger/{seq}`). Pause/resume. Empty state "No decisions yet. Send a message in the Sandbox." Error state: banner with Retry.

### UI-03 Approvals

| Region | Components |
| --- | --- |
| Queue (left) | Tabs Pending, Decided. Items show kind (action, ingress review, policy change), requester, age, expiry countdown, summary (`email.send to attacker@evil.example`) |
| Detail (right) | **Exact arguments** in a read-only JSON view with the target highlighted, fingerprint (first 12 chars, copy for full), rule IDs with reasons, session taint, blast radius chip, **LLM summary labeled "advisory"** (or "unavailable, decided by rules"). For policy changes: the structural diff. For ingress reviews: redacted findings and the text with spans highlighted. |
| Actions | **Approve** and **Reject** with an optional comment. Disabled with an explanation when the active user is the requester or lacks the role. Clicking Approve as the requester still sends the request, so the refusal is real and ledgered (needed for demo step 5). |

States: empty ("No held actions"), expired (greyed, "Expired, the agent must re-propose"), already decided (read-only with approver and signature digest).

### UI-04 Attack Graph

| Region | Components |
| --- | --- |
| Canvas (center) | Cytoscape graph. Node shapes by type (user person, role badge, service rounded box, agent hexagon, tool diamond, asset cylinder, external cloud). **Entry points** have a green ring. **Derived entry points** show a `derived` badge (X-03). **Sensitive assets** have a red fill scaled by sensitivity. Reverse-traversal edges render with an arrow in the traversal direction and a dashed style, with tooltip "stored as consumer to source". Selecting a route highlights its nodes and edges and dims the rest. Layout: breadth-first from entry points. Cycle edges are drawn curved. |
| Left panel | **Routes** list: path ID, entry, asset, length, a one-line summary. Truncation warning banner when `truncated`. **Max depth** control (stepper 1..8, default 4) that recomputes on change. Graph version and a "model last changed" timestamp. |
| Route detail | Click a route: ordered steps with edge type chips and the plain-language sentence per step |
| Right panel | **Remediation** list: ranked suggestions (edge, routes broken, rationale). **Preview** shows removed, remaining, new inline without changing anything. **Apply** (admin only, confirmation dialog) is a ledgered change. |
| Bottom: diff panel | After any change: three columns **Removed**, **Remaining**, **New** with path IDs and summaries. A banner when `comparison_reliable` is false. |
| Toolbar | Upload JSON (admin), **Validate only**, Download current model, Blast radius lookup (click a node to see its card), Stretch: CSV upload, edit form |

Upload errors render as a list: location, code, plain message ("`/edges/1/dst`: Edge e-bad refers to destination svc:ghost, which is not defined..."). The graph is unchanged and a banner says so.

States: empty graph ("Upload a model to begin"), no routes ("No routes within depth 4. Increase depth or mark entry points"), unavailable (error with Retry, blast shows `high`).

### UI-05 PromptShield Lab

Left: text area, **source tier** select (`user`, `retrieved_document`, `tool_output`), presets for the five poisoned reviews, benign tricky cases, and canary variants. Right: **Outcome** card (outcome, reason, rule IDs, path), **Findings** table (type, confidence, detector, encoding, span, redacted evidence), original text with spans highlighted, **sanitized output** with markers, and a re-scan result ("clean" or residual findings). A toggle shows the effect of the LLM signal (rules only vs with LLM). Lab scans do not change session taint, and the screen says so. Empty and error states as elsewhere.

### UI-06 Benchmark

Run button ("Run on held-out test split"), run metadata (policy version, time, mode). Cards: confusion matrix, precision, recall, F1, **false-positive rate**, each with Wilson 95% interval. Charts: per-category recall, per-tier recall, direct vs indirect. Table **Misses** and table **False positives** (ID, category, tier, excerpt, findings, explanation). Sanitize quality card. A permanent note: "Only the held-out test split is reported. Misses are listed, not hidden." Side-by-side tabs for rules-only and rules plus LLM. Empty state: "No run yet." The page never shows test-case text from before a run is requested by an explicit click.

### UI-07 Policy Editor

Left: versions list (version, creator, approver, activated time). Center: structured editor for rules (table with inline editing of outcome, reason, and the condition JSON), thresholds, and the ingress outcome table (a 3 x 6 grid of dropdowns, pinned cell locked with a lock icon and tooltip). Right: **diff** against the active version, lint messages (floor violations in red). **Propose change** button calls `POST /policy/proposals` and navigates to the pending approval. The button text is explicit: "Propose, a second admin must approve". Role-gated: non-admins see read-only. States: lint failure (list), stale base (409, reload prompt).

### UI-08 Audit Ledger

Table with columns seq, time, module, event, subject, outcome, reason, rules, path, policy version, short hash. Filters: module, event type, subject, outcome. Row drawer: full entry, redacted payload, `prev_hash` and `hash`. **Verify chain** button shows result inline: green "Valid, N entries checked" or red "BROKEN at seq 17: hash mismatch", with that row highlighted and subsequent rows marked "after break". A clearly marked, red-bordered **Tamper with row (demo only)** button per row, visible only in demo mode and to admins, with a dialog stating that it bypasses the append API to simulate an insider. Stretch: Export checkpoint.

### UI-09 Test Report

Last pytest run (`GET /tests/report`): totals, run time, **Run tests** button. Grouped by requirement ID (AG, BP, PS, X, PE, LG, LA, SS, AU, FI), each group expandable to test names, status, duration. A "Requirements without a passing test" list that must be empty for MVP. Filter failed. Stretch tests shown as skipped with a tag. Empty state: "No run yet. Run tests."

## 2. Shared components

`OutcomeChip`, `PathChip`, `RuleChip` (tooltip with rule reason from the policy), `TaintBadge`, `JsonView` (read-only, copy, highlights), `HashText` (truncate, copy), `Toast`, `ConfirmDialog`, `RoleGate` (renders the explanation when disabled), `EmptyState`, `ErrorBanner`.

## 3. Data fetching rules

* Poll `/decisions?since_seq=` and `/approvals?status=pending` every 2 s while the screen is visible.
* Never cache `/ledger/verify`. Recompute on click.
* Mutations disable their button until the response returns and show the server `message` on error.
* The UI never constructs agent-plane requests. All agent actions in the Sandbox go through `/api/v1/sandbox/*` (D-03).

## 4. Acceptance checklist (T-UI-01 and manual)

1. Each screen renders on a fresh seed with a meaningful empty state.
2. Approvals shows the exact arguments equal to those stored, and the advisory label.
3. Self-approval attempt shows the server's refusal text and the ledger gains `approval.refused.self`.
4. Attack Graph shows 7 routes at depth 4, 2 at depth 2, 8 at depth 5, derived badges on two tools, and an error list for `bad_graph.json`.
5. Remediation preview then apply shows the three-column diff with the expected path IDs.
6. LLM toggle flips the badge, and the next decision shows the `fallback` chip.
7. Verify is green on a clean ledger and red naming the tampered seq after the tamper action.
8. Tamper button is absent when demo mode is off.
