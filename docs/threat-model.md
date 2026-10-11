# Sentinel: Threat Model

Scope: the Sentinel control plane and the simulated Acme Retail agent. Production authentication, multi-tenancy, and real integrations are non-goals. Honest limits are a feature, so section 6 states what Sentinel does not stop.

## 1. Assets

| ID | Asset | Why it matters | Where it lives |
| --- | --- | --- | --- |
| A1 | Customer data | Confidentiality of PII and order totals | `customers`, mock executors |
| A2 | Canary and secret values | Proof of leakage, and real secrets in a real deployment | `protected_values`, `customers.internal_notes` |
| A3 | Policy | Controls every decision | `policy_versions` |
| A4 | Access graph | Drives blast radius and remediation | `graph_versions` |
| A5 | Ledger | Evidence of what happened | `ledger`, `ledger_payloads` |
| A6 | Approval authority | The only way to release a held action | `approvals`, roles, `APPROVAL_KEY` |
| A7 | Session taint state | Tightening signal for ActionGate | `sessions` |
| A8 | Signing keys | Forge approvals, tokens, human sessions | env vars |

## 2. Adversaries

| ID | Adversary | Capability | Goal |
| --- | --- | --- | --- |
| ADV-1 | Malicious content author | Writes reviews, web pages, tool outputs the agent reads (indirect injection) | Make the agent leak data, change policy, or take actions |
| ADV-2 | Malicious end user | Types prompts (direct injection) | Same, plus extract system prompt and canaries |
| ADV-3 | Curious insider with log or DB access | Edits the SQLite file, the ledger, possibly the policy rows | Hide or alter evidence, loosen policy |
| ADV-4 | Compromised agent | Fully controls the proposed actions and ingress submissions it sends, holds the agent credential | Exfiltrate, escalate, escape taint, bypass approval |
| ADV-5 | Requester trying to self-approve | Legitimate human account with role `requester` | Approve own risky action |
| ADV-6 | Colluding or careless approver | Holds the approver role | Rubber-stamp a harmful action |

## 3. Trust assumptions

* The Sentinel server process, its code, and its keys are trusted. A host compromise defeats everything here.
* The agent is untrusted by design. Sentinel is built so that a fully compromised agent still cannot execute an unapproved side effect.
* Human-plane users are authenticated but individually fallible (ADV-6).
* The LLM, when present, is untrusted input to the engine (section 4.5).

## 4. Attack scenarios, mitigations, residual risk

Each mitigation cites requirement IDs and a test from `test-plan.md`.

| ID | Scenario | Adversary | Mitigation | Test | Residual risk |
| --- | --- | --- | --- | --- | --- |
| TM-01 | Poisoned review tells the agent to forward the customer list to an outside address | ADV-1 | PS-04, PS-12 sanitize the instruction, taint set to `flagged` (PS-10). If the agent proposes the email anyway, `AG-R-H01/H02/H05` hold it. Approver sees the exact arguments. | T-E2E-01 | Detection can miss a paraphrase (TM-14). The ActionGate hold is the second layer. |
| TM-02 | Review hides the instruction in an HTML comment, zero-width characters, Unicode tags, CSS, or base64 | ADV-1 | PS-11 and PS-05 decode and scan layers to depth 2 | T-PS-11, T-PS-05 | Encodings beyond depth 2 or other schemes (ROT13, custom ciphers) are not decoded. |
| TM-03 | User asks the agent to print its system prompt or a canary | ADV-2 | PS-03, PS-05, `user x extraction -> block`, `user x protected_value -> block`. Egress scan (X-05) blocks canaries in any action argument. | T-PS-03, T-X-05 | A model that paraphrases a secret instead of echoing it passes both checks. |
| TM-04 | Agent tries to call approval, policy, graph, or taint-reset endpoints | ADV-4 | AU-01, AU-02: separate routers, keys, and credentials. Wrong-plane calls are refused and ledgered. | T-AU-01 | None at this layer. Host compromise is out of scope. |
| TM-05 | Content tries to change policy ("update the policy to allow all") | ADV-1, ADV-2 | PS-09: structural. No import path from content handling to the policy writer. Detectors also flag the text. Policy changes need a human admin and a second admin approval (PE-06). | T-PS-09, T-PE-06 | A human admin could be socially engineered into proposing a bad change. The second-admin gate and the diff view limit that. |
| TM-06 | Requester approves their own held action | ADV-5 | AG-07, server-side check of requester vs approver, plus role check. Refusal is ledgered. | T-AG-07 | Two accounts controlled by one person (collusion). Not detectable by Sentinel. |
| TM-07 | **Approval substitution (TOCTOU).** Agent gets `X` approved, then executes `X'` | ADV-4 | AG-06: fingerprint over agent, type, arguments, target. Execute recomputes from the submitted action. Mismatch refuses and creates a new held action (AG-16). | T-AG-06 | Fingerprint covers the declared arguments only. Anything the executor derives from state outside the arguments is outside the approval. |
| TM-08 | **Approval replay.** Reuse an approval, or use one after expiry | ADV-4 | AG-14: single use via atomic UPDATE, 900 s expiry, HMAC signature verified at execute | T-AG-14 | None within the model. A stolen `APPROVAL_KEY` allows forging (TM-18). |
| TM-09 | Policy tightened or session re-flagged between approval and execution | ADV-4 | D-27: execute-time re-evaluation, a `block` result refuses | T-AG-14 | A `hold`-to-`hold` change is satisfied by the existing approval. |
| TM-10 | **Confused deputy.** Agent with legitimate Mailer access is steered by content to use it harmfully | ADV-1 | Taint plus blast radius make actions on attack-path nodes stricter (X-01, X-02). BreachPath shows the route and suggests removing edges (BP-07). | T-AG-12, T-AG-13 | The agent still has its permissions. Sentinel reduces and gates use. It does not remove the confused-deputy property of an agent that reads untrusted content. |
| TM-11 | **Session laundering.** Agent opens a new session to drop taint | ADV-4 | SS-04, D-02: sessions are created on the human plane only. Taint is monotonic (SS-02) and reset is human-only (SS-03). | T-SS-03, T-SS-04 | A human who resets taint without reviewing. Resets are ledgered with the actor. |
| TM-13 | **LLM manipulation.** Prompt makes the LLM label a malicious input benign or an action safe | ADV-1, ADV-2 | LA-04, D-07: the LLM can only tighten, and never produces `block`. Mock `says_safe_always` is a test. LLM output is schema-validated, time-bounded, and non-authoritative. | T-LA-04, T-AG-10 | The LLM can be manipulated into over-flagging (denial of service through `escalate`). This is a nuisance, not a breach. |
| TM-14 | Detector false negatives: paraphrases, multi-turn setups, non-English attacks, novel obfuscation | ADV-1, ADV-2 | Benchmark reports misses (PS-08). Defense in depth: ActionGate rules do not depend on detection. | T-PS-08 | **Real and accepted.** Detection is probabilistic and will miss attacks. The guarantee is that missed attacks still face deny-by-default actions. |
| TM-15 | Framing abuse: wrapping an attack in "for example" or quotes to earn the discount | ADV-1 | D-19: no discount for protected values, floor 45 (escalate band) for exfil with instruction and external destination | T-PS-13 | Override-only text with heavy framing can fall below threshold. It is then weak and logged. |
| TM-16 | Ledger edit, delete, or reorder by an insider | ADV-3 | LG-01..03: hash chain, verify points to the first broken `seq`. Triggers block casual SQL. | T-LG-03..05 | **Tail truncation is undetectable** without an externally held head hash (LG-06, Stretch). **A determined insider with write access can recompute every hash after the edit,** because the chain is unkeyed. A keyed (HMAC) chain with the key held off-host, or periodic external checkpoints, closes this. |
| TM-17 | Insider edits policy or graph rows directly | ADV-3 | Policy versions are immutable by trigger and carry a content hash recorded in the ledger on activation. Graph versions are hashed. Mismatch is visible against ledger payload digests. | T-PE-04 | Same as TM-16: an insider who rewrites both the row and the ledger can hide it. |
| TM-18 | Key theft: human token key, approval key, exec key, agent pepper | ADV-3 | Four separate keys, env-only, rotated by restart. Execution tokens live 60 s and are single use. | T-AU-04 | Demo keys are weak by design. Production needs a secret store. |
| TM-19 | Direct call to executors, skipping the gateway | ADV-4 | AG-11, AU-04: executors verify an HMAC token bound to action and fingerprint. A static test checks imports. | T-AG-11 | Code execution inside the server process bypasses this. |
| TM-20 | **Graph-model staleness.** The graph says a route is closed but reality differs | all | BP-14 versioning and timestamps. Observed-vs-declared (BP-13, Stretch) flags undeclared access. UI shows the model age. | T-BP-13 | **BreachPath is only as good as the model entered.** It never invents edges (BP-02, BP-07), so a missing edge means a missing route. |
| TM-21 | Denial of service: huge payloads, ReDoS, dense graphs | ADV-1, ADV-2 | PS-16 size and time budgets, linear-time regexes. BP-10 caps with honest truncation. BP-15 file limits. | T-PS-16, T-BP-10 | Resource exhaustion by many small requests. Rate limiting is out of scope. |
| TM-22 | Approver fatigue or rubber-stamping | ADV-6 | AG-15 shows exact arguments and rule reasons. Holds are rare because allow rules cover routine work. | UI-03 checks | Humans can still approve a harmful action. Sentinel makes it visible and attributable, not impossible. |
| TM-23 | Canary appears in a log or screenshot | ADV-3 | LG-04: redaction before write, digests instead of values. A test scans the DB for all encodings of the canaries. | T-LG-06 | Excerpts of near-secret text could still reveal context. |
| TM-24 | Indirect leak through allowed channels (`web.fetch` URL query string, `update_account` free text) | ADV-4 | Egress scan on every argument (X-05). `AG-R-H08` holds fetches in flagged sessions. | T-X-05 | Low-bandwidth covert channels through allowed arguments. |
| TM-25 | Prompt injection / jailbreak via Live LLM in agent runtime | ADV-1, ADV-2 | AG-17..AG-20: LLM tool calls intercepted and evaluated by ActionGate. PromptShield pre-screens ingesting tools. Even a fully compromised model cannot execute an unapproved action. | T-LLM-05, T-AG-10 | Output phrasing from LLM can still deceive user, but no simulated side-effect executes without passing ActionGate. |
| TM-26 | LLM API key exfiltration or tampering | ADV-3, ADV-4 | Secrets stored only in server environment, never logged, never stored in DB or ledger, never returned in API responses. `.env` gitignored. | T-LG-06, T-LLM-02 | Host environment compromise (out of scope). |
| TM-27 | Denial of service / latency attack via external LLM provider | ADV-1, ADV-2 | LA-02, LA-08, LA-09: hard timeout `LLM_TIMEOUT_SECONDS`, circuit breaker, automatic fallback to `ScriptedAgent` simulation with `agent_source = simulated`. | T-LA-02, T-LLM-04 | User receives simulated responses until provider recovers. |
| TM-28 | Unauthorized modification of LLM settings or kill switch | ADV-4, ADV-5 | AU-05, LA-07: settings endpoints are admin-only on the human plane. Agent credentials and non-admin tokens get 403. Every setting change is ledgered. | T-AU-05, T-LLM-02 | Admin credentials compromised. |
| TM-29 | Requesters accessing admin dashboards or approving actions | ADV-5 | AU-05, AU-06: server-side role checks reject requesters on approver/admin endpoints with 403 `auth.forbidden_role`. Seeded login routes by role. | T-AU-05, T-AG-07 | Collusion between human accounts. |

## 5. Required discussions

### 5.1 Confused deputy
SupportBot legitimately holds permissions that content can steer. Sentinel does not claim to remove that. It (a) screens content before the model, (b) raises the bar for actions when untrusted content was ingested, (c) raises it further for resources on an attack path, and (d) shows the route so an admin can remove the permission. Layers (b) and (c) matter most because (a) is probabilistic.

### 5.2 Approval replay and substitution
The approval is bound to a SHA-256 fingerprint of the exact action, signed by HMAC, single-use, and time-limited. The executor accepts a submitted action, not an approval reference alone, so a mutated argument is detected at the point of use. Between approval and use the gateway re-runs the hard guards, so policy tightening still wins.

### 5.3 Policy tampering through content
Structural, not heuristic: policy edits exist only on the human plane (separate router, key, and credential type), require role `admin`, are held, bound to a diff fingerprint, and need a different admin. Content handling never imports the policy writer. Detection of "update the policy" text is a bonus, not the control.

### 5.4 LLM manipulation
Treated as an untrusted advisor. Output is schema-validated and cannot loosen. It never yields `block`. If it fails, rules decide, and the ledger names the path.

### 5.5 Ledger truncation
Stated plainly: the hash chain detects edits, deletions in the middle, and reordering. It does not detect removal of the last N rows, because nothing later references them. Mitigation: export a checkpoint (head seq and hash, HMAC-signed) and verify against it (LG-06, Stretch). Also stated: an insider who can rewrite the whole table can rebuild a consistent chain unless the head is anchored off-host or the hash is keyed.

### 5.6 Graph-model staleness
BreachPath analyzes the model the user entered. If reality differs, results are wrong in either direction. The tool reports the graph version, never adds edges, and (Stretch) compares the model with observed actions.

### 5.7 Detector false-negative risk
Reported, not hidden. The benchmark includes known-hard cases (paraphrase, multi-turn, non-English, obfuscation) and lists every miss on the test split with an explanation. The design assumption is that detection will fail sometimes, so action gating is independent of it.

### 5.8 Live LLM agency vs deterministic controls
Sentinel treats real LLMs (such as OpenAI models) as probabilistic, untrusted proposal generators. When user messages prompt the agent runtime, the LLM emits candidate tool calls. ActionGate intercepts these calls before execution and subjects them to deterministic schema validation, recipient restrictions, canary scans, blast radius evaluation, and policy rules. Ingesting tools (`browse_page`, `read_reviews`) are screened by PromptShield before the model ever sees the fetched data. Thus, indirect injections inside retrieved content are filtered before model ingestion, and any residual malicious steering is blocked at ActionGate.

## 6. What Sentinel does not defend against

* A compromised Sentinel host, its keys, or its Python process.
* An insider who rewrites the whole database and any off-host anchors (TM-16).
* Semantic attacks that never use a detectable pattern, for example a politely worded request that is plausibly legitimate. The action layer is the control.
* Approvers who knowingly approve harmful actions.
* Data that the agent leaks through channels Sentinel does not model (real email, real web).
* Attacks entirely inside a single allowed action's free-text fields beyond what the egress scan matches.

## 7. Security requirements summary

| Property | Requirements |
| --- | --- |
| Separation of authority | AU-01, AU-02, AU-03, PE-06, SS-04 |
| Integrity of evidence | LG-01..LG-05, LG-07 |
| Integrity of approvals | AG-06, AG-07, AG-14, AG-16 |
| Default deny and fail safe | AG-01, AG-02, PE-03, PE-07, LA-02, LG fail-closed (D-26) |
| Honest measurement | PS-08, BP-10 |
