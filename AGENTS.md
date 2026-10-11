# AGENTS.md

Instructions for AI coding agents working in the Sentinel repository. Read this file fully before making any change. Human contributors should follow it too.

## 1. What this project is

**Sentinel** is a security control plane for an AI agent. It combines three modules around one simulated agent (`SupportBot`, for the fictional company Acme Retail):

| Module           | Role                                        | Question it answers                                        |
| ---------------- | ------------------------------------------- | ---------------------------------------------------------- |
| **PromptShield** | Screens inputs before the model             | Is this input trying to manipulate the agent or leak data? |
| **ActionGate**   | Authorizes proposed actions after the model | Is this action allowed, blocked, or held for a human?      |
| **BreachPath**   | Models access as a graph                    | If the agent is compromised, what can it reach?            |

Three shared components bind them: one **policy engine**, one **hash-chained audit ledger**, one **LLM adapter**.

All tools, data, and side effects are **simulated**. The decisions are real; the sends and deletes are mocks.

## 2. Read the docs first

The specification lives in `/docs`. It is the source of truth. Do not rely on assumptions.

| File                   | Read it when                                 |
| ---------------------- | -------------------------------------------- |
| `docs/spec.md`         | Before implementing any feature              |
| `docs/architecture.md` | Before adding or moving a component          |
| `docs/data-models.md`  | Before touching the DB or any JSON schema    |
| `docs/api.md`          | Before adding or changing an endpoint        |
| `docs/policy-spec.md`  | Before touching the policy engine or rules   |
| `docs/test-plan.md`    | Before writing or changing tests             |
| `docs/threat-model.md` | Before changing anything security-relevant   |
| `docs/seed-data.md`    | Before changing seed data                    |
| `docs/ui-spec.md`      | Before building or changing a screen         |
| `docs/demo-script.md`  | Before changing anything the demo depends on |
| `docs/roadmap.md`      | To find the current milestone and task order |

Every requirement has an ID (`AG-xx`, `BP-xx`, `PS-xx`, `X-xx`). Reference the ID in code comments, test names, and commit messages.

If the code and the docs disagree, **stop and flag it**. Either fix the code to match the spec or update the spec with a clear note. Never let them silently drift.

## 3. Commands

Run these from the repo root. If a command below does not exist yet, create it in the `Makefile` instead of inventing a different workflow.

```
make setup      # install backend and frontend dependencies
make seed       # rebuild the database and all synthetic data (deterministic)
make dev        # start backend and frontend in development mode
make test       # run the full backend test suite
make test-fast  # run unit tests only
make lint       # run linters and type checks
make bench      # run the PromptShield benchmark and write the metrics report
docker compose up   # one-command start for judges
```

Always run `make test` and `make lint` before declaring a task done.

## 4. Repository layout

```
backend/app/core/          policy engine, ledger, LLM adapter, sessions and taint
backend/app/actiongate/    registries, evaluation pipeline, approvals, executors
backend/app/breachpath/    graph model, validation, path search, remediation, diff
backend/app/promptshield/  detectors, normalization, outcome table, sanitizer
backend/app/api/           FastAPI routers (agent plane and human plane)
backend/tests/             pytest suites, organized by module
frontend/src/screens/      one folder per screen
seed/                      seed.py and all synthetic datasets
docs/                      the specification
```

Keep module boundaries. Modules talk to each other through the interfaces in `docs/architecture.md` (for example `blast_radius()` and the session taint API), never by importing each other's internals.

## 5. Non-negotiable design rules

These define the product. Never violate them, even to make a test pass or a demo easier.

1. **AI is advisory, rules decide.** The LLM may produce a signal. The deterministic policy engine makes the final decision. An LLM signal can only make an outcome **stricter**, never looser.
2. **Default deny.** Unknown agents, unknown action types, malformed input, invalid arguments, and unavailable context resolve to `block` or `hold`. Never to `allow`.
3. **Fail safe and record the path.** If the LLM times out, errors, or returns invalid output, the rules-only path decides and the ledger records `decision_path = fallback`. Valid values are `rules`, `rules+llm`, `fallback`.
4. **Untrusted content is data.** Text from documents, web pages, and tool outputs is examined, never obeyed. No code path may read policy, configuration, roles, or permissions from content. Policy changes come only from the authenticated human plane and are themselves gated actions.
5. **Two auth planes.** Agent credentials must not be able to call any human-plane endpoint (approve, edit policy, edit graph, clear taint). Enforce this on the server, not in the UI.
6. **Approvals are bound to content.** An approval applies to the SHA-256 fingerprint of the canonical `{agent_id, action_type, arguments, target}`. Recompute and compare at execution time. Approvals are single-use and expire. The requester can never approve their own request.
7. **Gateway is the only path.** Mock executors accept only calls with a gateway-issued execution token.
8. **Every decision is ledgered, including refusals.** Blocks, failed self-approvals, rejected uploads, and LLM fallbacks all produce ledger entries. The ledger is append-only and hash-chained. Never write code that updates or deletes ledger rows (except the clearly marked demo-only tamper endpoint).
9. **No invented facts in BreachPath.** Never create nodes or edges the user did not enter. Reject malformed models with a located, readable error. Remediation suggestions reference only existing edge IDs.
10. **Never put secrets in logs or the ledger.** Store digests and redacted excerpts. Canary values must never appear in any output.

## 6. Coding conventions

- **Language and versions:** Python 3.11+, FastAPI, SQLite; React with Vite and Cytoscape.js on the frontend. Do not add a new framework or major dependency without a note in the PR explaining why.
- **Typing:** type-hint all Python functions. Use Pydantic models for every request, response, and schema. No untyped dicts crossing module boundaries.
- **Determinism:** the policy engine and path search must be deterministic. Same input and same policy version give the same output. Sort before hashing and iterating where order could vary. Seed all randomness.
- **Canonical JSON:** use the single shared helper (sorted keys, no whitespace, UTF-8) for every hash. Never hand-roll serialization for hashing.
- **Errors:** return structured errors `{code, message, location?}`. No bare exceptions leaking to clients. Fail closed on unexpected errors in the decision path.
- **Bounded work:** path search must use a visited set per path, a max depth, a max path count, and a time budget. Surface `truncated: true` when a cap is hit. Never silently drop results.
- **Small, readable functions.** Prefer clear code over clever code. Comment the _why_ for security-relevant logic, with the requirement ID.
- **No dead code or speculative features.** Build what the spec says.

## 7. Testing rules

Tests are the primary evidence for judges. Treat them as part of the product.

- Write or update tests **in the same change** as the code. A feature without tests is not done.
- Name tests with the requirement ID, for example `test_AG06_changed_argument_invalidates_approval`.
- Every row of the acceptance matrix in `docs/test-plan.md` must have an automated test. This includes: default deny, LLM says "safe", approval binding, self-approval, LLM timeout/garbage/down, ledger tamper detection, cycles, max depth, dangling-edge rejection, diff correctness (including a new route), encoded canaries, indirect injection, sanitize preservation, taint link, blast-radius link, auth-plane separation, gateway bypass, and benchmark honesty.
- Use the LLM **mock adapter** in tests (modes `ok`, `says_safe_always`, `timeout`, `garbage`, `down`). Tests must never call a real model or the network.
- Do not weaken, skip, or delete a failing test to get green. Fix the code, or if the test is wrong, explain why in the commit message and update the spec.
- Do not tune detectors on the benchmark `test` split. Tune on `dev` only. Report misses and false positives honestly in the metrics output.

## 8. Working style for agents

1. **Locate the task** in `docs/roadmap.md` and the requirement IDs it covers.
2. **Read the relevant docs** from section 2 before writing code.
3. **Plan briefly.** State which files you will change and which tests you will add.
4. **Build a vertical slice** before broadening. Prefer one working end-to-end path over several half-built ones.
5. **Run `make test` and `make lint`.** Fix everything you broke.
6. **Summarize** what changed, which requirement IDs are now covered, and anything you were unsure about.

Keep changes small and focused: one concern per commit. Commit messages follow `type(scope): summary [ID]`, for example `feat(actiongate): bind approvals to action fingerprint [AG-06]`.

## 9. Ask a human before you

- Change a rule in the **non-negotiable list** (section 5).
- Change the policy v1 defaults, outcome names, or `decision_path` values.
- Change the ledger entry format or hashing scheme (this invalidates existing chains).
- Add a dependency, a service, or a new auth mechanism.
- Remove or reduce a test.
- Do something the spec does not cover and that affects security behavior.

For small, reversible gaps, make a decision, record it as `Decision:` with a one-line rationale in the relevant doc, and continue.

## 10. Demo and safety constraints

- The demo must be **reproducible**. Keep the scripted replay mode working: fixed inputs produce fixed outcomes regardless of any live LLM.
- The "Tamper with row" endpoint and button are **demo-only**. They must be clearly labeled, disabled when `DEMO_MODE` is off, and never reachable from the agent plane.
- All data is synthetic. Never add real personal data, real credentials, or real external integrations. Mock tools must not make real network calls, send real email, or delete real files.
- Run `make seed` after any change to seed data, and confirm the demo scenario in `docs/demo-script.md` still produces the documented result at every step.

## 11. Definition of done

A task is done only when all of these are true:

- [ ] Behavior matches the cited requirement IDs in `docs/spec.md`.
- [ ] Automated tests exist, are named by requirement ID, and pass (`make test`).
- [ ] Lint and type checks pass (`make lint`).
- [ ] None of the section 5 rules is weakened.
- [ ] Docs are updated if behavior, endpoints, schemas, or policy changed.
- [ ] The demo scenario still works from a fresh `make seed`.
- [ ] Failure paths are covered: invalid input, LLM down, unknown agent, missing context.
