# Sentinel

**A security control plane for an AI agent.** One product, three problems, one agent.

| Stage | Module | Question it answers |
| --- | --- | --- |
| Before the model | **PromptShield** | Is this input trying to manipulate the agent or leak data? |
| After the model | **ActionGate** | Is this specific proposed action allowed, blocked, or held for a human? |
| Around the model | **BreachPath** | If this agent is compromised, what can it reach? |

They share one **policy engine**, one **hash-chained audit ledger**, and one **LLM adapter**, and they feed each other: untrusted content taints a session, tainted sessions get stricter action rules, and actions on nodes that sit on an attack path get stricter still.

## Pitch

AI agents read untrusted text and then act. Detection of malicious text is probabilistic, so Sentinel does not bet on it. It screens inputs, but the real guarantee is structural:

1. **AI is advisory, rules decide.** An LLM may add a signal. It can only make a decision stricter, never looser.
2. **Default deny.** Unknown agents, unknown actions, bad arguments, and missing context end in block or hold.
3. **Fail safe, and say so.** If the LLM is down, slow, or returns garbage, rules decide and the ledger records `decision_path = fallback`.
4. **Untrusted content is data.** Policy can only change through a gated human-plane proposal that another admin approves. An agent has no route to it.
5. **Evidence over claims.** Every requirement has an automated test. The benchmark reports misses and false positives honestly. The ledger is tamper-evident, and its limits are documented.
6. **No invented facts.** BreachPath never creates nodes or edges you did not enter.

## Quick start (one command)

```bash
docker compose up --build        # seeds on first run, serves UI and API at http://localhost:8000
```

Sign in with the user switcher (password `demo`): **Alice** (requester), **Bob** (approver), **Admin** and **Dana** (admins). Open **Agent Sandbox** and press **Next step** on the scripted replay.

Other commands:

```bash
make seed     # delete the DB and rebuild every synthetic dataset (seed 1337)
make test     # pytest, writes reports/last_run.json for the Test Report screen
make bench    # PromptShield benchmark on the held-out test split
make demo     # seed, start, open the Sandbox
make dev      # backend with reload (8000) and Vite (5173)
```

Everything is simulated. Mock tools write to a "fake outbox" panel. Nothing real is sent or deleted. The decisions are real, the side effects are not.

## Repository map

```
sentinel/
  README.md
  docs/
    architecture.md   components, trust boundaries, sequence diagrams, tech, deployment, decision log
    spec.md           functional requirements per module, algorithms, edge cases
    data-models.md    DB schema, JSON schemas, test vectors
    api.md            every endpoint with request, response, errors, auth plane
    policy-spec.md    policy format, evaluation semantics, complete default policy v1
    threat-model.md   assets, adversaries, scenarios, mitigations, residual risk
    test-plan.md      acceptance matrix, fault injection, benchmark methodology
    seed-data.md      every synthetic dataset and its deliberate edge cases
    ui-spec.md        screens, components, interactions, empty and error states
    demo-script.md    the 5-minute scenario with expected on-screen results
    roadmap.md        milestones, tasks, build order, cut list
  backend/app/
    core/             policy.py  ledger.py  llm.py  session.py
    actiongate/       registries, pipeline, approvals, executors
    breachpath/       model, validation, search, remediation, diff, blast
    promptshield/     normalize, decoders, detectors, outcomes, sanitize, benchmark
    api/              agent plane (/agent/v1) and human plane (/api/v1)
    tests/
  frontend/src/       screens/  components/
  seed/               seed.py graph.json bad_graph.json reviews.json benchmark.json
                      policy_v1.yaml llm_fixtures.json replay_demo_v1.json
  docker-compose.yml  Makefile
```

## How the pieces fit

```
 user / docs / web / tool output
            |
            v
   PromptShield (ingress screen) --taint--> Session Store
            |                                    |
            v                                    v
        LLM agent --proposed action--> ActionGate --> Policy Engine <-- BreachPath graph
                                           |             (blast radius, entry points)
                             allow / block / hold
                                           |
                +--------------------------+------------------+
                v                                             v
       Approval workflow                         Hash-chained audit ledger
  (bound to action fingerprint)                 (every module writes here)
                |
                v
      Mock executors (reachable only through the gateway)
```

Two auth planes: the **agent plane** (`/agent/v1`) can only submit inputs and propose actions. The **human plane** (`/api/v1`) alone can approve, edit policy or graph, and reset taint. That separation is what makes "content read by an agent can never edit policy" structural rather than a detection claim.

## Demo in one paragraph

SupportBot has a 3-step route from a web page through the agent and the mailer to the customer DB. A poisoned review tells the agent to email the customer list to `attacker@evil.example`. PromptShield sanitizes it and taints the session. The agent proposes the email anyway and ActionGate **holds** it. Alice tries to approve her own request and is refused (ledgered). Bob sees the real arguments and rejects. Admin applies BreachPath's suggestion removing the agent's direct read access to the customer DB, and the diff shows exactly which routes were removed. With the LLM killed, the next action is still decided safely and the ledger shows `fallback`. Editing a ledger row makes **Verify chain** fail and name the broken row. Details in `docs/demo-script.md`.

## Scope

**MVP** is buildable by 3 to 4 people in a short window and is listed per requirement. **Stretch** items (CSV upload, observed-vs-declared report, ledger checkpoint export, SSE, real LLM provider) are in `docs/roadmap.md` with a cut list.

**Non-goals:** real integrations, real customer data, production authentication or multi-tenancy, model training, a general agent framework.

## Honest limits

* Detection will miss attacks (paraphrase, multi-turn, non-English, novel obfuscation). The benchmark lists every miss. Action gating does not depend on detection.
* The hash chain detects edits, middle deletions, and reordering. It cannot detect removal of the last rows without an external checkpoint, and an insider who rewrites the whole table can rebuild a consistent chain unless the head is anchored off-host.
* BreachPath is only as accurate as the model you enter. It never adds edges.
* Demo authentication and keys are for demonstration only.

See `docs/threat-model.md` for the full discussion.

## Requirement IDs

Every requirement has a stable ID (`AG-xx`, `BP-xx`, `PS-xx`, `X-xx`, plus `PE`, `LG`, `LA`, `SS`, `AU`, `SD`, `UI`, `DEMO`) that appears in `docs/spec.md` and traces to tests in `docs/test-plan.md`. The Test Report screen groups the last pytest run by these IDs.
