# Sentinel: Policy Specification

One policy file governs all three modules (X-06). It is versioned, immutable per version, loaded from the database, and changed only through a gated human-plane proposal (PE-04, PE-06). Requirement IDs refer to `spec.md`.

## 1. Format and lifecycle

* Authoring format: YAML. Stored format: canonical JSON of the same document (`policy_versions.content_json`).
* `version` in the file is informational. The stored `version` is assigned by the server (max + 1) when a proposal is approved.
* Lifecycle: draft in the editor, `POST /policy/proposals` (lint, hold, approval row), a different admin approves, new immutable version is activated, `policy.activated` is ledgered.
* Every decision records `policy_version`. Old decisions are never reinterpreted.

## 2. Document structure and schema

```yaml
schema: sentinel.policy/1
policy_id: <string>
description: <string>
default_outcome: block | hold          # allow is rejected by lint (PE-03, PE-05)
default_justification: <string>        # required when default_outcome is hold
settings: {...}                        # thresholds, LLM, TTLs, internal domains, edge traversal
impact: {factors: [...]}               # named factors producing impact.level
constraints: {global: {...}, per_action: {...}}   # step 5, short-circuit block
action_rules: [Rule]                   # step 7
policy_rules: [Rule]                   # kind=policy_change
ingress: {thresholds: {...}, table: {...}}        # PromptShield outcome table
```

```json
{
  "$id": "sentinel/policy.schema.json", "type": "object", "additionalProperties": false,
  "required": ["schema","policy_id","default_outcome","settings","impact","constraints","action_rules","policy_rules","ingress"],
  "properties": {
    "schema": {"const": "sentinel.policy/1"},
    "policy_id": {"type": "string"}, "description": {"type": "string"},
    "default_outcome": {"enum": ["block","hold"]},
    "default_justification": {"type": "string"},
    "settings": {"type": "object"},
    "impact": {"type": "object", "required": ["factors"]},
    "constraints": {"type": "object"},
    "action_rules": {"type": "array", "items": {"$ref": "#/$defs/rule"}},
    "policy_rules": {"type": "array", "items": {"$ref": "#/$defs/rule"}},
    "ingress": {"type": "object", "required": ["thresholds","table"]}
  },
  "$defs": {
    "rule": {"type": "object", "additionalProperties": false, "required": ["id","priority","outcome","reason","when"],
      "properties": {"id": {"type": "string", "pattern": "^[A-Z]{2}-R-[A-Z0-9-]+$"}, "priority": {"type": "integer", "minimum": 1},
        "outcome": {"enum": ["allow","hold","block"]}, "reason": {"type": "string", "maxLength": 200}, "when": {"$ref": "#/$defs/cond"}}},
    "cond": {"oneOf": [
      {"type": "object", "required": ["all"], "properties": {"all": {"type": "array", "items": {"$ref": "#/$defs/cond"}}}},
      {"type": "object", "required": ["any"], "properties": {"any": {"type": "array", "items": {"$ref": "#/$defs/cond"}}}},
      {"type": "object", "required": ["not"], "properties": {"not": {"$ref": "#/$defs/cond"}}},
      {"type": "object", "required": ["field","op","value"], "properties": {"field": {"type": "string"}, "op": {"enum": ["eq","ne","in","not_in","gt","gte","lt","lte"]}, "value": {}}}
    ]}
  }
}
```

## 3. Evaluation semantics

### 3.1 Conditions

* Leaves compare a context field with a literal. `in` and `not_in` take lists.
* Ordinal fields compare by rank, so `gte` works: `low < medium < high` for `blast.level`, `impact.level`, `action.sensitivity`. Booleans use `eq`. Taint level is an integer (0, 1, 2).
* An absent required field raises `ContextError` and the decision is `block` with `PE-ERR-CONTEXT` (PE-07). An absent optional field makes its leaf false.
* No regex, no function calls, no field-to-field comparison. Rules cannot read content text.

### 3.2 Combining rules (PE-02)

1. Evaluate every rule for the request kind.
2. Collect matches. If none, return `default_outcome` with rule `PE-DEFAULT`.
3. Strictness: `block` (3) > `hold` (2) > `allow` (0). Ingress adds `escalate` (= hold, 2) and `sanitize` (1).
4. Outcome = strictest matched. Primary rule = strictest outcome, then lowest `priority`, then lexicographic `id`.
5. `rule_ids` = all matches ordered by (strictness desc, priority asc, id).

An `allow` rule is therefore necessary to allow, and any stricter match overrides it. A new action type gets `block` until a human adds an allow rule.

### 3.3 Impact factors

`impact.level` is the maximum level of every applicable factor. Factors are named so a reviewer can see why. The numeric `impact.score` is display only and cannot appear in rules (lint, PE-05).

`score = min(100, 20 * sensitivity_rank + 10 * irreversible + 15 * external + min(15, 5 * floor(records / 10)))` with ranks low 1, medium 2, high 3. Example: external email gives 60 + 10 + 15 = 85.

### 3.4 Required context

| Kind | Required fields |
| --- | --- |
| `action` | `agent.id`, `agent.status`, `action.type`, `action.reversible`, `action.record_count`, `action.sensitivity`, `action.destination_external`, `impact.level`, `blast.level`, `session.taint_level` |
| `ingress` | `tier`, `session.taint_level`, `findings[]` with `type`, `confidence_pct` |
| `policy_change` | `proposer.id`, `proposer.is_admin`, `diff.size`, `base_version` |

The gateway fills fail-safe values when upstream data is unavailable: `blast.level = high`, `action.record_count = 0` only when the registry says `const 0`, never otherwise (a missing count is `ContextError`).

### 3.5 Pipeline guards that are not editable

Steps 1 to 4 (`AG-DENY-AGENT`, `AG-DENY-ACTION`, `AG-DENY-NOTALLOWED`, `AG-DENY-ARGS`), the protected-value scan (`AG-CON-PROTECTED`), execution-token enforcement, the fingerprint check, self-approval refusal, and `PC-R-001` are code, not policy (PE-05 floor). Policy can add constraints and rules, but cannot remove these.

## 4. Floor invariants checked by lint (PE-05)

1. `default_outcome` is `block` or `hold` (with justification).
2. `constraints.global.protected_value_scan` is `true`.
3. No rule with outcome `allow` matches `action.type == policy.update`, and `PC-R-001` exists unchanged.
4. Every (tier x threat) cell exists in `ingress.table` for `user`, `retrieved_document`, `tool_output`, with a valid outcome.
5. `ingress.thresholds.band_min <= act_min`, both 0 to 100.
6. Every `rule.id` is unique. Every regex in constraints compiles, is under 200 characters, and has no nested quantifier.
7. No condition references `impact.score`.
8. `settings.approval_ttl_s` is 60 to 3600. `settings.llm.timeout_ms` is 100 to 10000.
9. `ingress.table` for tier `user` and threat `protected_value` is not weaker than `block`. (Decision: the one table cell pinned by the floor, because it is the canary guarantee.)

## 5. Ingress outcome table (PS-06)

Keyed by tier then threat. Values `allow | block | sanitize | escalate`. The `developer` tier is documented for completeness and is not reachable through the API (D-16).

| Tier \ Threat | override | extraction | exfil_target | protected_value | hidden_content | directive |
| --- | --- | --- | --- | --- | --- | --- |
| `developer` | allow | allow | allow | allow | allow | allow |
| `user` | block | block | escalate | block | sanitize | allow |
| `retrieved_document` | sanitize | sanitize | sanitize | sanitize | sanitize | sanitize |
| `tool_output` | sanitize | sanitize | sanitize | sanitize | sanitize | sanitize |

Confidence handling (integers):

| Confidence | Behavior |
| --- | --- |
| `>= act_min` (60) | Table outcome, rule `PS-R-<TIER>-<THREAT>` |
| `band_min` (40) to 59, threat in `high_impact_types` | `escalate`, rule `PS-R-LOWCONF-ESCALATE` |
| `band_min` to 59, other threats | Weak. Recorded, no outcome |
| `< band_min` | Weak. Recorded, no outcome |

Built-in outcomes outside the table: `PS-SAN-NOSPAN` (escalate), `PS-SAN-RESIDUAL` (escalate), `PS-SAN-EMPTY` (block), `PS-ERR-BUDGET`, `PS-LLM-TIGHTEN` (escalate).

## 6. Complete default policy v1

This file is `seed/policy_v1.yaml`. It is complete enough to run the demo and every X-link test without further decisions.

```yaml
schema: sentinel.policy/1
policy_id: sentinel-default
description: Acme Retail SupportBot default policy, v1
default_outcome: block

settings:
  approval_ttl_s: 900
  execution_token_ttl_s: 60
  internal_domains: [acme.example]
  llm:
    enabled: true
    timeout_ms: 3000
    breaker_failures: 3
    breaker_cooldown_s: 30
    tighten_min_confidence: 70
    on_failure: rules_only          # hold_allow is a Stretch option
  breachpath:
    edge_traversal: {}              # e.g. {network_reachable: false} to ignore a type

impact:
  factors:
    - {id: IMP-SENS, source: action.sensitivity, map: {low: low, medium: medium, high: high}}
    - {id: IMP-RECORDS, source: action.record_count, steps: [{gte: 50, level: high}, {gte: 10, level: medium}]}
    - {id: IMP-IRREV, when: {field: action.reversible, op: eq, value: false}, level: medium}
    - {id: IMP-EXTERNAL, when: {field: action.destination_external, op: eq, value: true}, level: high}

constraints:
  global:
    protected_value_scan: true      # AG-CON-PROTECTED, floor invariant
    forbidden_patterns:
      - {id: FP-SQL, regex: '(?i)\b(drop|truncate)\s+table\b', applies_to: [db.read, db.update, db.delete]}
  per_action:
    email.send:
      deny_domains: [pastebin.example, mailinator.example, blocked.example]
      max_recipients: 20
    db.read:   {max_records_hard: 500}
    db.update: {max_records_hard: 100}
    db.delete: {max_records_hard: 100}

action_rules:
  # ---- allow rules: necessary to allow, overridden by any stricter match ----
  - id: AG-R-A01
    priority: 100
    outcome: allow
    reason: Fetching a page is low impact
    when: {field: action.type, op: eq, value: web.fetch}
  - id: AG-R-A02
    priority: 101
    outcome: allow
    reason: Reading reviews is low impact. Content is screened at ingress
    when: {field: action.type, op: eq, value: reviews.read}
  - id: AG-R-A03
    priority: 102
    outcome: allow
    reason: Small customer read in a clean session
    when:
      all:
        - {field: action.type, op: eq, value: db.read}
        - {field: session.taint_level, op: eq, value: 0}
        - {field: action.record_count, op: lte, value: 20}
  - id: AG-R-A04
    priority: 103
    outcome: allow
    reason: Email to internal recipients only
    when:
      all:
        - {field: action.type, op: eq, value: email.send}
        - {field: action.destination_external, op: eq, value: false}
  - id: AG-R-A05
    priority: 104
    outcome: allow
    reason: Small account update
    when:
      all:
        - {field: action.type, op: eq, value: db.update}
        - {field: action.record_count, op: lte, value: 10}

  # ---- hold rules ----
  - id: AG-R-H01
    priority: 10
    outcome: hold
    reason: External recipient requires human approval
    when:
      all:
        - {field: action.type, op: eq, value: email.send}
        - {field: action.destination_external, op: eq, value: true}
  - id: AG-R-H02
    priority: 11
    outcome: hold
    reason: Flagged session, all outbound email needs approval (X-01)
    when:
      all:
        - {field: action.type, op: eq, value: email.send}
        - {field: session.taint_level, op: gte, value: 2}
  - id: AG-R-H03
    priority: 12
    outcome: hold
    reason: High-sensitivity read in a tainted session or above the automatic row limit (X-01)
    when:
      all:
        - {field: action.type, op: eq, value: db.read}
        - {field: action.sensitivity, op: gte, value: high}
        - any:
            - {field: session.taint_level, op: gte, value: 1}
            - {field: action.record_count, op: gt, value: 20}
  - id: AG-R-H04
    priority: 13
    outcome: hold
    reason: Irreversible bulk delete requires approval
    when:
      all:
        - {field: action.type, op: eq, value: db.delete}
        - {field: action.reversible, op: eq, value: false}
        - {field: action.record_count, op: gt, value: 1}
  - id: AG-R-H05
    priority: 14
    outcome: hold
    reason: Action on a node on an attack path to a sensitive asset while the session is tainted (X-02)
    when:
      all:
        - {field: blast.level, op: eq, value: high}
        - {field: session.taint_level, op: gte, value: 1}
  - id: AG-R-H06
    priority: 15
    outcome: hold
    reason: Account changes in a flagged session need approval
    when:
      all:
        - {field: action.type, op: eq, value: db.update}
        - {field: session.taint_level, op: gte, value: 2}
  - id: AG-R-H07
    priority: 16
    outcome: hold
    reason: Update above the automatic row limit
    when:
      all:
        - {field: action.type, op: eq, value: db.update}
        - {field: action.record_count, op: gt, value: 10}
  - id: AG-R-H08
    priority: 17
    outcome: hold
    reason: Fetching in a flagged session could carry data in the URL
    when:
      all:
        - {field: action.type, op: eq, value: web.fetch}
        - {field: session.taint_level, op: gte, value: 2}
  - id: AG-R-H09
    priority: 18
    outcome: hold
    reason: Irreversible action with high impact
    when:
      all:
        - {field: action.reversible, op: eq, value: false}
        - {field: impact.level, op: eq, value: high}

  # ---- block rules ----
  - id: AG-R-B01
    priority: 1
    outcome: block
    reason: Deletes are refused in a flagged session
    when:
      all:
        - {field: action.type, op: eq, value: db.delete}
        - {field: session.taint_level, op: gte, value: 2}

policy_rules:
  - id: PC-R-001
    priority: 10
    outcome: hold
    reason: Every policy change needs approval from a different admin
    when: {field: diff.size, op: gte, value: 0}
  - id: PC-R-002
    priority: 1
    outcome: block
    reason: Only admins may propose policy changes
    when: {field: proposer.is_admin, op: eq, value: false}

ingress:
  thresholds:
    band_min: 40
    act_min: 60
    high_impact_types: [exfil_target, protected_value, extraction]
  table:
    developer:          {override: allow, extraction: allow, exfil_target: allow, protected_value: allow, hidden_content: allow, directive: allow}
    user:               {override: block, extraction: block, exfil_target: escalate, protected_value: block, hidden_content: sanitize, directive: allow}
    retrieved_document: {override: sanitize, extraction: sanitize, exfil_target: sanitize, protected_value: sanitize, hidden_content: sanitize, directive: sanitize}
    tool_output:        {override: sanitize, extraction: sanitize, exfil_target: sanitize, protected_value: sanitize, hidden_content: sanitize, directive: sanitize}
```

## 7. Worked decisions (all produced by v1 with seed data)

| # | Scenario | Context | Matches | Outcome |
| --- | --- | --- | --- | --- |
| 1 | `query_customers {limit:10}` clean | taint 0, count 10, blast high | A03 | **allow** |
| 2 | Same, after `browse_page` | taint 1 | H03, H05 | **hold** (X-01) |
| 3 | `update_account` on `asset:marketing_db`, 3 ids | taint 1, blast low, impact medium | A05 | **allow** |
| 4 | `update_account` on `asset:customer_db`, 3 ids | taint 1, blast high | A05, H05 | **hold** (X-02) |
| 5 | `send_email` to `bob@acme.example`, clean | external false, taint 0 | A04 | **allow** |
| 6 | Same, flagged session | taint 2, blast high (mailer) | A04, H02, H05 | **hold** |
| 7 | Demo step 4, `send_email` to `attacker@evil.example`, flagged | external, impact high | H01, H02, H05, H09 | **hold** |
| 8 | `delete_records` 1 id, clean | irreversible, impact high | H09 | **hold** |
| 9 | `delete_records` 1 id, flagged | taint 2 | B01, H09 | **block** |
| 10 | `delete_records` 5 ids, clean | irreversible, count 5 | H04, H09 | **hold** |
| 11 | `web.fetch`, clean / flagged | taint 0 / 2 | A01 / A01, H08 | **allow** / **hold** |
| 12 | `send_email` body contains a canary | step 5 | `AG-CON-PROTECTED` | **block** (X-05) |
| 13 | `send_email` to `x@pastebin.example` | step 5 | `AG-CON-DOMAIN-DENY` | **block** |
| 14 | `drive.format` (unregistered) | step 2 | `AG-DENY-ACTION` | **block** |
| 15 | `query_customers {limit:21}` clean | count 21 | H03 | **hold** |
| 16 | `query_customers {limit:501}` | step 5 | `AG-CON-RECORDS-MAX` | **block** |

## 8. Editing semantics (PE-06, X-07)

* Editable: rule list, thresholds, ingress table (except the pinned cell), constraint lists, impact factors, LLM settings, TTLs, internal domains.
* The editor shows a structural diff against the active version. Saving calls `POST /policy/proposals`.
* The fingerprint of a proposal is `SHA-256(canonical_json({action_type:"policy.update", base_version, diff}))` where `diff` is the ordered RFC 6902 op list from a deterministic differ (ops sorted by path, then op). Approval recomputes it from the stored proposal against the current active version. A mismatch or a moved base is `policy.stale_base`.
* Worked example: raising `AG-R-H03`'s row threshold from 20 to 10 is a one-op diff `replace /action_rules/7/when/all/2/any/1/value`. It is held until Dana approves what Admin proposed.
* Content read by an agent has no path to any of this: the proposal endpoint is human plane only, requires role `admin`, and `promptshield` has no import path to the policy writer (PS-09).
