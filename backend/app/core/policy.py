"""
Deterministic policy engine (PE-01..PE-07).

Design (spec.md §1.1):
  evaluate(request, policy) is a pure function — no clock, randomness, or network.
  Deny-overrides: strictest outcome wins (PE-02).
  Default deny: unknown outcome → policy.default_outcome (PE-03).
  Versioned, immutable: each version is a DB row; UPDATE/DELETE blocked by triggers (PE-04).
  Lint + floor invariants enforced on every proposed policy (PE-05).

Outcome strictness (spec.md §0):
  block (3) > hold = escalate (2) > sanitize (1) > allow (0)
"""

from __future__ import annotations

import json
import re
from typing import Any

# ── Strictness ordering ───────────────────────────────────────────────────────

_STRICTNESS: dict[str, int] = {
    "allow": 0,
    "sanitize": 1,
    "escalate": 2,
    "hold": 2,
    "block": 3,
}

_ORDINAL: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3, "none": -1}

_ORDINAL_FIELDS = {"blast.level", "impact.level", "action.sensitivity"}


def strictness(outcome: str) -> int:
    return _STRICTNESS.get(outcome, -1)


# ── Context error ─────────────────────────────────────────────────────────────

class ContextError(Exception):
    """Raised when a required context field is absent (PE-07)."""
    def __init__(self, field: str) -> None:
        super().__init__(f"Required context field missing: {field}")
        self.field = field


# ── Required context fields per kind (PE-07, policy-spec.md §3.4) ─────────────

_REQUIRED_FIELDS: dict[str, list[str]] = {
    "action": [
        "agent.id", "agent.status", "action.type", "action.reversible",
        "action.record_count", "action.sensitivity", "action.destination_external",
        "impact.level", "blast.level", "session.taint_level",
    ],
    "ingress": ["tier", "session.taint_level"],
    "policy_change": ["proposer.id", "proposer.is_admin", "diff.size", "base_version"],
}


def _get_field(context: dict[str, Any], field: str) -> Any:
    """Retrieve a dotted field path from context. Supports flat dotted keys and nested dicts."""
    if field in context:
        return context[field]
    parts = field.split(".")
    cur: Any = context
    for p in parts:
        if not isinstance(cur, dict) or p not in cur:
            return _MISSING
        cur = cur[p]
    return cur


_MISSING = object()  # sentinel for absent optional fields


def _check_required(kind: str, context: dict[str, Any]) -> None:
    """PE-07: raise ContextError if a required field is missing."""
    for field in _REQUIRED_FIELDS.get(kind, []):
        if _get_field(context, field) is _MISSING:
            raise ContextError(field)


# ── Condition evaluator ───────────────────────────────────────────────────────

def eval_cond(cond: dict[str, Any], context: dict[str, Any]) -> bool:
    """Evaluate a condition node against the context.

    Combinators: all, any, not.
    Leaves: {field, op, value}.
    Missing optional fields evaluate to False (not ContextError) per PE-07.
    """
    if "all" in cond:
        return all(eval_cond(c, context) for c in cond["all"])
    if "any" in cond:
        return any(eval_cond(c, context) for c in cond["any"])
    if "not" in cond:
        return not eval_cond(cond["not"], context)

    # Leaf
    field: str = cond["field"]
    op: str = cond["op"]
    value: Any = cond["value"]

    actual = _get_field(context, field)
    if actual is _MISSING:
        # Absent optional field → false (PE-07: required fields already checked)
        return False

    return _compare(actual, op, value, field in _ORDINAL_FIELDS)


def _compare(actual: Any, op: str, value: Any, ordinal: bool) -> bool:
    if ordinal:
        a = _ORDINAL.get(str(actual), -1)
        v = _ORDINAL.get(str(value), -1)
        if op == "eq":
            return a == v
        if op == "ne":
            return a != v
        if op == "gt":
            return a > v
        if op == "gte":
            return a >= v
        if op == "lt":
            return a < v
        if op == "lte":
            return a <= v
    else:
        if op == "eq":
            return bool(actual == value)
        if op == "ne":
            return bool(actual != value)
        if op == "gt":
            return bool(actual > value)
        if op == "gte":
            return bool(actual >= value)
        if op == "lt":
            return bool(actual < value)
        if op == "lte":
            return bool(actual <= value)
        if op == "in":
            return bool(actual in value)
        if op == "not_in":
            return bool(actual not in value)
    return False


# ── Decision result ───────────────────────────────────────────────────────────

class Decision:
    """Result of a policy evaluation."""

    def __init__(
        self,
        outcome: str,
        reason: str,
        rule_ids: list[str],
        policy_version: int = 0,
        decision_path: str = "rules",
    ) -> None:
        self.outcome = outcome
        self.reason = reason
        self.rule_ids = rule_ids
        self.policy_version = policy_version
        self.decision_path = decision_path

    def tighten_to(self, new_outcome: str, rule: str) -> Decision:
        """Return a new Decision with outcome tightened to *new_outcome* (LA-04)."""
        assert strictness(new_outcome) >= strictness(self.outcome), \
            f"tighten_to: {new_outcome} is not stricter than {self.outcome}"
        new_rule_ids = list(self.rule_ids)
        if rule not in new_rule_ids:
            new_rule_ids.insert(0, rule)
        return Decision(
            outcome=new_outcome,
            reason=self.reason,
            rule_ids=new_rule_ids,
            policy_version=self.policy_version,
            decision_path=self.decision_path,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_path": self.decision_path,
            "outcome": self.outcome,
            "policy_version": self.policy_version,
            "reason": self.reason,
            "rule_ids": self.rule_ids,
        }


class DecisionRequest:
    """Request envelope for policy evaluation."""
    def __init__(self, kind: str, context: dict[str, Any], policy_version: int | None = None) -> None:
        self.kind = kind
        self.context = context
        self.policy_version = policy_version


# ── Policy engine ─────────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Deterministic policy evaluator (PE-01..PE-07).

    Usage:
        engine = PolicyEngine()
        decision = engine.evaluate(kind="action", context={...})
        # or
        decision = engine.evaluate(DecisionRequest("action", context={...}))
    """

    def __init__(self) -> None:
        self._cache: dict[int, dict[str, Any]] = {}

    def _load(self, version: int | None = None) -> dict[str, Any]:
        """Load policy from DB; cache by version. Raises if unavailable."""
        from backend.app.db import get_connection
        conn = get_connection()
        if version is None:
            row = conn.execute(
                "SELECT version, content_json FROM policy_versions "
                "WHERE activated_at IS NOT NULL ORDER BY version DESC LIMIT 1"
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT version, content_json FROM policy_versions WHERE version=?", (version,)
            ).fetchone()

        if row is None:
            raise RuntimeError("PE-ERR-NOPOLICY")

        ver = row[0]
        if ver not in self._cache:
            self._cache[ver] = json.loads(row[1])
            self._cache[ver]["_version"] = ver
        return self._cache[ver]

    def load_active_policy(self) -> dict[str, Any]:
        """Return the active policy document dict."""
        return self._load()

    def tighten_outcome(self, old_outcome: str, proposed_outcome: str) -> str:
        """Return the stricter outcome between old and proposed (LA-04)."""
        if strictness(proposed_outcome) > strictness(old_outcome):
            return proposed_outcome
        return old_outcome

    def invalidate_cache(self) -> None:
        """Clear the version cache (call after activating a new version)."""
        self._cache.clear()

    def active_version(self) -> int:
        """Return the currently active policy version number."""
        policy = self._load()
        return int(policy["_version"])

    def evaluate(
        self,
        kind_or_req: str | DecisionRequest,
        context: dict[str, Any] | None = None,
        policy_version: int | None = None,
    ) -> Decision:
        """
        PE-01..PE-07: Deterministic evaluation.

        Args:
            kind_or_req: "action" | "ingress" | "policy_change" or DecisionRequest
            context: dict of named fields (optional if DecisionRequest passed)
            policy_version: pin a specific version; None = active

        Returns Decision. Never raises (all errors → block).
        """
        if isinstance(kind_or_req, DecisionRequest):
            kind = kind_or_req.kind
            context = kind_or_req.context
            policy_version = kind_or_req.policy_version or policy_version
        else:
            kind = kind_or_req
            if context is None:
                context = {}

        try:
            policy = self._load(policy_version)
        except RuntimeError:
            return Decision("block", "No policy available.", ["PE-ERR-NOPOLICY"])

        ver = policy["_version"]

        # PE-07: check required context fields
        try:
            _check_required(kind, context)
        except ContextError as exc:
            return Decision(
                "block",
                f"Required context field missing: {exc.field}",
                ["PE-ERR-CONTEXT"],
                policy_version=ver,
            )

        # Select rule set
        if kind == "policy_change":
            rules = policy.get("policy_rules", [])
        else:
            rules = policy.get("action_rules", [])

        # Evaluate each rule (PE-02)
        matched: list[dict[str, Any]] = []
        for rule in rules:
            try:
                if eval_cond(rule["when"], context):
                    matched.append(rule)
            except Exception:
                # Malformed rule condition → skip (fail safe)
                pass

        # For ingress: also check the outcome table (PS-06)
        if kind == "ingress":
            table_matches = self._ingress_table_matches(context, policy)
            matched.extend(table_matches)

        if not matched:
            default = policy.get("default_outcome", "block")
            reason = policy.get("default_justification", "No rule matched.")
            return Decision(default, reason, ["PE-DEFAULT"], policy_version=ver)

        # Sort: strictness desc, priority asc, id asc (PE-02)
        matched.sort(key=lambda r: (-strictness(r["outcome"]), r["priority"], r["id"]))
        top = matched[0]
        rule_ids = [r["id"] for r in matched]

        return Decision(
            outcome=top["outcome"],
            reason=top["reason"],
            rule_ids=rule_ids,
            policy_version=ver,
        )

    def _ingress_table_matches(
        self, context: dict[str, Any], policy: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        PS-06: For each finding in context['findings'], look up the outcome table
        and produce a synthetic rule match.
        """
        thresholds = policy.get("ingress", {}).get("thresholds", {})
        table = policy.get("ingress", {}).get("table", {})
        tier = context.get("tier", "user")
        tier_table = table.get(tier, {})
        act_min = thresholds.get("act_min", 60)
        band_min = thresholds.get("band_min", 40)
        high_impact = set(thresholds.get("high_impact_types", []))

        matches: list[dict[str, Any]] = []
        for finding in context.get("findings", []):
            ftype = finding.get("type", "")
            conf = finding.get("confidence_pct", 0)

            if conf < band_min:
                continue

            if conf >= act_min:
                # Full table outcome
                outcome = tier_table.get(ftype, "allow")
                rule_id = f"PS-R-{tier.upper()}-{ftype.upper()}"
            else:
                # Low-confidence band (40..59)
                if ftype in high_impact:
                    outcome = "escalate"
                    rule_id = "PS-R-LOWCONF-ESCALATE"
                else:
                    continue  # weak, no match

            matches.append({
                "id": rule_id,
                "priority": 50,
                "outcome": outcome,
                "reason": f"Ingress finding: {ftype} at {conf}%",
                "when": {},  # already matched
            })

        return matches


# ── Lint / floor invariants (PE-05) ─────────────────────────────────────────

def lint_policy(doc: dict[str, Any]) -> list[str]:
    """
    Validate a policy document against the floor invariants (PE-05).

    Returns a list of error strings. Empty list means the policy is valid.
    """
    errors: list[str] = []

    # 1. default_outcome in {block, hold}
    default = doc.get("default_outcome")
    if default not in ("block", "hold"):
        errors.append("default_outcome must be 'block' or 'hold'.")
    if default == "hold" and not doc.get("default_justification"):
        errors.append("default_justification is required when default_outcome is 'hold'.")

    # 2. protected_value_scan must be true
    pv_scan = doc.get("constraints", {}).get("global", {}).get("protected_value_scan")
    if pv_scan is not True:
        errors.append("constraints.global.protected_value_scan must be true.")

    # 3. PC-R-001 must exist unchanged, no allow rule for policy.update
    policy_rules = doc.get("policy_rules", [])
    action_rules = doc.get("action_rules", [])
    pc_r001 = [r for r in policy_rules if r.get("id") == "PC-R-001"]
    if not pc_r001:
        errors.append("PC-R-001 must exist in policy_rules.")
    elif pc_r001[0].get("outcome") != "hold":
        errors.append("PC-R-001 must have outcome 'hold'.")
    for rule in policy_rules:
        if rule.get("outcome") == "allow":
            errors.append(f"Policy rule {rule.get('id')} has outcome 'allow', which is forbidden.")
    for rule in action_rules:
        if rule.get("outcome") == "allow" and "policy.update" in json.dumps(rule.get("when", {})):
            errors.append(f"Action rule {rule.get('id')} has outcome 'allow' for policy.update, which is forbidden.")

    # 4. Ingress table: every (tier x threat) cell must exist
    required_tiers = ["user", "retrieved_document", "tool_output"]
    required_threats = ["override", "extraction", "exfil_target", "protected_value", "hidden_content", "directive"]
    valid_outcomes = {"allow", "block", "sanitize", "escalate"}
    table = doc.get("ingress", {}).get("table", {})
    for tier in required_tiers:
        for threat in required_threats:
            cell = table.get(tier, {}).get(threat)
            if cell is None:
                errors.append(f"ingress.table.{tier}.{threat} is missing.")
            elif cell not in valid_outcomes:
                errors.append(f"ingress.table.{tier}.{threat} has invalid outcome '{cell}'.")

    # 5. ingress.thresholds.band_min <= act_min, both 0..100
    thresholds = doc.get("ingress", {}).get("thresholds", {})
    band_min = thresholds.get("band_min", 0)
    act_min = thresholds.get("act_min", 60)
    if not (0 <= band_min <= 100):
        errors.append("ingress.thresholds.band_min must be 0..100.")
    if not (0 <= act_min <= 100):
        errors.append("ingress.thresholds.act_min must be 0..100.")
    if band_min > act_min:
        errors.append("ingress.thresholds.band_min must be <= act_min.")

    # 6. Unique rule IDs; regexes compile and are safe
    all_rules = doc.get("action_rules", []) + doc.get("policy_rules", [])
    rule_ids_seen: set[str] = set()
    for rule in all_rules:
        rid = rule.get("id", "")
        if rid in rule_ids_seen:
            errors.append(f"Duplicate rule id: {rid}.")
        rule_ids_seen.add(rid)

    for cp in doc.get("constraints", {}).get("global", {}).get("forbidden_patterns", []):
        regex = cp.get("regex", "")
        if len(regex) > 200:
            errors.append(f"Forbidden pattern {cp.get('id')} regex is over 200 characters.")
        try:
            re.compile(regex)
        except re.error as e:
            errors.append(f"Forbidden pattern {cp.get('id')} regex does not compile: {e}.")
        if re.search(r"\([^)]*[+*][^)]*\)[+*]", regex):
            errors.append(f"Forbidden pattern {cp.get('id')} regex has nested quantifiers.")

    # 7. No condition references impact.score
    def _check_no_score(obj: Any) -> None:
        if isinstance(obj, dict):
            if obj.get("field") == "impact.score":
                errors.append("Rules may not reference impact.score.")
            for v in obj.values():
                _check_no_score(v)
        elif isinstance(obj, list):
            for item in obj:
                _check_no_score(item)

    for rule in all_rules:
        _check_no_score(rule.get("when", {}))

    # 8. TTL ranges
    s = doc.get("settings", {})
    ttl = s.get("approval_ttl_s", 900)
    if not (60 <= ttl <= 3600):
        errors.append(f"settings.approval_ttl_s must be 60..3600, got {ttl}.")
    llm_timeout = s.get("llm", {}).get("timeout_ms", 3000)
    if not (100 <= llm_timeout <= 10000):
        errors.append(f"settings.llm.timeout_ms must be 100..10000, got {llm_timeout}.")

    # 9. ingress.table.user.protected_value must be 'block' (canary guarantee)
    user_pv = table.get("user", {}).get("protected_value")
    if user_pv != "block":
        errors.append("ingress.table.user.protected_value must be 'block' (canary guarantee).")

    return errors


lint = lint_policy


# ── Module-level singleton ────────────────────────────────────────────────────

_engine = PolicyEngine()


def get_engine() -> PolicyEngine:
    """Return the shared PolicyEngine instance."""
    return _engine
