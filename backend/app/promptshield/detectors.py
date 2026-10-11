"""
PromptShield detectors D1..D6 (PS-02..PS-05, PS-11..PS-13, spec §4.3).

- D1: override (PS-02)
- D2: extraction (PS-03)
- D3: exfil_target (PS-04)
- D4: protected_value (PS-05)
- D5: hidden_content (PS-11)
- D6: directive (PS-12)
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from backend.app.promptshield.normalization import (
    DecodedLayer,
    decode_layers,
    strip,
)

# ── Seed canaries & default protected values ──────────────────────────────────
SEED_PROTECTED_VALUES = [
    {"pv_id": "pv-apikey-1", "kind": "canary", "value": "sk-acme-4c1f9e27b8a3d605e7f1", "shape_regex": r"sk-acme-[0-9a-f]{16,}"},
    {"pv_id": "pv-nid-1", "kind": "national_id", "value": "NID-4417-9082-3361", "shape_regex": r"NID-\d{4}-\d{4}-\d{4}"},
    {"pv_id": "pv-marker-1", "kind": "canary", "value": "CANARY::acme::0x7d3e91", "shape_regex": r"CANARY::acme::0x[0-9a-f]{4,}"},
]

INTERNAL_DOMAINS = {"acme.example", "shop.example"}

# ── Regexes ───────────────────────────────────────────────────────────────────
AI_ADDRESSEE_REGEX = re.compile(
    r"(?i)\b(ai assistant|assistant|chatgpt|claude|supportbot|model)\b",
)

FRAMING_PREFIX_REGEX = re.compile(
    r"(?i)\b(such as|for example|e\.g\.|the phrase|an example of|attackers (?:may|often|can)|prompt injection|jailbreak|researchers|this article|known as|security blog|quoting|reading a blog)\b",
)

# D1 Override patterns
O1_VERB_OBJ = re.compile(
    r"\b(ignore|disregard|forget|bypass|override|drop|cancel|dismiss|reset|update|change|alter|modify|set)\b.{1,40}?\b(all|previous|prior|initial|system|safety|\s+)*\s*(instructions|rules|prompt|prompts|system prompt|constraints|guidelines|directions|directives|commands|guardrails|safety rules|safety protocols|protocols|policy|default_outcome)\b",
    re.IGNORECASE,
)
O2_ROLE = re.compile(
    r"\b(you are now\s+[a-z0-9_ -]+|act as\s+[a-z0-9_ -]+|jailbreak mode|pretend you (?:have no|are without) rules|unrestricted ai|unrestricted assistant|dan mode|\bdan\b|developer mode enabled|in admin mode|developer override mode)\b",
    re.IGNORECASE,
)
O3_FAKE_SYS = re.compile(
    r"(\[system\]|\[system message\]|<\|im_start\|>system|<<<system>>>|<<sys>>|system note:|developer note:|developer mode:|emergency administrative override)",
    re.IGNORECASE,
)
POSSESSIVE_CHECK = re.compile(
    r"\b(my|our)\s+(previous|prior)?\s*(instructions|email|manual|kettle|order)\b|\b(delivery instructions|delivery address|delivery note)\b",
    re.IGNORECASE,
)

# D2 Extraction patterns
D2_EXTRACTION = re.compile(
    r"\b(show|tell|print|reveal|repeat|dump|output|give|disclose|what (?:was|were|are))\b.{1,35}?\b(initial|secret|hidden|verbatim|developer|confidential|full|system|all|\s+)*\s*(system prompt|prompt|instructions|developer instructions|system instructions|prompt template|secret guidelines)\b",
    re.IGNORECASE,
)
D2_STORE_CONTEXT = re.compile(
    r"(?i)\b(return|refund|shipping|store|opening|hours|delivery|exchange|warranty|policy)\b",
)

# D3 Exfil patterns
URL_REGEX = re.compile(r"https?://[a-zA-Z0-9_.:-]+(/[^\s<>\"']*)?")
EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b")
MD_BEACON_REGEX = re.compile(r"!\[(.*?)\]\((https?://[^\s)]+)\)")
HTML_BEACON_REGEX = re.compile(r"""<img\s+[^>]*src=["'](https?://[^"']+)["']""", re.I)

DATA_MOVING_VERB = re.compile(r"\b(send|email|post|upload|exfiltrate|forward|transmit|leak)\b", re.IGNORECASE)
DATA_NOUN = re.compile(
    r"\b(customer list|customers|data|passwords|secrets|orders|canary|database|user data|customer data|emails|confidential emails|records|details|sensitive data|files|findings|credentials|keys|information)\b",
    re.IGNORECASE,
)

WEBHOOK_DOMAINS = {"webhook.site", "pipedream.net", "burpcollaborator.net", "requestbin.com"}

# D5 Hidden patterns
HTML_COMMENT_REGEX = re.compile(r"<!--(.*?)-->", re.S)
ZERO_WIDTH_RUN = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad]{4,}")
CSS_HIDDEN_REGEX = re.compile(
    r"""(?i)<(?:span|div|p)\s+[^>]*style=["'][^"']*(?:display:\s*none|visibility:\s*hidden|opacity:\s*0|font-size:\s*0)[^"']*["'][^>]*>(.*?)</(?:span|div|p)>""",
    re.S,
)

# D6 Directive patterns
D6_AI_DIRECTIVE = re.compile(
    r"\b(ai assistant|assistant|supportbot)[:,]?\s*(?:please\s+)?(forward|send|email|exfiltrate|write|fetch|execute|run)\b",
    re.IGNORECASE,
)
D6_GENERIC = re.compile(
    r"(?i)\b(you (?:must|should|need to))\s+(forward|send|email|exfiltrate|transmit|upload)\b",
)


class Finding:
    def __init__(
        self,
        finding_type: str,
        start: int | None,
        end: int | None,
        confidence_pct: int,
        evidence: str,
        encoding: str = "plain",
        signals: list[str] | None = None,
        detector: str = "D1",
        weak: bool = False,
    ) -> None:
        self.type = finding_type
        self.start = start
        self.end = end
        self.confidence_pct = max(0, min(100, confidence_pct))
        self.evidence = evidence[:80]
        self.encoding = encoding
        self.signals = signals or []
        self.detector = detector
        self.weak = weak

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "confidence_pct": self.confidence_pct,
            "evidence": self.evidence,
            "encoding": self.encoding,
            "signals": self.signals,
            "detector": self.detector,
            "weak": self.weak,
        }


def check_framing(text: str, start: int) -> bool:
    """Check if match is inside quotes or preceded by framing markers (PS-13)."""
    # Check quotes: count double quotes before start
    prefix = text[:start]
    if prefix.count('"') % 2 == 1 or prefix.count("'") % 2 == 1:
        return True

    # Preceded by framing marker within 120 chars
    window = prefix[-120:]
    return bool(FRAMING_PREFIX_REGEX.search(window))


def detect_d1_override(text: str, tier: str, exfil_co_occurs: bool = False) -> list[Finding]:
    """D1 Override detector (PS-02, spec §4.3)."""
    findings: list[Finding] = []

    # 1. O1: verb + object
    for m in O1_VERB_OBJ.finditer(text):
        match_str = m.group(0)
        start, end = m.start(), m.end()

        # Check possessives immediately before object (e.g. 'my previous email')
        if POSSESSIVE_CHECK.search(match_str) or POSSESSIVE_CHECK.search(text[max(0, start-20):end]):
            # -30 discount
            score = 60 - 30
        else:
            score = 60

        # Modifiers
        # AI addressee within 80 chars
        ctx_window = text[max(0, start - 80): min(len(text), end + 80)]
        if AI_ADDRESSEE_REGEX.search(ctx_window):
            score += 15

        if tier in ("retrieved_document", "tool_output"):
            score += 10

        if exfil_co_occurs:
            score += 15

        if check_framing(text, start):
            score -= 30

        if score >= 35:
            findings.append(Finding(
                finding_type="override",
                start=start,
                end=end,
                confidence_pct=score,
                evidence=match_str,
                encoding="plain",
                signals=["O1_verb_object"],
                detector="D1",
                weak=score < 40,
            ))

    # 2. O2: role reassignment
    for m in O2_ROLE.finditer(text):
        start, end = m.start(), m.end()
        score = 65
        ctx_window = text[max(0, start - 80): min(len(text), end + 80)]
        if AI_ADDRESSEE_REGEX.search(ctx_window):
            score += 15
        if tier in ("retrieved_document", "tool_output"):
            score += 10
        if exfil_co_occurs:
            score += 15
        if check_framing(text, start):
            score -= 30

        if score >= 35:
            findings.append(Finding(
                finding_type="override",
                start=start,
                end=end,
                confidence_pct=score,
                evidence=m.group(0),
                encoding="plain",
                signals=["O2_role_reassignment"],
                detector="D1",
                weak=score < 40,
            ))

    # 3. O3: fake system delimiters
    for m in O3_FAKE_SYS.finditer(text):
        start, end = m.start(), m.end()
        score = 65
        if tier != "developer":
            score += 10
        if tier in ("retrieved_document", "tool_output"):
            score += 10
        if exfil_co_occurs:
            score += 15
        if check_framing(text, start):
            score -= 30

        if score >= 35:
            findings.append(Finding(
                finding_type="override",
                start=start,
                end=end,
                confidence_pct=score,
                evidence=m.group(0),
                encoding="plain",
                signals=["O3_fake_system"],
                detector="D1",
                weak=score < 40,
            ))

    return findings


def detect_d2_extraction(text: str, tier: str) -> list[Finding]:
    """D2 Prompt Extraction detector (PS-03, spec §4.3)."""
    findings: list[Finding] = []

    for m in D2_EXTRACTION.finditer(text):
        start, end = m.start(), m.end()
        # Store context exclusion check: within 6 words after object
        following = text[end: min(len(text), end + 50)]
        if D2_STORE_CONTEXT.search(following):
            continue  # Store context: opening hours, return policy -> NO finding!

        score = 65
        if tier != "user":
            score += 10
        if check_framing(text, start):
            score -= 40

        if score >= 35:
            findings.append(Finding(
                finding_type="extraction",
                start=start,
                end=end,
                confidence_pct=score,
                evidence=m.group(0),
                encoding="plain",
                signals=["system_prompt_extraction"],
                detector="D2",
                weak=score < 40,
            ))

    return findings


def detect_d3_exfil_target(text: str, tier: str) -> list[Finding]:
    """D3 Exfil Target detector (PS-04, spec §4.3)."""
    findings: list[Finding] = []

    # 1. Markdown Image Beacon: ![alt](url)
    for m in MD_BEACON_REGEX.finditer(text):
        start, end = m.start(), m.end()
        url = m.group(2)
        dom = urllib.parse.urlparse(url).netloc.split(":")[0].lower()
        if dom in INTERNAL_DOMAINS:
            continue

        query = urllib.parse.urlparse(url).query
        if query or "{{" in url or "?" in url:
            score = 85
            sig = "beacon_with_placeholder"
        else:
            score = 65
            sig = "beacon_without_placeholder"

        findings.append(Finding(
            finding_type="exfil_target",
            start=start,
            end=end,
            confidence_pct=score,
            evidence=m.group(0),
            encoding="plain",
            signals=[sig],
            detector="D3",
            weak=score < 40,
        ))

    # 2. HTML Image Beacon: <img src="url">
    for m in HTML_BEACON_REGEX.finditer(text):
        start, end = m.start(), m.end()
        url = m.group(1)
        dom = urllib.parse.urlparse(url).netloc.split(":")[0].lower()
        if dom in INTERNAL_DOMAINS:
            continue
        query = urllib.parse.urlparse(url).query
        score = 85 if query or "?" in url else 65

        findings.append(Finding(
            finding_type="exfil_target",
            start=start,
            end=end,
            confidence_pct=score,
            evidence=m.group(0),
            encoding="plain",
            signals=["html_image_beacon"],
            detector="D3",
            weak=score < 40,
        ))

    # 3. External Email or URL
    # Look for destinations and preceding data-moving verbs/nouns
    targets: list[tuple[int, int, str, str]] = []
    for m in EMAIL_REGEX.finditer(text):
        dom = m.group(1).lower()
        if dom not in INTERNAL_DOMAINS:
            targets.append((m.start(), m.end(), m.group(0), dom))

    for m in URL_REGEX.finditer(text):
        url = m.group(0)
        dom = urllib.parse.urlparse(url).netloc.split(":")[0].lower()
        if dom not in INTERNAL_DOMAINS:
            targets.append((m.start(), m.end(), url, dom))

    for t_start, t_end, _target_str, dom in targets:
        # Preceding window within 120 chars
        window_120 = text[max(0, t_start - 120): t_start]
        has_verb = bool(DATA_MOVING_VERB.search(window_120))
        has_noun = bool(DATA_NOUN.search(window_120))

        if has_verb and has_noun:
            score = 90
            sig = "exfil_verb_and_data_noun"
            # Span extends from instruction clause start
            verb_m = list(DATA_MOVING_VERB.finditer(window_120))
            clause_offset = verb_m[-1].start() if verb_m else 0
            finding_start = max(0, t_start - 120) + clause_offset
            # End includes target and sentence end
            finding_end = t_end
            if finding_end < len(text) and text[finding_end] in ".;\n":
                finding_end += 1
        elif dom in WEBHOOK_DOMAINS:
            score = 45
            sig = "webhook_domain"
            finding_start, finding_end = t_start, t_end
        else:
            score = 20
            sig = "external_dest_no_instruction"
            finding_start, finding_end = t_start, t_end

        if check_framing(text, finding_start):
            score = max(45, score - 30) if has_verb and has_noun else score - 30

        if score >= 35:
            findings.append(Finding(
                finding_type="exfil_target",
                start=finding_start,
                end=finding_end,
                confidence_pct=score,
                evidence=text[finding_start:finding_end],
                encoding="plain",
                signals=[sig],
                detector="D3",
                weak=score < 40,
            ))

    return findings


def detect_d4_protected_values(text: str, decoded_layers: list[DecodedLayer] | None = None) -> list[Finding]:
    """D4 Protected Values detector (PS-05, spec §4.3)."""
    findings: list[Finding] = []

    # 1. Check exact match in plain text
    for pv in SEED_PROTECTED_VALUES:
        val = pv["value"]
        if val in text:
            idx = text.find(val)
            findings.append(Finding(
                finding_type="protected_value",
                start=idx,
                end=idx + len(val),
                confidence_pct=98,
                evidence=f"[REDACTED:{pv['pv_id']}]",
                encoding="plain",
                signals=["exact_match_plain"],
                detector="D4",
                weak=False,
            ))

    # 2. Check stripped/normalized form (spaced, separators, zero-width, case)
    stripped_text, s_idx_map = strip(text)
    for pv in SEED_PROTECTED_VALUES:
        pv_stripped, _ = strip(pv["value"])
        if pv_stripped in stripped_text:
            pos = stripped_text.find(pv_stripped)
            start_orig = s_idx_map[pos]
            end_orig = s_idx_map[pos + len(pv_stripped) - 1] + 1
            raw_sub = text[start_orig:end_orig]

            # Determine encoding: case, spaced, plain
            if raw_sub == pv["value"]:
                enc = "plain"
            elif raw_sub.lower() == pv["value"].lower() and " " not in raw_sub and "_" not in raw_sub:
                enc = "case"
            else:
                enc = "spaced"

            # Avoid duplicating exact plain matches
            if not any(f.type == "protected_value" and f.start == start_orig for f in findings):
                findings.append(Finding(
                    finding_type="protected_value",
                    start=start_orig,
                    end=end_orig,
                    confidence_pct=98,
                    evidence=f"[REDACTED:{pv['pv_id']}]",
                    encoding=enc,
                    signals=["normalized_match"],
                    detector="D4",
                    weak=False,
                ))

    # 3. Check inside decoded layers (base64, hex, url, depth 2)
    layers = decoded_layers if decoded_layers is not None else decode_layers(text)
    for layer in layers:
        for pv in SEED_PROTECTED_VALUES:
            val = pv["value"]
            if val in layer.text or strip(val)[0] in strip(layer.text)[0]:
                enc_name = layer.encoding
                if ">" in enc_name:
                    enc_name = f"nested:{enc_name}"

                findings.append(Finding(
                    finding_type="protected_value",
                    start=layer.start,
                    end=layer.end,
                    confidence_pct=95,
                    evidence=f"[REDACTED:{pv['pv_id']}]",
                    encoding=enc_name,
                    signals=["decoded_layer_match"],
                    detector="D4",
                    weak=False,
                ))

    # 4. Shape-only checks (near-misses / unregistered shape matches)
    for pv in SEED_PROTECTED_VALUES:
        pattern = re.compile(pv["shape_regex"], re.I)
        for m in pattern.finditer(text):
            matched_val = m.group(0)
            # If not exact match with registered values -> shape-only match at 70
            if matched_val.lower() != pv["value"].lower():
                findings.append(Finding(
                    finding_type="protected_value",
                    start=m.start(),
                    end=m.end(),
                    confidence_pct=70,
                    evidence="[SHAPE_MATCH]",
                    encoding="plain",
                    signals=["shape_only_match"],
                    detector="D4",
                    weak=False,
                ))

    return findings


def detect_d5_hidden_content(text: str, tier: str, decoded_layers: list[DecodedLayer] | None = None) -> list[Finding]:
    """D5 Hidden Content detector (PS-11, spec §4.3)."""
    findings: list[Finding] = []

    # 1. HTML comments: <!-- ... -->
    for m in HTML_COMMENT_REGEX.finditer(text):
        start, end = m.start(), m.end()
        inner_content = m.group(1)

        # Run inner detectors
        inner_findings = []
        inner_findings += detect_d1_override(inner_content, tier)
        inner_findings += detect_d2_extraction(inner_content, tier)
        inner_findings += detect_d3_exfil_target(inner_content, tier)
        inner_findings += detect_d6_directive(inner_content, tier)

        strong_inner = any(f.confidence_pct >= 40 for f in inner_findings)
        if strong_inner:
            findings.append(Finding(
                finding_type="hidden_content",
                start=start,
                end=end,
                confidence_pct=85,
                evidence=m.group(0),
                encoding="plain",
                signals=["html_comment"],
                detector="D5",
                weak=False,
            ))
            # Include inner findings with adjusted offsets
            for f in inner_findings:
                if f.confidence_pct >= 40:
                    f.start = start + 4 + (f.start or 0)
                    f.end = start + 4 + (f.end or len(inner_content))
                    findings.append(f)

    # 2. Zero-width runs
    for m in ZERO_WIDTH_RUN.finditer(text):
        start, end = m.start(), m.end()
        findings.append(Finding(
            finding_type="hidden_content",
            start=start,
            end=end,
            confidence_pct=35,
            evidence="[ZERO_WIDTH_RUN]",
            encoding="plain",
            signals=["zero_width_run"],
            detector="D5",
            weak=True,
        ))

    # 3. CSS-hidden elements
    for m in CSS_HIDDEN_REGEX.finditer(text):
        start, end = m.start(), m.end()
        inner_content = m.group(1)
        inner_f = detect_d1_override(inner_content, tier) + detect_d6_directive(inner_content, tier)
        strong = any(f.confidence_pct >= 40 for f in inner_f)
        score = 85 if strong else 35

        findings.append(Finding(
            finding_type="hidden_content",
            start=start,
            end=end,
            confidence_pct=score,
            evidence=m.group(0),
            encoding="plain",
            signals=["css_hidden_element"],
            detector="D5",
            weak=score < 40,
        ))

    # 4. Decoded layers with strong findings (e.g. base64 instruction rv-p5)
    layers = decoded_layers if decoded_layers is not None else decode_layers(text)
    for layer in layers:
        inner_f = detect_d1_override(layer.text, tier) + detect_d3_exfil_target(layer.text, tier) + detect_d6_directive(layer.text, tier)
        if any(f.confidence_pct >= 40 for f in inner_f):
            score = 90 if "tags" in layer.encoding else 85
            findings.append(Finding(
                finding_type="hidden_content",
                start=layer.start,
                end=layer.end,
                confidence_pct=score,
                evidence=layer.raw_blob,
                encoding=layer.encoding,
                signals=["encoded_hidden_instruction"],
                detector="D5",
                weak=False,
            ))
            for f in inner_f:
                if f.confidence_pct >= 40:
                    # Report span mapped to outer blob
                    f.start = layer.start
                    f.end = layer.end
                    findings.append(f)

    return findings


def detect_d6_directive(text: str, tier: str) -> list[Finding]:
    """D6 Directive detector for untrusted tiers (PS-12, spec §4.3)."""
    # Untrusted tiers only
    if tier not in ("retrieved_document", "tool_output"):
        return []

    findings: list[Finding] = []

    # 1. AI addressee plus imperative
    for m in D6_AI_DIRECTIVE.finditer(text):
        start = m.start()
        # Find sentence boundary or instruction clause end
        end = min(len(text), start + 120)
        dot_idx = text.find(".", start)
        if dot_idx != -1 and dot_idx < end:
            end = dot_idx + 1

        score = 70
        high_risk_verb = m.group(2).lower() in ("forward", "send", "email", "exfiltrate")
        if high_risk_verb:
            score += 15
        if tier == "tool_output":
            score += 10

        window = text[start: min(len(text), start + 200)]
        if EMAIL_REGEX.search(window) or URL_REGEX.search(window):
            score += 15

        if check_framing(text, start):
            score -= 40

        findings.append(Finding(
            finding_type="directive",
            start=start,
            end=end,
            confidence_pct=score,
            evidence=text[start:end],
            encoding="plain",
            signals=["ai_addressee_imperative"],
            detector="D6",
            weak=score < 40,
        ))

    # 2. Generic 'you should/must' only with data noun or external destination
    for m in D6_GENERIC.finditer(text):
        start = m.start()
        # Check sentence boundary
        dot_idx = text.find(".", start)
        end = dot_idx + 1 if dot_idx != -1 else min(len(text), start + 100)
        clause = text[start:end]

        has_data = bool(DATA_NOUN.search(clause))
        has_dest = bool(EMAIL_REGEX.search(clause) or URL_REGEX.search(clause))

        if has_data or has_dest:
            score = 45
            if tier == "tool_output":
                score += 10
            if check_framing(text, start):
                score -= 40

            findings.append(Finding(
                finding_type="directive",
                start=start,
                end=end,
                confidence_pct=score,
                evidence=clause,
                encoding="plain",
                signals=["generic_imperative_with_data"],
                detector="D6",
                weak=score < 40,
            ))

    return findings


def run_all_detectors(text: str, tier: str) -> list[Finding]:
    """Run all detectors D1..D6 and return combined list of findings."""
    layers = decode_layers(text)

    findings: list[Finding] = []
    findings += detect_d4_protected_values(text, decoded_layers=layers)
    findings += detect_d3_exfil_target(text, tier)

    has_exfil = any(f.type == "exfil_target" and f.confidence_pct >= 40 for f in findings)

    findings += detect_d1_override(text, tier, exfil_co_occurs=has_exfil)
    findings += detect_d2_extraction(text, tier)
    findings += detect_d5_hidden_content(text, tier, decoded_layers=layers)
    findings += detect_d6_directive(text, tier)
    return findings


# ── Convenience aliases for detectors ──────────────────────────────────────────
def detect_override(text: str, tier: str = "user") -> list[Finding]:
    return detect_d1_override(text, tier)


def detect_extraction(text: str, tier: str = "user") -> list[Finding]:
    return detect_d2_extraction(text, tier)


def detect_exfil_target(text: str, tier: str = "user") -> list[Finding]:
    return detect_d3_exfil_target(text, tier)


def detect_protected_values(text: str, tier: str = "user") -> list[Finding]:
    return detect_d4_protected_values(text)


def detect_hidden_content(text: str, tier: str = "user") -> list[Finding]:
    return detect_d5_hidden_content(text, tier)


def detect_directive(text: str, tier: str = "tool_output") -> list[Finding]:
    return detect_d6_directive(text, tier)
