"""
PromptShield sanitizer engine (PS-07, spec §4.4, seed-data §3.2).

- Isolates offending spans and merges adjacent/overlapping spans.
- Replaces with [removed by Sentinel: <types>] (sorted alphabetically).
- Rescans: upgrades to escalate on residual findings (PS-SAN-RESIDUAL).
- Checks span isolability: upgrades to escalate if span is None (PS-SAN-NOSPAN).
- Blocks with PS-SAN-EMPTY if clean alphanumeric remainder is < 8 chars.
"""

from __future__ import annotations

import re
from typing import Any

from backend.app.promptshield.detectors import Finding, run_all_detectors

MARKER_REGEX = re.compile(r"\[removed by Sentinel: [^\]]+\]")


def alnum_len(s: str) -> int:
    return sum(1 for c in s if c.isalnum())


def merge_spans(spans_with_types: list[tuple[int, int, str]], text: str) -> list[tuple[int, int, list[str]]]:
    """
    Merge spans that overlap or are separated only by whitespace.
    Collects distinct finding types sorted alphabetically.
    """
    if not spans_with_types:
        return []

    # Sort by start offset ascending
    sorted_spans = sorted(spans_with_types, key=lambda s: (s[0], s[1]))
    merged: list[tuple[int, int, set[str]]] = []

    for start, end, ftype in sorted_spans:
        # Clamp bounds
        s = max(0, start)
        e = min(len(text), end)

        # Expand end to include sentence-final punctuation if present (seed-data §3.2)
        while e < len(text) and text[e] in ".!?;:":
            e += 1

        if not merged:
            merged.append((s, e, {ftype}))
            continue

        prev_s, prev_e, prev_types = merged[-1]

        # Check if overlapping or separated only by whitespace and punctuation
        between = text[prev_e:s] if s >= prev_e else ""
        if s <= prev_e or all(c.isspace() or c in ".,!?;:" for c in between):
            # Merge!
            new_e = max(prev_e, e)
            prev_types.add(ftype)
            merged[-1] = (prev_s, new_e, prev_types)
        else:
            merged.append((s, e, {ftype}))

    return [(s, e, sorted(list(types))) for s, e, types in merged]


def sanitize_text(
    text: str,
    actionable_findings: list[Finding],
    tier: str,
) -> tuple[str, str, list[dict[str, Any]]]:
    """
    Sanitize text by replacing malicious spans with Sentinel removal markers (PS-07).
    Returns (outcome, sanitized_text, removed_spans_info).
    Outcomes: 'sanitize' (success), 'escalate' (residual/unisolable), 'block' (empty).
    """
    # Check unisolable spans
    if any(f.start is None or f.end is None for f in actionable_findings):
        return "escalate", text, []

    spans_with_types = [(f.start, f.end, f.type) for f in actionable_findings if f.start is not None and f.end is not None]
    merged = merge_spans(spans_with_types, text)

    # Reconstruct text with markers
    result_pieces: list[str] = []
    last_idx = 0
    removed_spans_info: list[dict[str, Any]] = []

    for s, e, types in merged:
        result_pieces.append(text[last_idx:s])
        marker = f"[removed by Sentinel: {', '.join(types)}]"
        result_pieces.append(marker)
        last_idx = e
        removed_spans_info.append({"types": types, "start": s, "end": e})

    result_pieces.append(text[last_idx:])
    sanitized_text = "".join(result_pieces)

    # Check empty remainder (less than 8 alphanumeric characters outside markers)
    clean_remainder = MARKER_REGEX.sub("", sanitized_text)
    if alnum_len(clean_remainder) < 8:
        return "block", sanitized_text, removed_spans_info

    # Rescan clean check (PS-SAN-RESIDUAL)
    rescan_findings = run_all_detectors(clean_remainder, tier)
    if any(f.confidence_pct >= 60 for f in rescan_findings):
        return "escalate", sanitized_text, removed_spans_info

    return "sanitize", sanitized_text, removed_spans_info
