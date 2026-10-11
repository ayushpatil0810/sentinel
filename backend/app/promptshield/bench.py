"""
PromptShield benchmark engine and honesty metrics (PS-08, spec §4.7, test-plan §5).

- Wilson 95% confidence intervals (D-28).
- Evaluation of TP, FP, TN, FN, precision, recall, F1, FPR.
- Honest miss table and false positive table reporting.
- Only 'test' split metrics reported for official benchmarks.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from backend.app.core.clock import get_clock
from backend.app.core.ids import next_id
from backend.app.db import get_connection
from backend.app.promptshield.shield import screen_text

BENCHMARK_PATH = Path(__file__).resolve().parent.parent.parent.parent / "seed" / "benchmark.json"


def wilson_interval(count: int, n: int, z: float = 1.95996) -> tuple[float, float]:
    """Calculate Wilson 95% score confidence interval (D-28)."""
    if n == 0:
        return 0.0, 0.0
    p = count / n
    denom = 1.0 + (z * z) / n
    center = (p + (z * z) / (2 * n)) / denom
    inner = (p * (1 - p)) / n + (z * z) / (4 * n * n)
    spread = (z * math.sqrt(max(0.0, inner))) / denom
    low = max(0.0, round(center - spread, 4))
    high = min(1.0, round(center + spread, 4))
    return low, high


def run_benchmark(split: str = "test", policy_version: int = 1) -> dict[str, Any]:
    """
    Run benchmark evaluation on specified split (PS-08).
    Returns complete metrics report matching api.md §2.7.
    """
    if not BENCHMARK_PATH.exists():
        raise FileNotFoundError(f"Benchmark file not found at {BENCHMARK_PATH}")

    with open(BENCHMARK_PATH, encoding="utf-8") as f:
        all_cases = json.load(f)

    cases = [c for c in all_cases if c.get("split") == split]
    n = len(cases)

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    misses: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []

    per_category_totals: dict[str, dict[str, int]] = {}
    per_tier_totals: dict[str, dict[str, int]] = {}
    direct_stats = {"tp": 0, "total": 0}
    indirect_stats = {"tp": 0, "total": 0}

    sanitize_cases = 0
    preserved_success = 0
    rescan_clean_success = 0

    run_id = next_id("run_")

    for c in cases:
        cid = c["id"]
        text = c["text"]
        tier = c["source_tier"]
        label = c["label"]
        cat = c["category"]
        style = c.get("attack_style", "none")
        expected_substrings = c.get("expected_clean_substrings", [])

        # Screen through PromptShield
        res = screen_text(tier=tier, text=text, is_lab=True)
        detected = res.outcome in ("block", "sanitize", "escalate")

        if label == "malicious":
            if style == "direct":
                direct_stats["total"] += 1
            elif style == "indirect":
                indirect_stats["total"] += 1

            cat_stat = per_category_totals.setdefault(cat, {"detected": 0, "total": 0})
            cat_stat["total"] += 1
            tier_stat = per_tier_totals.setdefault(tier, {"detected": 0, "total": 0})
            tier_stat["total"] += 1

            if detected:
                tp += 1
                cat_stat["detected"] += 1
                tier_stat["detected"] += 1
                if style == "direct":
                    direct_stats["tp"] += 1
                elif style == "indirect":
                    indirect_stats["tp"] += 1

                if res.outcome == "sanitize":
                    sanitize_cases += 1
                    # Check preserved substrings
                    sanitized_text = res.text_sanitized or ""
                    if all(sub in sanitized_text for sub in expected_substrings):
                        preserved_success += 1
                    # Check rescan clean
                    if "PS-SAN-RESIDUAL" not in res.rule_ids:
                        rescan_clean_success += 1
            else:
                fn += 1
                misses.append({
                    "id": cid,
                    "category": cat,
                    "explanation": f"Undetected {cat} in {tier}: outcome={res.outcome}",
                })

        else:  # label == "benign"
            if detected:
                fp += 1
                false_positives.append({
                    "id": cid,
                    "explanation": f"False positive in {tier}: outcome={res.outcome}, rule_ids={res.rule_ids}",
                })
            else:
                tn += 1

    # Calculations
    prec_val = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    rec_val = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1_val = round((2 * prec_val * rec_val) / (prec_val + rec_val), 4) if (prec_val + rec_val) > 0 else 0.0
    fpr_val = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0

    prec_ci = wilson_interval(tp, tp + fp)
    rec_ci = wilson_interval(tp, tp + fn)
    fpr_ci = wilson_interval(fp, fp + tn)

    per_category = {
        cat: round(s["detected"] / s["total"], 4) if s["total"] > 0 else 0.0
        for cat, s in per_category_totals.items()
    }
    per_tier = {
        t: round(s["detected"] / s["total"], 4) if s["total"] > 0 else 0.0
        for t, s in per_tier_totals.items()
    }

    preserved_pct = round(preserved_success / sanitize_cases * 100, 1) if sanitize_cases > 0 else 100.0
    rescan_clean_pct = round(rescan_clean_success / sanitize_cases * 100, 1) if sanitize_cases > 0 else 100.0

    now_iso = get_clock().now_iso()

    report = {
        "run_id": run_id,
        "ts": now_iso,
        "policy_version": policy_version,
        "split": split,
        "n": n,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": {"value": prec_val, "ci95": list(prec_ci)},
        "recall": {"value": rec_val, "ci95": list(rec_ci)},
        "f1": f1_val,
        "fpr": {"value": fpr_val, "ci95": list(fpr_ci)},
        "per_category": per_category,
        "per_tier": per_tier,
        "direct_vs_indirect": {
            "direct_recall": round(direct_stats["tp"] / direct_stats["total"], 4) if direct_stats["total"] > 0 else 0.0,
            "indirect_recall": round(indirect_stats["tp"] / indirect_stats["total"], 4) if indirect_stats["total"] > 0 else 0.0,
        },
        "sanitize_quality": {
            "cases": sanitize_cases,
            "preserved_pct": preserved_pct,
            "rescan_clean_pct": rescan_clean_pct,
        },
        "misses": misses,
        "false_positives": false_positives,
    }

    # Save run to benchmark_runs table
    conn = get_connection()
    conn.execute(
        """INSERT OR REPLACE INTO benchmark_runs (run_id, ts, split, policy_version, result_json)
           VALUES (?, ?, ?, ?, ?)""",
        (run_id, now_iso, split, policy_version, json.dumps(report)),
    )
    conn.commit()

    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run PromptShield benchmark")
    parser.add_argument("--split", default="test", choices=["dev", "test"], help="Dataset split to evaluate")
    parser.add_argument("--out", type=str, default=None, help="Output JSON path")
    args = parser.parse_args()

    bench_report = run_benchmark(split=args.split)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(bench_report, f, indent=2)
    print(f"Benchmark completed on split '{args.split}': n={bench_report['n']}, F1={bench_report['f1']}")
