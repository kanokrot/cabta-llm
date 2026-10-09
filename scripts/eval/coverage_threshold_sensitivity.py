#!/usr/bin/env python3
"""Offline coverage-threshold sensitivity simulation for stored Group A rows."""

from __future__ import annotations

import argparse
import copy
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = REPO_ROOT / "scripts" / "eval" / "output" / "coverage_threshold_sensitivity.json"
THRESHOLDS = (0.1, 0.3, 0.5)
UNAVAILABLE_COUNTS = (0, 1, 2, 3, 4, 5)
REPETITIONS = 200
RANDOM_SEED = 20261009
VERDICTS = ("MALICIOUS", "CLEAN", "UNKNOWN")
LABELS = ("MALICIOUS", "CLEAN")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path)
    parser.add_argument("--additions", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    sys.path.insert(0, str(REPO_ROOT))
    from scripts.eval.replay_source_error_handling import (
        DEFAULT_ADDITIONS,
        DEFAULT_BASE,
        SCORING_SOURCES,
        is_trusted_shortcut_row,
        load_jsonl,
    )
    from src.scoring.intelligent_scoring import IntelligentScoring
    import src.utils.helpers as helpers

    if len(SCORING_SOURCES) != 6:
        raise RuntimeError(f"expected six scoring sources, got {len(SCORING_SOURCES)}")

    base_path = args.base or DEFAULT_BASE
    additions_path = args.additions or DEFAULT_ADDITIONS
    rows = load_jsonl(base_path) + load_jsonl(additions_path)
    scored_rows = [row for row in rows if not is_trusted_shortcut_row(row)]
    rng = random.Random(RANDOM_SEED)

    # This is the current early branch in determine_verdict(): each matching
    # row returns MALICIOUS before the coverage threshold is evaluated.
    baseline_override_rows = []
    for row in scored_rows:
        sources = row.get("sources") if isinstance(row.get("sources"), dict) else {}
        score = IntelligentScoring.calculate_ioc_score({"sources": sources})
        coverage = IntelligentScoring.calculate_source_coverage({"sources": sources})
        if score >= 70 and coverage.get("sources_flagged", 0) > 0:
            baseline_override_rows.append(row.get("ioc"))

    # Each entry stores predicted verdict counts conditioned on the true label,
    # plus predictions for all simulations in which no flagged source remains.
    raw: dict[str, dict[str, Any]] = {
        str(threshold): {
            str(k): {
                "by_true_label": {label: Counter() for label in LABELS},
                "no_flag": Counter(),
                "no_flag_total": 0,
            }
            for k in UNAVAILABLE_COUNTS
        }
        for threshold in THRESHOLDS
    }
    baseline_threshold = helpers.INCONCLUSIVE_COVERAGE_THRESHOLD
    try:
        for k in UNAVAILABLE_COUNTS:
            for _ in range(REPETITIONS):
                for row in scored_rows:
                    original = row.get("sources")
                    original_sources = original if isinstance(original, dict) else {}
                    selected = set(rng.sample(SCORING_SOURCES, k)) if k else set()
                    simulated_sources = copy.deepcopy(original_sources)
                    for source_name in selected:
                        item = simulated_sources.get(source_name)
                        if not isinstance(item, dict):
                            item = {}
                            simulated_sources[source_name] = item
                        item["unavailable"] = True
                        item["status"] = "Error"
                        item["error"] = item.get("error") or "simulated unavailable source"

                    intel = {"sources": simulated_sources}
                    score = IntelligentScoring.calculate_ioc_score(intel)
                    coverage = IntelligentScoring.calculate_source_coverage(intel)
                    label = str(row.get("expected_verdict") or "UNKNOWN").upper()
                    for threshold in THRESHOLDS:
                        helpers.INCONCLUSIVE_COVERAGE_THRESHOLD = threshold
                        verdict = helpers.determine_verdict(score, coverage)
                        bucket = raw[str(threshold)][str(k)]
                        if label in LABELS:
                            bucket["by_true_label"][label][verdict] += 1
                        if coverage.get("sources_flagged", 0) == 0:
                            bucket["no_flag_total"] += 1
                            bucket["no_flag"][verdict] += 1
    finally:
        helpers.INCONCLUSIVE_COVERAGE_THRESHOLD = baseline_threshold

    label_denominators = {
        label: sum(
            str(row.get("expected_verdict") or "UNKNOWN").upper() == label
            for row in scored_rows
        ) * REPETITIONS
        for label in LABELS
    }

    def rates(counter: Counter, denominator: int) -> dict[str, float]:
        return {
            verdict: counter.get(verdict, 0) / denominator if denominator else 0.0
            for verdict in VERDICTS
        }

    finalized: dict[str, dict[str, Any]] = {}
    for threshold, by_k in raw.items():
        finalized[threshold] = {}
        for k, bucket in by_k.items():
            finalized[threshold][k] = {
                "by_true_label": {
                    label: {
                        "counts": {v: bucket["by_true_label"][label].get(v, 0) for v in VERDICTS},
                        "rates": rates(bucket["by_true_label"][label], label_denominators[label]),
                    }
                    for label in LABELS
                },
                "no_flag_remaining": {
                    "count": bucket["no_flag_total"],
                    "counts": {v: bucket["no_flag"].get(v, 0) for v in VERDICTS},
                    "rates": rates(bucket["no_flag"], bucket["no_flag_total"]),
                },
            }

    report = {
        "inputs": {
            "base": str(base_path),
            "additions": str(additions_path),
            "rows_total": len(rows),
            "rows_scored": len(scored_rows),
            "trusted_shortcut_rows_excluded": len(rows) - len(scored_rows),
            "label_denominators": label_denominators,
        },
        "simulation": {
            "scoring_sources": list(SCORING_SOURCES),
            "thresholds": list(THRESHOLDS),
            "unavailable_counts": list(UNAVAILABLE_COUNTS),
            "repetitions_per_k": REPETITIONS,
            "seed": RANDOM_SEED,
            "sampling": "For each row and repetition, sample exactly k of the six scoring sources and mark them unavailable; pre-existing source errors remain errors.",
            "score_coverage_verdict": "Recomputed with production IntelligentScoring and determine_verdict.",
            "no_flag_denominator": "Simulations with coverage.sources_flagged == 0, aggregated across all true labels.",
        },
        "current_override": {
            "condition": "score >= 70 and sources_flagged > 0",
            "rows_malicious_regardless_of_threshold": len(baseline_override_rows),
            "iocs": baseline_override_rows,
        },
        "results": finalized,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"rows={len(rows)} scored={len(scored_rows)} trusted_shortcuts_excluded={len(rows) - len(scored_rows)}")
    print(f"override_malicious_regardless_of_threshold={len(baseline_override_rows)}")
    print("threshold k | MAL true: M/C/U % | CLEAN true: M/C/U % | no flagged: M/C/U %")
    for threshold in THRESHOLDS:
        for k in UNAVAILABLE_COUNTS:
            result = finalized[str(threshold)][str(k)]
            mal = result["by_true_label"]["MALICIOUS"]["rates"]
            clean = result["by_true_label"]["CLEAN"]["rates"]
            no_flag = result["no_flag_remaining"]["rates"]
            fmt = lambda values: "/".join(f"{values[v] * 100:.1f}" for v in VERDICTS)
            print(f"{threshold:.1f} {k} | {fmt(mal)} | {fmt(clean)} | {fmt(no_flag)}")
    print(f"wrote={args.output}")


if __name__ == "__main__":
    main()
