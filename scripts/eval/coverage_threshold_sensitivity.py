#!/usr/bin/env python3
"""Offline sensitivity analysis for the IOC coverage verdict threshold.

Reads the stored Group A eval rows through replay_source_error_handling's
loader, excludes trusted-shortcut rows, and writes a JSON report only beneath
scripts/eval/output. No threat-intelligence providers are called.
"""

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
THRESHOLDS = (0.2, 0.3, 0.4, 0.5)
UNAVAILABLE_COUNTS = (0, 1, 2, 3, 4, 5)
REPETITIONS = 200
RANDOM_SEED = 20261009
VERDICTS = ("MALICIOUS", "CLEAN", "UNKNOWN", "SUSPICIOUS")


def normalized_ioc_type(value: Any) -> str:
    ioc_type = str(value or "").strip().lower()
    if ioc_type == "ip":
        return "ipv4"
    if ioc_type == "hash":
        return "sha256"
    return ioc_type


def source_is_explicitly_not_applicable(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    status = str(item.get("status", "")).strip()
    reason = str(item.get("error") or item.get("message") or "").strip().lower()
    return (
        item.get("not_applicable") is True
        or status == "➖"
        or reason == "not applicable"
    )


def applicable_scoring_sources(row: dict[str, Any], sources: dict[str, Any], supported_types: dict[str, set[str]]) -> list[str]:
    ioc_type = normalized_ioc_type(row.get("expected_ioc_type"))
    return [
        name
        for name in supported_types
        if ioc_type in supported_types[name]
        and not source_is_explicitly_not_applicable(sources.get(name))
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path)
    parser.add_argument("--additions", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--repetitions", type=int, default=REPETITIONS)
    args = parser.parse_args()

    sys.path.insert(0, str(REPO_ROOT))
    from scripts.eval.replay_source_error_handling import (
        DEFAULT_ADDITIONS,
        DEFAULT_BASE,
        SCORING_SOURCES,
        SUPPORTED_TYPES,
        is_trusted_shortcut_row,
        load_jsonl,
    )
    from src.scoring.intelligent_scoring import IntelligentScoring
    import src.utils.helpers as helpers

    base_path = args.base or DEFAULT_BASE
    additions_path = args.additions or DEFAULT_ADDITIONS
    rows = load_jsonl(base_path) + load_jsonl(additions_path)
    scored_rows = [row for row in rows if not is_trusted_shortcut_row(row)]
    rng = random.Random(args.seed)

    # Count rows whose current MALICIOUS result is protected by the early
    # score>=70 + at-least-one-flagged branch from the coverage downgrade.
    override_counts = Counter()
    override_examples = []
    baseline_threshold = helpers.INCONCLUSIVE_COVERAGE_THRESHOLD
    try:
        helpers.INCONCLUSIVE_COVERAGE_THRESHOLD = 0.3
        for row in scored_rows:
            sources = row.get("sources") if isinstance(row.get("sources"), dict) else {}
            intel = {"sources": sources}
            score = IntelligentScoring.calculate_ioc_score(intel)
            coverage = IntelligentScoring.calculate_source_coverage(intel)
            flagged = coverage.get("sources_flagged", 0)
            if score >= 70 and flagged > 0:
                override_counts["triggered"] += 1
                ratio = (
                    coverage.get("sources_ok", 0) / coverage.get("sources_applicable", 1)
                    if coverage.get("sources_applicable", 0)
                    else 0.0
                )
                if ratio < 0.3:
                    override_counts["needed_to_avoid_unknown"] += 1
                    override_examples.append({
                        "ioc": row.get("ioc"),
                        "score": score,
                        "sources_flagged": flagged,
                        "coverage_ratio": ratio,
                        "expected_verdict": row.get("expected_verdict"),
                    })
    finally:
        helpers.INCONCLUSIVE_COVERAGE_THRESHOLD = baseline_threshold

    # Results are accumulated as equal-weight row/repetition observations.
    results: dict[str, dict[str, Any]] = {
        str(threshold): {
            str(k): {
                "verdict_counts": Counter(),
                "malicious_clean": 0,
                "malicious_unknown": 0,
                "clean_non_clean": 0,
            }
            for k in UNAVAILABLE_COUNTS
        }
        for threshold in THRESHOLDS
    }
    unavailable_cap_counts = Counter()

    for k in UNAVAILABLE_COUNTS:
        for _ in range(args.repetitions):
            for row in scored_rows:
                row_sources = row.get("sources")
                original_sources = row_sources if isinstance(row_sources, dict) else {}
                applicable = applicable_scoring_sources(row, original_sources, SUPPORTED_TYPES)
                available = [
                    name for name in applicable
                    if not IntelligentScoring._is_source_error(original_sources.get(name))
                ]
                remove_count = min(k, len(available))
                if remove_count < k:
                    unavailable_cap_counts[str(k)] += 1
                selected = set(rng.sample(available, remove_count)) if remove_count else set()
                simulated_sources = copy.deepcopy(original_sources)
                for name in selected:
                    item = simulated_sources.get(name)
                    if not isinstance(item, dict):
                        item = {}
                        simulated_sources[name] = item
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
                    bucket = results[str(threshold)][str(k)]
                    bucket["verdict_counts"][verdict] += 1
                    if label == "MALICIOUS":
                        bucket["malicious_clean"] += verdict == "CLEAN"
                        bucket["malicious_unknown"] += verdict == "UNKNOWN"
                    elif label == "CLEAN":
                        bucket["clean_non_clean"] += verdict != "CLEAN"

    helpers.INCONCLUSIVE_COVERAGE_THRESHOLD = baseline_threshold
    malicious_denominator = sum(
        str(row.get("expected_verdict") or "UNKNOWN").upper() == "MALICIOUS"
        for row in scored_rows
    ) * args.repetitions
    clean_denominator = sum(
        str(row.get("expected_verdict") or "UNKNOWN").upper() == "CLEAN"
        for row in scored_rows
    ) * args.repetitions

    finalized: dict[str, dict[str, Any]] = {}
    for threshold, by_k in results.items():
        finalized[threshold] = {}
        for k, bucket in by_k.items():
            total = len(scored_rows) * args.repetitions
            counts = {verdict: bucket["verdict_counts"].get(verdict, 0) for verdict in VERDICTS}
            finalized[threshold][k] = {
                "verdict_counts": counts,
                "verdict_rates": {verdict: counts[verdict] / total if total else 0.0 for verdict in VERDICTS},
                "malicious_silent_miss_rate": bucket["malicious_clean"] / malicious_denominator if malicious_denominator else 0.0,
                "malicious_abstain_rate": bucket["malicious_unknown"] / malicious_denominator if malicious_denominator else 0.0,
                "clean_non_clean_rate": bucket["clean_non_clean"] / clean_denominator if clean_denominator else 0.0,
            }

    summary_k3_k4 = {
        str(threshold): {
            str(k): {
                "malicious_silent_miss_rate": finalized[str(threshold)][str(k)]["malicious_silent_miss_rate"],
                "malicious_abstain_rate": finalized[str(threshold)][str(k)]["malicious_abstain_rate"],
            }
            for k in (3, 4)
        }
        for threshold in THRESHOLDS
    }
    report = {
        "inputs": {
            "base": str(base_path),
            "additions": str(additions_path),
            "rows_total": len(rows),
            "rows_scored": len(scored_rows),
            "trusted_shortcut_rows_excluded": len(rows) - len(scored_rows),
            "repetitions_per_k": args.repetitions,
            "seed": args.seed,
        },
        "simulation": {
            "thresholds": list(THRESHOLDS),
            "unavailable_counts_requested": list(UNAVAILABLE_COUNTS),
            "selection": (
                "For each row and repetition, sample k currently non-error, applicable scoring sources; "
                "mark them unavailable. Existing errors remain unavailable. If fewer than k currently "
                "available sources exist, remove all available sources for that row."
            ),
            "coverage_and_verdict": "Recomputed with production IntelligentScoring and determine_verdict.",
            "label_denominators": {
                "malicious_row_repetitions": malicious_denominator,
                "clean_row_repetitions": clean_denominator,
            },
            "rows_with_fewer_than_k_available_sources": dict(unavailable_cap_counts),
        },
        "current_override": {
            "threshold": 0.3,
            "score_ge_70_and_flagged_gt_0_rows": override_counts["triggered"],
            "coverage_below_current_threshold_needing_early_override": override_counts["needed_to_avoid_unknown"],
            "rows": override_examples,
        },
        "results": finalized,
        "k3_k4_summary": summary_k3_k4,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"rows_total={len(rows)} rows_scored={len(scored_rows)} trusted_shortcuts_excluded={len(rows) - len(scored_rows)}")
    print(f"current_override={json.dumps(report['current_override'], ensure_ascii=False)}")
    for threshold in THRESHOLDS:
        print(f"threshold={threshold:.1f}")
        for k in UNAVAILABLE_COUNTS:
            result = finalized[str(threshold)][str(k)]
            print(
                f"  k={k} verdicts={json.dumps(result['verdict_counts'])} "
                f"malicious_clean={result['malicious_silent_miss_rate']:.4%} "
                f"malicious_unknown={result['malicious_abstain_rate']:.4%} "
                f"clean_non_clean={result['clean_non_clean_rate']:.4%}"
            )
    print("k3_k4_summary=" + json.dumps(summary_k3_k4, ensure_ascii=False))
    print(f"wrote={args.output}")


if __name__ == "__main__":
    main()
