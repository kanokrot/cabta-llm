#!/usr/bin/env python3
"""Replay the stored 1,144-row IOC evaluation before/after error accounting.

Inputs are read-only. The only output is a JSON report in scripts/eval/output.
The baseline scorer is loaded from the pre-change repository revision so the
comparison remains reproducible after this script is committed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import types
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = REPO_ROOT / "scripts" / "eval" / "eval_results_group_a_v3_rich_weightsum.jsonl"
DEFAULT_ADDITIONS = (
    REPO_ROOT
    / "scripts"
    / "eval"
    / "output"
    / "eval_results_clean_additions_group_a_2026-09-22.jsonl"
)
DEFAULT_OUTPUT = (
    REPO_ROOT
    / "scripts"
    / "eval"
    / "output"
    / "source_error_handling_replay_1144.json"
)
BASELINE_REVISION = "db788897b535f313260a10d4bfd5a33de22155f7"
VERDICTS = ("MALICIOUS", "CLEAN", "UNKNOWN", "SUSPICIOUS")
SCORING_SOURCES = (
    "feodotracker",
    "c2_trackers",
    "spamhaus",
    "tor_exit_nodes",
    "sslblacklist",
    "threatfox",
)

# Mirrors the applicability declarations in ThreatIntelligence's source defaults
# and task construction. Used only to annotate the replay; scoring behavior below
# continues to use the stored source fields and production functions.
SUPPORTED_TYPES = {
    "feodotracker": {"ipv4"},
    "c2_trackers": {"ipv4", "domain", "url"},
    "spamhaus": {"ipv4"},
    "tor_exit_nodes": {"ipv4"},
    "sslblacklist": {"ipv4", "sha1"},
    "threatfox": {"ipv4", "domain", "url", "md5", "sha1", "sha256"},
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict) or not value.get("ioc"):
                raise ValueError(f"invalid IOC row in {path}:{line_number}")
            rows.append(value)
    return rows


def load_baseline_scorer(revision: str):
    """Load the exact pre-change scorer from Git without writing a temp file."""
    source = subprocess.run(
        ["git", "show", f"{revision}:src/scoring/intelligent_scoring.py"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout
    module = types.ModuleType("src.scoring._source_error_replay_baseline")
    module.__package__ = "src.scoring"
    exec(compile(source, f"{revision}:src/scoring/intelligent_scoring.py", "exec"), module.__dict__)
    return module.IntelligentScoring


def coverage_ratio(coverage: dict[str, Any]) -> float:
    attempted = coverage.get("total_sources_attempted", 0)
    if not attempted:
        return 0.0
    return (coverage.get("sources_flagged", 0) + coverage.get("sources_clean", 0)) / attempted


def binary_metrics(rows: list[dict[str, Any]], exclude_unknown: bool) -> dict[str, Any]:
    evaluated = [
        row for row in rows
        if not (exclude_unknown and row["predicted_verdict"] == "UNKNOWN")
    ]
    tp = sum(
        row["expected_verdict"] == "MALICIOUS"
        and row["predicted_verdict"] == "MALICIOUS"
        for row in evaluated
    )
    fp = sum(
        row["expected_verdict"] != "MALICIOUS"
        and row["predicted_verdict"] == "MALICIOUS"
        for row in evaluated
    )
    fn = sum(
        row["expected_verdict"] == "MALICIOUS"
        and row["predicted_verdict"] != "MALICIOUS"
        for row in evaluated
    )
    tn = sum(
        row["expected_verdict"] != "MALICIOUS"
        and row["predicted_verdict"] != "MALICIOUS"
        for row in evaluated
    )
    count = len(evaluated)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    unknown_count = sum(row["predicted_verdict"] == "UNKNOWN" for row in rows)
    return {
        "count_evaluated": count,
        "abstain_count": unknown_count,
        "abstain_rate": unknown_count / len(rows) if rows else 0.0,
        "accuracy": (tp + tn) / count if count else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
    }


def classify_scoring_sources(row: dict[str, Any], scorer) -> dict[str, list[str]]:
    sources = row.get("sources")
    if not isinstance(sources, dict):
        sources = {}
    ioc_type = str(row.get("expected_ioc_type") or "").lower()
    if ioc_type == "ip":
        ioc_type = "ipv4"
    elif ioc_type == "hash":
        ioc_type = "sha256"

    not_applicable = []
    errors = []
    ok = []
    unavailable_markers = []
    for name in SCORING_SOURCES:
        item = sources.get(name)
        if not isinstance(item, dict):
            errors.append(name)
            continue
        if item.get("unavailable") is True:
            unavailable_markers.append(name)
        if ioc_type not in SUPPORTED_TYPES[name]:
            not_applicable.append(name)
        elif scorer._is_source_error(item):
            errors.append(name)
        else:
            ok.append(name)
    return {
        "error_or_missing_result": errors,
        "not_applicable_by_ioc_type": not_applicable,
        "ok": ok,
        "raw_unavailable_markers": unavailable_markers,
    }


def is_trusted_shortcut_row(row: dict[str, Any]) -> bool:
    """Recognize production's early-return trusted infrastructure results."""
    return row.get("trusted_shortcut") is True and row.get("sources_checked") == 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--additions", type=Path, default=DEFAULT_ADDITIONS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--baseline-revision", default=BASELINE_REVISION)
    args = parser.parse_args()

    sys.path.insert(0, str(REPO_ROOT))
    from src.scoring.intelligent_scoring import IntelligentScoring as NewScorer
    from src.utils.helpers import determine_verdict

    OldScorer = load_baseline_scorer(args.baseline_revision)
    rows = load_jsonl(args.base) + load_jsonl(args.additions)
    replayed: dict[str, list[dict[str, Any]]] = {"old": [], "new": []}
    scored_replayed: dict[str, list[dict[str, Any]]] = {"old": [], "new": []}
    changed_rows = []
    label_splits: dict[str, dict[str, Any]] = {}

    for expected in ("CLEAN", "MALICIOUS", "SUSPICIOUS", "UNKNOWN"):
        labeled_rows = [
            row for row in rows
            if str(row.get("expected_verdict") or "UNKNOWN").upper() == expected
        ]
        trusted_rows = [row for row in labeled_rows if is_trusted_shortcut_row(row)]
        label_splits[expected] = {
            "total": len(labeled_rows),
            "scored_by_sources": len(labeled_rows) - len(trusted_rows),
            "trusted_shortcut": len(trusted_rows),
            "trusted_shortcut_iocs": [row["ioc"] for row in trusted_rows],
        }

    for input_row in rows:
        sources = input_row.get("sources")
        if not isinstance(sources, dict):
            sources = {}
        intel = {"sources": sources}
        expected = str(input_row.get("expected_verdict") or "UNKNOWN").upper()
        trusted_shortcut = is_trusted_shortcut_row(input_row)

        if trusted_shortcut:
            # Production returns directly from the trusted-infrastructure path;
            # the eval export's unavailable placeholders were never scored.
            recorded_verdict = str(input_row.get("predicted_verdict") or "CLEAN").upper()
            if recorded_verdict not in VERDICTS:
                raise ValueError(
                    f"invalid recorded trusted-shortcut verdict for {input_row['ioc']}: "
                    f"{recorded_verdict}"
                )
            old_score = new_score = input_row.get("threat_score", 0) or 0
            old_coverage = new_coverage = NewScorer.calculate_source_coverage({"sources": {}})
            old_verdict = new_verdict = recorded_verdict
        else:
            old_score = OldScorer.calculate_ioc_score(intel)
            old_coverage = OldScorer.calculate_source_coverage(intel)
            old_verdict = determine_verdict(old_score, old_coverage)

            new_score = NewScorer.calculate_ioc_score(intel)
            new_coverage = NewScorer.calculate_source_coverage(intel)
            new_verdict = determine_verdict(new_score, new_coverage)

        old_row = {
            "ioc": input_row["ioc"],
            "expected_verdict": expected,
            "predicted_verdict": old_verdict,
        }
        new_row = {
            "ioc": input_row["ioc"],
            "expected_verdict": expected,
            "predicted_verdict": new_verdict,
        }
        replayed["old"].append(old_row)
        replayed["new"].append(new_row)
        if not trusted_shortcut:
            scored_replayed["old"].append(old_row)
            scored_replayed["new"].append(new_row)

        if old_verdict != new_verdict or old_score != new_score:
            changed_rows.append({
                "ioc": input_row["ioc"],
                "expected_verdict": expected,
                "old_score": old_score,
                "new_score": new_score,
                "old_verdict": old_verdict,
                "new_verdict": new_verdict,
                "coverage_before": {
                    "ok": old_coverage["sources_flagged"] + old_coverage["sources_clean"],
                    "applicable": old_coverage["total_sources_attempted"],
                    "ratio": coverage_ratio(old_coverage),
                },
                "coverage_after": {
                    "ok": new_coverage["sources_ok"],
                    "applicable": new_coverage["sources_applicable"],
                    "ratio": coverage_ratio(new_coverage),
                },
                "scoring_source_accounting": classify_scoring_sources(input_row, NewScorer),
                "trusted_shortcut": trusted_shortcut,
                "sources_checked": input_row.get("sources_checked"),
                "label_source": input_row.get("source"),
            })

    report = {
        "inputs": {
            "base": str(args.base),
            "additions": str(args.additions),
            "baseline_revision": args.baseline_revision,
            "rows": len(rows),
        },
        "definitions": {
            "positive_class": "MALICIOUS",
            "unknown_as_negative": "UNKNOWN is included as a negative prediction",
            "unknown_as_abstain": "UNKNOWN rows are removed from metric denominators",
            "trusted_shortcut": (
                "Rows with trusted_shortcut=true and sources_checked=0 use their "
                "recorded production verdict and are excluded from scored-only metrics"
            ),
            "source_accounting_note": (
                "not_applicable_by_ioc_type is annotated for review; source error "
                "accounting applies only to rows actually scored"
            ),
        },
        "logic": {},
        "expected_label_split": label_splits,
        "changed_rows": changed_rows,
    }

    for label, result_rows in replayed.items():
        verdict_counts = Counter(row["predicted_verdict"] for row in result_rows)
        report["logic"][label] = {
            "verdict_counts": {verdict: verdict_counts.get(verdict, 0) for verdict in VERDICTS},
            "metrics_unknown_as_negative": binary_metrics(result_rows, exclude_unknown=False),
            "metrics_unknown_as_abstain": binary_metrics(result_rows, exclude_unknown=True),
        }
        scored_rows = scored_replayed[label]
        scored_counts = Counter(row["predicted_verdict"] for row in scored_rows)
        report["logic"][label]["scored_only"] = {
            "verdict_counts": {
                verdict: scored_counts.get(verdict, 0) for verdict in VERDICTS
            },
            "metrics_unknown_as_negative": binary_metrics(scored_rows, exclude_unknown=False),
            "metrics_unknown_as_abstain": binary_metrics(scored_rows, exclude_unknown=True),
        }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"rows={len(rows)} changed_rows={len(changed_rows)}")
    for label in ("old", "new"):
        logic = report["logic"][label]
        counts = logic["verdict_counts"]
        print(f"{label} verdict_counts=" + json.dumps(counts, ensure_ascii=False))
        for treatment in ("metrics_unknown_as_negative", "metrics_unknown_as_abstain"):
            metrics = logic[treatment]
            print(
                f"{label} {treatment}: "
                f"accuracy={metrics['accuracy'] * 100:.1f}% "
                f"precision={metrics['precision'] * 100:.1f}% "
                f"recall={metrics['recall'] * 100:.1f}% "
                f"f1={metrics['f1'] * 100:.1f}% "
                f"abstain_rate={metrics['abstain_rate'] * 100:.1f}% "
                f"evaluated={metrics['count_evaluated']}"
            )
        scored_metrics = logic["scored_only"]["metrics_unknown_as_negative"]
        print(
            f"{label} scored_only: "
            f"verdict_counts={json.dumps(logic['scored_only']['verdict_counts'], ensure_ascii=False)} "
            f"accuracy={scored_metrics['accuracy'] * 100:.1f}% "
            f"precision={scored_metrics['precision'] * 100:.1f}% "
            f"recall={scored_metrics['recall'] * 100:.1f}% "
            f"f1={scored_metrics['f1'] * 100:.1f}% "
            f"evaluated={scored_metrics['count_evaluated']}"
        )
    print("expected_label_split=" + json.dumps(label_splits, ensure_ascii=False))
    print("changed_rows_detail=" + json.dumps(changed_rows, ensure_ascii=False))
    print(f"wrote={args.output}")


if __name__ == "__main__":
    main()
