#!/usr/bin/env python3
"""Validate and summarize two IOC evaluation JSONL files.

The script refuses to write a summary when the combined input contains a
duplicate ``ioc`` value.  Metrics are binary with MALICIOUS as the positive
class; CLEAN, SUSPICIOUS, and UNKNOWN are treated as non-positive.
"""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = REPO_ROOT / "scripts" / "eval" / "eval_results_group_a_v3_rich_weightsum.jsonl"
DEFAULT_ADDITIONS = REPO_ROOT / "scripts" / "eval" / "output" / "eval_results_clean_additions_group_a_2026-09-22.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "scripts" / "eval" / "output" / "combined_group_a_metrics_v3_plus_clean_additions_2026-09-22.json"

VERDICT_LABELS = ("CLEAN", "MALICIOUS", "SUSPICIOUS", "UNKNOWN")
IOC_TYPE_ORDER = ("ip", "domain", "url", "hash")


def load_jsonl(path: Path):
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in {path} line {line_number}: {exc}") from exc
        if not isinstance(row, dict) or not row.get("ioc"):
            raise ValueError(f"missing ioc field in {path} line {line_number}")
        rows.append(row)
    return rows


def normalized_ioc_type(value):
    value = str(value or "").lower()
    if value in {"md5", "sha1", "sha256", "hash"}:
        return "hash"
    return value


def verdict_matrix(rows):
    matrix = {
        expected: {predicted: 0 for predicted in VERDICT_LABELS}
        for expected in VERDICT_LABELS
    }
    for row in rows:
        expected = str(row.get("expected_verdict") or "UNKNOWN").upper()
        predicted = str(row.get("predicted_verdict") or "UNKNOWN").upper()
        if expected not in matrix:
            matrix[expected] = {label: 0 for label in VERDICT_LABELS}
        if predicted not in VERDICT_LABELS:
            for values in matrix.values():
                values.setdefault(predicted, 0)
        matrix[expected][predicted] = matrix[expected].get(predicted, 0) + 1
    return matrix


def binary_metrics(rows):
    # Strict binary interpretation: only MALICIOUS is positive.
    tp = sum(
        row.get("expected_verdict") == "MALICIOUS"
        and row.get("predicted_verdict") == "MALICIOUS"
        for row in rows
    )
    tn = sum(
        row.get("expected_verdict") != "MALICIOUS"
        and row.get("predicted_verdict") != "MALICIOUS"
        for row in rows
    )
    fp = sum(
        row.get("expected_verdict") != "MALICIOUS"
        and row.get("predicted_verdict") == "MALICIOUS"
        for row in rows
    )
    fn = sum(
        row.get("expected_verdict") == "MALICIOUS"
        and row.get("predicted_verdict") != "MALICIOUS"
        for row in rows
    )
    total = len(rows)
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    # Macro-average over the CLEAN/non-positive and MALICIOUS/positive
    # classes, matching sklearn's average="macro", zero_division=0.
    clean_precision = tn / (tn + fn) if (tn + fn) else 0.0
    clean_recall = tn / (tn + fp) if (tn + fp) else 0.0
    clean_f1 = (
        2 * clean_precision * clean_recall / (clean_precision + clean_recall)
        if (clean_precision + clean_recall)
        else 0.0
    )
    return {
        "count": total,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "macro_average": {
            "precision": (clean_precision + precision) / 2,
            "recall": (clean_recall + recall) / 2,
            "f1": (clean_f1 + f1) / 2,
        },
        "confusion_matrix": {"TN": tn, "FP": fp, "FN": fn, "TP": tp},
        "verdict_confusion_matrix": verdict_matrix(rows),
    }


def main():
    parser = argparse.ArgumentParser(description="Summarize combined IOC evaluation metrics")
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--additions", type=Path, default=DEFAULT_ADDITIONS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    base = load_jsonl(args.base)
    additions = load_jsonl(args.additions)
    all_rows = base + additions

    counts = Counter(row["ioc"] for row in all_rows)
    duplicates = {ioc: count for ioc, count in counts.items() if count > 1}
    print(f"total={len(all_rows)} unique={len(counts)} duplicates={len(duplicates)}")
    for verdict, count in sorted(Counter(row.get("expected_verdict") for row in all_rows).items()):
        print(f"{verdict}={count}")
    if duplicates:
        sample = list(duplicates.items())[:10]
        raise SystemExit(f"duplicate ioc values found; refusing to summarize: {sample}")

    by_type = defaultdict(list)
    for row in all_rows:
        by_type[normalized_ioc_type(row.get("expected_ioc_type"))].append(row)

    summary = {
        "inputs": {
            "base": str(args.base),
            "additions": str(args.additions),
        },
        "deduplication": {
            "key": "ioc",
            "total_rows": len(all_rows),
            "unique_ioc": len(counts),
            "duplicate_ioc_count": 0,
            "duplicate_iocs": [],
        },
        "expected_verdict_counts": dict(sorted(Counter(row.get("expected_verdict") for row in all_rows).items())),
        "expected_ioc_type_counts": {
            ioc_type: len(by_type.get(ioc_type, []))
            for ioc_type in IOC_TYPE_ORDER
        },
        "metric_definition": {
            "positive_class": "MALICIOUS",
            "negative_class": "all verdicts other than MALICIOUS",
            "hash_group": ["md5", "sha1", "sha256", "hash"],
            "zero_division_metric_value": 0.0,
        },
        "overall": binary_metrics(all_rows),
        "by_expected_ioc_type": {
            ioc_type: binary_metrics(by_type[ioc_type])
            for ioc_type in IOC_TYPE_ORDER
            if ioc_type in by_type
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote={args.output}")


if __name__ == "__main__":
    main()
