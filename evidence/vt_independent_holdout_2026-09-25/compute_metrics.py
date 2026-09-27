#!/usr/bin/env python3
"""Compute the Group A and VT-independent holdout evaluation summaries."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
GROUP_A_PATH = ROOT / "group_a_eval_results.jsonl"
VT_PATHS = (
    ROOT / "vt_holdout_eval_results_179.jsonl",
    ROOT / "vt_holdout_eval_results_batch3_21.jsonl",
)
POSITIVE_CLASS = "MALICIOUS"
LABEL_SOURCE_FIELD = "source"
EXCLUDED_LABEL_SOURCES = frozenset(
    {"circl_misp_feed_osint", "malwarebazaar_recent_detections"}
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"expected object at {path}:{line_number}")
        rows.append(value)
    return rows


def verdict(value: Any) -> str:
    return str(value or "UNKNOWN").upper()


def binary_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    true_positive = sum(
        verdict(row.get("expected_verdict")) == POSITIVE_CLASS
        and verdict(row.get("predicted_verdict")) == POSITIVE_CLASS
        for row in rows
    )
    true_negative = sum(
        verdict(row.get("expected_verdict")) != POSITIVE_CLASS
        and verdict(row.get("predicted_verdict")) != POSITIVE_CLASS
        for row in rows
    )
    false_positive = sum(
        verdict(row.get("expected_verdict")) != POSITIVE_CLASS
        and verdict(row.get("predicted_verdict")) == POSITIVE_CLASS
        for row in rows
    )
    false_negative = sum(
        verdict(row.get("expected_verdict")) == POSITIVE_CLASS
        and verdict(row.get("predicted_verdict")) != POSITIVE_CLASS
        for row in rows
    )

    total = len(rows)
    accuracy = (true_positive + true_negative) / total if total else 0.0
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "count": total,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": {
            "TN": true_negative,
            "FP": false_positive,
            "FN": false_negative,
            "TP": true_positive,
        },
    }


def distributions(rows: list[dict[str, Any]]) -> tuple[Counter[str], Counter[str]]:
    return (
        Counter(verdict(row.get("expected_verdict")) for row in rows),
        Counter(verdict(row.get("predicted_verdict")) for row in rows),
    )


def print_metrics(metrics: dict[str, Any]) -> None:
    print(
        f"n={metrics['count']} "
        f"accuracy={metrics['accuracy']:.6f} "
        f"precision={metrics['precision']:.6f} "
        f"recall={metrics['recall']:.6f} "
        f"F1={metrics['f1']:.6f}"
    )
    matrix = metrics["confusion_matrix"]
    print(
        f"TN={matrix['TN']} FP={matrix['FP']} "
        f"FN={matrix['FN']} TP={matrix['TP']}"
    )


def print_distribution(name: str, rows: list[dict[str, Any]]) -> None:
    expected, predicted = distributions(rows)
    print(f"{name}: n={len(rows)}")
    print(f"  expected_verdict={dict(sorted(expected.items()))}")
    print(f"  predicted_verdict={dict(sorted(predicted.items()))}")


def comparison_row(name: str, metrics: dict[str, Any]) -> str:
    return (
        f"{name},{metrics['count']},{metrics['accuracy']:.6f},"
        f"{metrics['precision']:.6f},{metrics['recall']:.6f},{metrics['f1']:.6f}"
    )


def main() -> None:
    group_a = load_jsonl(GROUP_A_PATH)
    vt_rows = [row for path in VT_PATHS for row in load_jsonl(path)]
    if len(vt_rows) != 200:
        raise RuntimeError(f"expected 200 concatenated VT rows, got {len(vt_rows)}")

    group_a_unfiltered_metrics = binary_metrics(group_a)
    group_a_filtered = [
        row
        for row in group_a
        if row.get(LABEL_SOURCE_FIELD) not in EXCLUDED_LABEL_SOURCES
    ]
    group_a_filtered_metrics = binary_metrics(group_a_filtered)
    vt_metrics = binary_metrics(vt_rows)

    print("=== INPUTS LOADED ===")
    print_distribution("Group A", group_a)
    print_distribution("VT-independent holdout", vt_rows)
    print()

    print("=== BINARIZATION ===")
    print("positive_class=MALICIOUS")
    print(
        "all verdicts other than MALICIOUS are counted as the negative class; "
        "Group A SUSPICIOUS predictions are therefore counted as negative, not excluded"
    )
    print()

    print("=== GROUP A / UNFILTERED (all label sources) ===")
    print_metrics(group_a_unfiltered_metrics)
    print()

    print(
        "=== GROUP A / FILTERED (excluding circl_misp_feed_osint & "
        "malwarebazaar_recent_detections label sources) ==="
    )
    print(f"filter_field={LABEL_SOURCE_FIELD}")
    print(f"excluded_label_sources={sorted(EXCLUDED_LABEL_SOURCES)}")
    print(f"filtered_rows={len(group_a_filtered)}")
    print_metrics(group_a_filtered_metrics)
    filtered_matrix = group_a_filtered_metrics["confusion_matrix"]
    filtered_correct = filtered_matrix["TP"] + filtered_matrix["TN"]
    expected_accuracy = 597 / 694
    actual_accuracy = group_a_filtered_metrics["accuracy"]
    if len(group_a_filtered) == 694 and filtered_correct == 597:
        print(
            f"headline_check=PASS ({filtered_correct}/{len(group_a_filtered)} = "
            f"{actual_accuracy * 100:.6f}%; expected 597/694 = "
            f"{expected_accuracy * 100:.6f}%)"
        )
    else:
        print(
            "HEADLINE DISCREPANCY: expected 597/694 = "
            f"{expected_accuracy * 100:.6f}%; observed "
            f"{filtered_correct}/{len(group_a_filtered)} = "
            f"{actual_accuracy * 100:.6f}%"
        )
    print()

    print("=== VT-INDEPENDENT HOLDOUT (label source: VirusTotal, no circularity) ===")
    print_metrics(vt_metrics)
    print("By expected IOC type:")
    by_type: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in vt_rows:
        by_type[str(row.get("expected_ioc_type") or "UNKNOWN")].append(row)
    print("type,n,accuracy,precision,recall,F1")
    for ioc_type in sorted(by_type):
        metrics = binary_metrics(by_type[ioc_type])
        print(
            f"{ioc_type},{metrics['count']},{metrics['accuracy']:.6f},"
            f"{metrics['precision']:.6f},{metrics['recall']:.6f},{metrics['f1']:.6f}"
        )
    print()

    print("=== FINAL THREE-WAY COMPARISON ===")
    print("dataset,n,accuracy,precision,recall,F1")
    print(comparison_row("GROUP_A_UNFILTERED_ALL_LABEL_SOURCES", group_a_unfiltered_metrics))
    print(comparison_row("GROUP_A_FILTERED_EXCLUDING_TWO_LABEL_SOURCES", group_a_filtered_metrics))
    print(comparison_row("VT_INDEPENDENT_HOLDOUT", vt_metrics))


if __name__ == "__main__":
    main()
