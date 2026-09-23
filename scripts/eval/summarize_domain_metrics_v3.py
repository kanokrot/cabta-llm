#!/usr/bin/env python3
"""Print binary metrics for domain rows in a verdict-fixed JSONL file."""

import argparse
import json
from collections import Counter
from pathlib import Path


DEFAULT_INPUT = Path(
    "scripts/eval/output/eval_results_v3_domain_independent_group_a_verdict_fixed.jsonl"
)


def load_rows(path: Path):
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON at line {line_number}: {exc}") from exc
        if row.get("expected_ioc_type") == "domain":
            rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    args = parser.parse_args()

    rows = load_rows(args.input)
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
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    result = {
        "input": str(args.input),
        "filter": {"expected_ioc_type": "domain"},
        "count": total,
        "expected_verdict": dict(sorted(Counter(row.get("expected_verdict") for row in rows).items())),
        "predicted_verdict": dict(sorted(Counter(row.get("predicted_verdict") for row in rows).items())),
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": {"TN": tn, "FP": fp, "FN": fn, "TP": tp},
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
