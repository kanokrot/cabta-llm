#!/usr/bin/env python3
"""Extract the current domain false-negative error set for offline review."""

import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULTS = REPO_ROOT / "scripts" / "eval" / "output" / "eval_results_group_a_v3_rich_weightsum_verdict_fixed.jsonl"
DEFAULT_BENCHMARK = REPO_ROOT / "data" / "benchmark" / "benchmark_iocs_v2_backup.json"
DEFAULT_OUTPUT = REPO_ROOT / "scripts" / "eval" / "output" / "domain_false_negatives_weightsum_2026-09-22.jsonl"


def load_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    benchmark = {
        row["ioc"]: row
        for row in json.loads(args.benchmark.read_text(encoding="utf-8"))
    }
    rows = load_jsonl(args.results)
    errors = []
    for row in rows:
        if not (
            row.get("expected_ioc_type") == "domain"
            and row.get("expected_verdict") == "MALICIOUS"
            and row.get("predicted_verdict") != "MALICIOUS"
        ):
            continue
        source_row = benchmark.get(row["ioc"], {})
        errors.append({
            "ioc": row["ioc"],
            "expected_verdict": row.get("expected_verdict"),
            "expected_ioc_type": row.get("expected_ioc_type"),
            "predicted_verdict": row.get("predicted_verdict"),
            "threat_score": row.get("threat_score"),
            "threat_score_original": row.get("threat_score_original"),
            "sources_flagged": row.get("sources_flagged"),
            "sources_count_recomputed": row.get("sources_count_recomputed"),
            "runtime_source": row.get("source"),
            "benchmark_tags": source_row.get("tags", []),
            "sources": row.get("sources", {}),
        })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in errors:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"rows={len(errors)}")
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
