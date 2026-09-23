#!/usr/bin/env python3
"""Recompute exported IOC verdicts from the stored production score.

This is an offline repair/export step.  It never calls an external API and
never modifies the input JSONL.  The verdict decision itself is delegated to
``src.utils.helpers.determine_verdict``; source coverage is reconstructed from
the stored ``sources`` object using the same production helper used by
``ioc_investigator.py``.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.scoring.intelligent_scoring import IntelligentScoring
from src.utils.helpers import determine_verdict


DEFAULT_INPUT = REPO_ROOT / "scripts" / "eval" / "eval_results_group_a_v3_rich_weightsum.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "scripts" / "eval" / "output" / "eval_results_group_a_v3_rich_weightsum_verdict_fixed.jsonl"


def load_rows(path: Path):
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


def recompute_row(row):
    if row.get("threat_score") is None:
        raise ValueError(f"missing threat_score for IOC {row['ioc']}")

    score = int(row["threat_score"])
    # This is the same coverage calculation used immediately before
    # determine_verdict() in src/tools/ioc_investigator.py.  The raw source
    # results are already present in the JSONL, so no network/API call occurs.
    coverage = IntelligentScoring.calculate_source_coverage(
        {"sources": row.get("sources", {})}
    )
    new_verdict = determine_verdict(score, coverage)

    updated = dict(row)
    updated["predicted_verdict"] = new_verdict
    return updated, coverage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    rows = load_rows(args.input)
    fixed_rows = []
    coverage_mismatches = []
    for row in rows:
        fixed, coverage = recompute_row(row)
        fixed_rows.append(fixed)
        # Keep this diagnostic visible because legacy aggregate fields can
        # differ from the production coverage derived from stored sources.
        if coverage["sources_flagged"] != (row.get("sources_flagged") or 0):
            coverage_mismatches.append(row["ioc"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in fixed_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    old_counts = Counter(str(row.get("predicted_verdict") or "UNKNOWN") for row in rows)
    new_counts = Counter(str(row.get("predicted_verdict") or "UNKNOWN") for row in fixed_rows)
    changed = sum(
        old.get("predicted_verdict") != new.get("predicted_verdict")
        for old, new in zip(rows, fixed_rows)
    )

    print(f"input={args.input}")
    print(f"output={args.output}")
    print(f"rows={len(rows)}")
    print(f"changed_predicted_verdict={changed}")
    print(f"coverage_sources_flagged_mismatches={len(coverage_mismatches)}")
    print("old_predicted_verdict=" + json.dumps(dict(sorted(old_counts.items())), ensure_ascii=False))
    print("new_predicted_verdict=" + json.dumps(dict(sorted(new_counts.items())), ensure_ascii=False))


if __name__ == "__main__":
    main()
