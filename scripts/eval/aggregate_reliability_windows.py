"""Aggregate the three already-valid reliability windows.

This script is read-only with respect to the raw JSONL windows.  It computes
operational reliability metrics from the preserved window files and writes a
separate JSON artifact.  It never makes network calls and never changes
production scoring policy.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median, pstdev
from typing import Any, Dict, Iterable, List, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
WINDOW_DIR = REPO_ROOT / "evidence" / "reliability_sampling" / "windows"
DEFAULT_OUTPUT = (
    REPO_ROOT
    / "evidence"
    / "reliability_sampling"
    / "reliability_aggregation_2026-09-15.json"
)
DEFAULT_WINDOWS = (
    WINDOW_DIR / "window1_2026-09-15.jsonl",
    WINDOW_DIR / "window2_2026-09-15.jsonl",
    WINDOW_DIR / "window3_2026-09-15.jsonl",
)

# Talos was explicitly excluded from the historical three-window aggregate.
HISTORICAL_EXCLUSIONS = {
    "talos": "confirmed non-functional; service deprecated and excluded by commit 060e9a6"
}
# CIRCL remains visible in raw historical metrics, but current policy excludes
# it permanently from source selection and production evidence.
CURRENT_POLICY_EXCLUSIONS = {
    "circl": (
        "CIRCL Passive DNS requires partner authorization not available in this "
        "environment; excluded permanently, same status as GreyNoise/Pulsedive"
    )
}


def percentile(values: Sequence[float], fraction: float) -> float | None:
    """Return a linear-interpolated percentile without a NumPy dependency."""

    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def numeric_stats(values: Iterable[Any]) -> Dict[str, Any]:
    numbers = [float(value) for value in values if isinstance(value, (int, float))]
    if not numbers:
        return {
            "count": 0,
            "min_ms": None,
            "mean_ms": None,
            "median_ms": None,
            "p95_ms": None,
            "max_ms": None,
        }
    return {
        "count": len(numbers),
        "min_ms": min(numbers),
        "mean_ms": mean(numbers),
        "median_ms": median(numbers),
        "p95_ms": percentile(numbers, 0.95),
        "max_ms": max(numbers),
    }


def load_window(path: Path, window_id: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        required = {"source", "ioc_type", "timestamp", "not_applicable"}
        missing = required.difference(row)
        if missing:
            raise ValueError(f"{path}:{line_number} missing fields {sorted(missing)}")
        row = dict(row)
        row["window_id"] = window_id
        rows.append(row)
    if not rows:
        raise ValueError(f"Reliability window is empty: {path}")
    return rows


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def result_counts(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    executable = [row for row in rows if not row.get("not_applicable", False)]
    success = sum(row.get("success") is True for row in executable)
    failures = sum(row.get("fail") is True for row in executable)
    latency_values = [row.get("latency_ms") for row in executable]
    found = Counter(
        "true" if row.get("found") is True else "false" if row.get("found") is False else "unknown"
        for row in executable
    )
    labels = {}
    for label in sorted({str(row.get("expected_label", "unknown")) for row in executable}):
        label_rows = [row for row in executable if str(row.get("expected_label", "unknown")) == label]
        label_success = sum(row.get("success") is True for row in label_rows)
        labels[label] = {
            "executable_count": len(label_rows),
            "success_count": label_success,
            "fail_count": sum(row.get("fail") is True for row in label_rows),
            "success_rate": ratio(label_success, len(label_rows)),
        }

    latency_by_class: Dict[str, Dict[str, Any]] = {}
    for latency_class in sorted({str(row.get("latency_class")) for row in executable}):
        latency_by_class[latency_class] = numeric_stats(
            row.get("latency_ms")
            for row in executable
            if str(row.get("latency_class")) == latency_class
        )

    return {
        "total_rows": len(rows),
        "not_applicable_count": len(rows) - len(executable),
        "executable_count": len(executable),
        "success_count": success,
        "fail_count": failures,
        "success_rate": ratio(success, len(executable)),
        "failure_rate": ratio(failures, len(executable)),
        "error_type_counts": dict(sorted(Counter(
            str(row.get("error_type")) for row in executable if row.get("error_type")
        ).items())),
        "found_counts": dict(sorted(found.items())),
        "status_counts": dict(sorted(Counter(
            str(row.get("status")) for row in executable
        ).items())),
        "label_metrics": labels,
        "latency": numeric_stats(latency_values),
        "latency_by_class": latency_by_class,
    }


def source_metric(
    source: str, rows: Sequence[Mapping[str, Any]], window_ids: Sequence[str]
) -> Dict[str, Any]:
    per_window: Dict[str, Dict[str, Any]] = {}
    for window_id in window_ids:
        window_rows = [row for row in rows if row.get("window_id") == window_id]
        per_window[window_id] = result_counts(window_rows)

    window_rates = [
        data["success_rate"]
        for data in per_window.values()
        if data["executable_count"]
    ]
    executable_counts = [data["executable_count"] for data in per_window.values() if data["executable_count"]]
    coverage_consistency = (
        min(executable_counts) / max(executable_counts) * 100
        if executable_counts and max(executable_counts)
        else None
    )
    aggregate = result_counts(rows)
    aggregate["window_success_rate_mean"] = mean(window_rates) if window_rates else None
    aggregate["window_success_rate_std"] = pstdev(window_rates) if len(window_rates) > 1 else 0.0 if window_rates else None
    aggregate["window_success_rate_min"] = min(window_rates) if window_rates else None
    aggregate["window_success_rate_max"] = max(window_rates) if window_rates else None
    aggregate["windows_present"] = sum(bool(data["total_rows"]) for data in per_window.values())
    aggregate["windows_with_zero_failures"] = sum(data["fail_count"] == 0 for data in per_window.values() if data["executable_count"])
    aggregate["executable_count_by_window"] = {
        window_id: data["executable_count"] for window_id, data in per_window.items()
    }
    aggregate["coverage_consistency_pct_min_over_max"] = coverage_consistency
    aggregate["per_window"] = per_window
    aggregate["policy"] = {
        "historically_excluded": source in HISTORICAL_EXCLUSIONS,
        "current_policy_excluded": source in CURRENT_POLICY_EXCLUSIONS,
        "historical_exclusion_reason": HISTORICAL_EXCLUSIONS.get(source),
        "current_policy_exclusion_reason": CURRENT_POLICY_EXCLUSIONS.get(source),
    }
    return aggregate


def build_aggregation(window_paths: Sequence[Path]) -> Dict[str, Any]:
    window_ids = [path.stem.split("_")[0] for path in window_paths]
    windows = [load_window(path, window_id) for path, window_id in zip(window_paths, window_ids)]
    all_rows = [row for window in windows for row in window]
    all_sources = sorted({str(row["source"]) for row in all_rows})
    metrics = {
        source: source_metric(
            source,
            [row for row in all_rows if str(row["source"]) == source],
            window_ids,
        )
        for source in all_sources
    }
    historical_rows = [
        row for row in all_rows if str(row["source"]) not in HISTORICAL_EXCLUSIONS
    ]
    eligible_sources = [
        source
        for source in all_sources
        if source not in HISTORICAL_EXCLUSIONS and source not in CURRENT_POLICY_EXCLUSIONS
    ]
    historical_counts = result_counts(historical_rows)
    return {
        "artifact_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "historical_three_window_aggregation",
        "method": {
            "raw_windows_read_only": True,
            "network_calls": False,
            "window_count": len(window_paths),
            "window_paths": [str(path) for path in window_paths],
            "denominator": "not_applicable=false executable rows",
            "latency_comparison_rule": "latency statistics remain separated by latency_class; cached and uncached classes are not ranked directly",
        },
        "window_summary": {
            window_id: {
                "path": str(path),
                "raw_rows": len(window),
                "sources": sorted({str(row["source"]) for row in window}),
                "source_count": len({str(row["source"]) for row in window}),
                "executable_rows_before_historical_exclusions": sum(not row.get("not_applicable", False) for row in window),
                "talos_rows_total": sum(row.get("source") == "talos" for row in window),
                "talos_executable_rows_excluded": sum(
                    row.get("source") == "talos" and not row.get("not_applicable", False)
                    for row in window
                ),
                "executable_rows_after_talos_exclusion": sum(
                    not row.get("not_applicable", False) and row.get("source") not in HISTORICAL_EXCLUSIONS
                    for row in window
                ),
                "timestamp_min": min(row["timestamp"] for row in window),
                "timestamp_max": max(row["timestamp"] for row in window),
            }
            for path, window_id, window in zip(window_paths, window_ids, windows)
        },
        "source_policy": {
            "all_observed_sources": all_sources,
            "historical_aggregate_sources": [source for source in all_sources if source not in HISTORICAL_EXCLUSIONS],
            "eligible_current_source_set": eligible_sources,
            "historical_exclusions": HISTORICAL_EXCLUSIONS,
            "current_policy_exclusions": CURRENT_POLICY_EXCLUSIONS,
        },
        "historical_aggregate": historical_counts,
        "source_metrics": metrics,
        "limitations": [
            "This aggregates three windows from one day, not the locked 21-window seven-day protocol.",
            "Window1 Talos rows are preserved in raw files but excluded from the historical aggregate per commit 060e9a6.",
            "CIRCL historical rows are shown for audit only and are excluded from the current eligible source set because Passive DNS requires unavailable partner authorization.",
            "Operational success measures call completion, not detection correctness; found counts must not be interpreted as ground truth.",
            "Latency classes are not directly comparable across cached and uncached sources.",
        ],
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--window", type=Path, action="append", dest="windows")
    args = parser.parse_args(argv)
    window_paths = args.windows or list(DEFAULT_WINDOWS)
    if len(window_paths) != 3:
        raise ValueError("Exactly three valid reliability window files are required")
    artifact = build_aggregation(window_paths)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("=== RELIABILITY AGGREGATION RAW OUTPUT ===")
    print(f"windows={len(window_paths)}; network_calls=False; raw_windows_read_only=True")
    for window_id, summary in artifact["window_summary"].items():
        print(
            f"{window_id}: raw_rows={summary['raw_rows']}; "
            f"executable_after_talos_exclusion={summary['executable_rows_after_talos_exclusion']}; "
            f"sources={summary['source_count']}"
        )
    print(
        "historical_aggregate="
        + json.dumps(artifact["historical_aggregate"], ensure_ascii=True)
    )
    print("--- SOURCE SUMMARY ---")
    print("source | executable | success_rate | fail | window_rate_mean | window_rate_std | coverage_consistency | policy")
    for source, data in artifact["source_metrics"].items():
        print(
            f"{source} | {data['executable_count']} | {data['success_rate']} | "
            f"{data['fail_count']} | {data['window_success_rate_mean']} | "
            f"{data['window_success_rate_std']} | "
            f"{data['coverage_consistency_pct_min_over_max']} | {data['policy']}"
        )
    print(f"eligible_current_source_set={artifact['source_policy']['eligible_current_source_set']}")
    print(f"aggregation_artifact_path={args.output}")


if __name__ == "__main__":
    main()
