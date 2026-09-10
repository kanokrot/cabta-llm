import json
from pathlib import Path

from scripts.tools.rag_coverage_matrix import build_coverage_matrix


BASELINE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "tools"
    / "rag_coverage_baseline.json"
)


def test_rag_coverage_does_not_regress_from_baseline():
    # After intentionally adding RAG coverage, regenerate the snapshot with:
    # python scripts/tools/rag_coverage_matrix.py --update-baseline
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    current = build_coverage_matrix()

    for coverage_name in ("verdict_coverage", "ioc_type_coverage"):
        for value, baseline_count in baseline[coverage_name].items():
            current_count = current[coverage_name].get(value, {}).get("count", 0)
            assert current_count >= baseline_count, (
                f"{coverage_name} regressed for {value}: "
                f"{baseline_count} -> {current_count}"
            )

    baseline_unreachable = set(baseline["unreachable_category"])
    current_unreachable = set(
        current["category_query_reachability"]["unreachable_category"]
    )
    unexpected = current_unreachable - baseline_unreachable
    assert current_unreachable <= baseline_unreachable, (
        "New unreachable_category values: " + ", ".join(sorted(unexpected))
    )

