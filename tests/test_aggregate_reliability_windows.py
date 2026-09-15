import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "eval" / "aggregate_reliability_windows.py"
SPEC = importlib.util.spec_from_file_location("aggregate_reliability_windows", SCRIPT_PATH)
assert SPEC and SPEC.loader
aggregate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(aggregate)


def test_result_counts_excludes_not_applicable_from_denominator():
    rows = [
        {"not_applicable": True, "success": None, "fail": None},
        {
            "not_applicable": False,
            "success": True,
            "fail": False,
            "found": False,
            "latency_ms": 10.0,
            "latency_class": "api_request",
            "expected_label": "clean",
            "source": "test",
            "status": "ok",
        },
        {
            "not_applicable": False,
            "success": False,
            "fail": True,
            "found": False,
            "latency_ms": 20.0,
            "latency_class": "api_request",
            "expected_label": "malicious",
            "error_type": "5xx",
            "source": "test",
            "status": "error",
        },
    ]

    result = aggregate.result_counts(rows)

    assert result["total_rows"] == 3
    assert result["not_applicable_count"] == 1
    assert result["executable_count"] == 2
    assert result["success_count"] == 1
    assert result["fail_count"] == 1
    assert result["success_rate"] == 0.5
    assert result["error_type_counts"] == {"5xx": 1}
    assert result["latency_by_class"]["api_request"]["count"] == 2


def test_source_metric_reports_cross_window_consistency_and_policy():
    rows = [
        {"window_id": "window1", "not_applicable": False, "success": True, "fail": False, "latency_ms": 10, "latency_class": "api_request"},
        {"window_id": "window2", "not_applicable": False, "success": True, "fail": False, "latency_ms": 20, "latency_class": "api_request"},
        {"window_id": "window3", "not_applicable": False, "success": False, "fail": True, "latency_ms": 30, "latency_class": "api_request", "error_type": "timeout"},
    ]

    result = aggregate.source_metric("circl", rows, ["window1", "window2", "window3"])

    assert result["executable_count"] == 3
    assert result["success_rate"] == 2 / 3
    assert result["windows_present"] == 3
    assert result["windows_with_zero_failures"] == 2
    assert result["coverage_consistency_pct_min_over_max"] == 100.0
    assert result["policy"]["current_policy_excluded"] is True
    assert result["policy"]["historically_excluded"] is False


def test_current_three_window_files_aggregate_without_talos():
    artifact = aggregate.build_aggregation(list(aggregate.DEFAULT_WINDOWS))

    assert artifact["method"]["network_calls"] is False
    assert artifact["window_summary"]["window1"]["raw_rows"] == 3365
    assert artifact["window_summary"]["window1"]["talos_rows_total"] == 240
    assert artifact["window_summary"]["window1"]["talos_executable_rows_excluded"] == 60
    assert artifact["historical_aggregate"]["executable_count"] == 3615
    assert artifact["historical_aggregate"]["success_count"] == 3614
    assert artifact["historical_aggregate"]["fail_count"] == 1
    assert "talos" not in artifact["source_policy"]["historical_aggregate_sources"]
    assert "circl" not in artifact["source_policy"]["eligible_current_source_set"]
    assert artifact["source_metrics"]["circl"]["policy"]["current_policy_excluded"] is True
