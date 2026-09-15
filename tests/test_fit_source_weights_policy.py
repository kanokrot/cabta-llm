import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pandas as pd


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "eval" / "fit_source_weights.py"
SPEC = importlib.util.spec_from_file_location("fit_source_weights", SCRIPT_PATH)
assert SPEC and SPEC.loader
fit_source_weights = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fit_source_weights)


def test_select_cv_sources_keeps_only_validated_group_a_sources():
    rows = [
        {"source": "feodotracker"},
        {"source": "tor_exit_nodes"},
        {"source": "spamhaus"},
        {"source": "c2_trackers"},
        {"source": "circl"},
        {"source": "sslblacklist"},
        {"source": "usom"},
        {"source": "alienvault"},
    ]

    selected, excluded = fit_source_weights.select_cv_sources(rows)

    assert selected == [
        "c2_trackers",
        "feodotracker",
        "spamhaus",
        "sslblacklist",
        "tor_exit_nodes",
        "usom",
    ]
    assert set(excluded) == {"alienvault", "circl"}
    assert "excluded permanently" in excluded["circl"]
    assert set(fit_source_weights.CV_SOURCE_ALLOWLIST) == {
        "c2_trackers",
        "feodotracker",
        "spamhaus",
        "sslblacklist",
        "tor_exit_nodes",
        "usom",
    }


def test_build_feature_matrix_can_use_explicit_source_policy():
    eval_rows = [
        {"ioc": "198.51.100.1", "expected_verdict": "MALICIOUS"},
        {"ioc": "example.org", "expected_verdict": "CLEAN"},
    ]
    cache_rows = [
        {
            "ioc": "198.51.100.1",
            "source": "spamhaus",
            "result": {"status": "✓", "found": True},
        },
        {
            "ioc": "198.51.100.1",
            "source": "alienvault",
            "result": {"status": "✓", "found": True},
        },
    ]

    features, presence, sources = fit_source_weights.build_feature_matrix(
        eval_rows, cache_rows, sources=["spamhaus", "c2_trackers"]
    )

    assert sources == ["spamhaus", "c2_trackers"]
    assert list(features.columns) == ["spamhaus", "c2_trackers", "is_malicious"]
    assert features.loc["198.51.100.1", "spamhaus"] > 0
    assert features.loc["198.51.100.1", "c2_trackers"] == 0
    assert bool(presence.loc["198.51.100.1", "spamhaus"])
    assert not bool(presence.loc["198.51.100.1", "c2_trackers"])


def test_cv_artifact_contains_provenance_policy_coverage_and_metrics():
    sources = ["feodotracker", "spamhaus"]
    feature_df = pd.DataFrame(
        {
            "feodotracker": [0, 0],
            "spamhaus": [95, 0],
            "is_malicious": [1, 0],
        },
        index=pd.Index(["198.51.100.1", "example.org"], name="ioc"),
    )
    presence_df = pd.DataFrame(
        {
            "feodotracker": [True, False],
            "spamhaus": [True, True],
        },
        index=feature_df.index,
    )
    coefficient_df = pd.DataFrame(
        {
            "source": sources,
            "mean_coef": [0.0, 1.25],
            "std_coef": [0.0, 0.1],
            "coef_per_fold": [[0.0] * 5, [1.25] * 5],
        }
    )
    metric_df = pd.DataFrame(
        {
            "fold": [1, 2],
            "accuracy": [0.5, 1.0],
            "precision": [0.5, 1.0],
            "recall": [1.0, 1.0],
            "n_test": [1, 1],
            "n_test_clean": [1, 1],
            "n_test_malicious": [0, 0],
        }
    )

    artifact = fit_source_weights.build_cv_artifact(
        created_at_utc=datetime.now(timezone.utc).isoformat(),
        eval_rows=[
            {"ioc": "198.51.100.1", "expected_verdict": "MALICIOUS"},
            {"ioc": "example.org", "expected_verdict": "CLEAN"},
        ],
        eval_path=Path("eval.jsonl"),
        cache_path=Path("cache.db"),
        matching_cache_min=datetime(2026, 9, 15, tzinfo=timezone.utc),
        latest_round_start=datetime(2026, 9, 15, 1, tzinfo=timezone.utc),
        latest_round_end=datetime(2026, 9, 15, 2, tzinfo=timezone.utc),
        cache_rows_all_count=4,
        latest_rows=[{"ioc": "198.51.100.1"}, {"ioc": "example.org"}],
        feature_df=feature_df,
        presence_df=presence_df,
        sources=sources,
        excluded_sources={"circl": "restricted"},
        coefficient_df=coefficient_df,
        metric_df=metric_df,
    )
    output_path = Path("results.json")
    with patch.object(Path, "mkdir"), patch.object(Path, "write_text") as write_text:
        fit_source_weights.write_cv_artifact(artifact, output_path)
    loaded = json.loads(write_text.call_args.args[0])

    assert loaded["artifact_version"] == 1
    assert loaded["source_policy"]["selected_sources"] == sources
    assert loaded["source_policy"]["excluded_sources"] == {"circl": "restricted"}
    assert {row["source"] for row in loaded["cache_coverage"]} == set(sources)
    assert loaded["coefficients"][1]["mean_coef"] == 1.25
    assert len(loaded["fold_metrics"]) == 2
    assert loaded["limitations"]
