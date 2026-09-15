import importlib.util
from pathlib import Path


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

    assert selected == ["c2_trackers", "feodotracker", "spamhaus", "tor_exit_nodes"]
    assert set(excluded) == {"alienvault", "circl", "sslblacklist", "usom"}
    assert "404/401" in excluded["circl"]
    assert "deprecated" in excluded["sslblacklist"]
    assert "paginated" in excluded["usom"]


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

