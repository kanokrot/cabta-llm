from src.utils.config import get_default_config, merge_with_defaults


def test_merge_aliases_canonical_hybrid_analysis_key():
    config = merge_with_defaults({
        "api_keys": {
            "hybrid_analysis": "canonical-test-key",
        }
    })

    assert config["api_keys"]["hybrid_analysis"] == "canonical-test-key"
    assert config["api_keys"]["hybridanalysis"] == "canonical-test-key"


def test_merge_aliases_legacy_hybridanalysis_key():
    config = merge_with_defaults({
        "api_keys": {
            "hybridanalysis": "legacy-test-key",
        }
    })

    assert config["api_keys"]["hybridanalysis"] == "legacy-test-key"
    assert config["api_keys"]["hybrid_analysis"] == "legacy-test-key"


def test_default_config_aliases_hybrid_analysis_environment_key(monkeypatch):
    monkeypatch.setenv("HYBRID_API_KEY", "environment-test-key")

    config = get_default_config()

    assert config["api_keys"]["hybridanalysis"] == "environment-test-key"
    assert config["api_keys"]["hybrid_analysis"] == "environment-test-key"
