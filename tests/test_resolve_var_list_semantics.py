"""Characterization tests for dotted variable lookup through list values."""

from src.agent.playbook_engine import _resolve_var


def _candidate_alias_context(results):
    return {
        "url_urlhaus": results,
        "url_urlhaus_results": results,
        "url_urlhaus_any_malicious": True,
        "url_urlhaus_items": [item["indicator"] for item in results],
    }


def test_dotted_lookup_on_single_item_list_returns_none():
    results = [
        {"malicious": True, "indicator": "https://malicious.example"},
    ]
    context = _candidate_alias_context(results)

    result = _resolve_var("url_urlhaus.malicious", context)

    assert result is None, f"observed: {result!r} ({type(result)})"


def test_dotted_lookup_does_not_aggregate_multiple_list_items():
    results = [
        {"malicious": False, "indicator": "https://clean.example"},
        {"malicious": True, "indicator": "https://malicious.example"},
    ]
    context = _candidate_alias_context(results)

    result = _resolve_var("url_urlhaus.malicious", context)

    assert result is None, f"observed: {result!r} ({type(result)})"
