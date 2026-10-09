from src.reporting.recommendation_comparison import compare_recommendations


def test_sample_recommendations_compare_by_category():
    rules = [
        "Block IOC at firewall/proxy immediately",
        "Hunt for connections to this IOC in logs (last 30 days)",
        "Isolate any affected hosts from network",
        "Create incident ticket for IR team",
        "Reset credentials on affected systems",
    ]
    ai = [
        "Immediately investigate internal network logs for any egress or ingress "
        "traffic associated with 176.120.22.24 ...",
        "Perform a retrospective search in the SIEM for historical connections "
        "to this IP ...",
        "Restore the degraded feeds (specifically AlienVault, C2_trackers, ...) "
        "and re-run the analysis ...",
        "Implement temporary block rules on perimeter firewalls or EDR solutions "
        "for this IP address ...",
    ]

    result = compare_recommendations(ai, rules)

    assert result == {
        "agreement": 2,
        "only_in_ai": 1,
        "only_in_rules": 3,
        "agreement_categories": ["block", "hunt"],
        "only_in_ai_categories": ["restore_feeds"],
        "only_in_rules_categories": ["credentials", "isolate", "ticket"],
        "comparable": True,
    }


def test_both_empty_or_none_are_incomparable_with_zero_counts():
    expected = {
        "agreement": 0,
        "only_in_ai": 0,
        "only_in_rules": 0,
        "agreement_categories": [],
        "only_in_ai_categories": [],
        "only_in_rules_categories": [],
        "comparable": False,
    }

    assert compare_recommendations(None, None) == expected
    assert compare_recommendations([], []) == expected


def test_empty_ai_with_populated_rules_is_incomparable():
    result = compare_recommendations([], ["Block the indicator"])

    assert result["comparable"] is False
    assert result["agreement"] == result["only_in_ai"] == result["only_in_rules"] == 0
    assert result["agreement_categories"] == []
    assert result["only_in_ai_categories"] == []
    assert result["only_in_rules_categories"] == []


def test_non_strings_and_blank_items_are_ignored():
    result = compare_recommendations(
        [None, 7, {}, "", "   ", "\n\t"],
        ["Block the indicator", False, "  "],
    )

    assert result["comparable"] is False
    assert result["agreement"] == result["only_in_ai"] == result["only_in_rules"] == 0


def test_unclassified_items_are_distinct_normalized_other_categories():
    result = compare_recommendations(
        ["Document   unusual activity", "Escalate to the owner"],
        ["document unusual activity"],
    )

    assert result["agreement_categories"] == ["other:document unusual activity"]
    assert result["only_in_ai_categories"] == ["other:escalate to the owner"]
    assert result["only_in_rules_categories"] == []
    assert result["agreement"] == 1
    assert result["only_in_ai"] == 1


def test_keyword_matching_is_case_insensitive():
    result = compare_recommendations(
        ["IMMEDIATELY BLOCK THE IOC"],
        ["block IOC at firewall"],
    )

    assert result["agreement_categories"] == ["block"]
    assert result["agreement"] == 1


def test_category_lists_are_sorted_and_repeated_calls_are_deterministic():
    ai = ["Create an incident ticket", "Restore the degraded feeds", "Block IOC"]
    rules = ["Reset credentials", "Isolate affected hosts", "Block IOC"]

    first = compare_recommendations(ai, rules)
    second = compare_recommendations(ai, rules)

    assert first == second
    assert first["agreement_categories"] == sorted(first["agreement_categories"])
    assert first["only_in_ai_categories"] == sorted(first["only_in_ai_categories"])
    assert first["only_in_rules_categories"] == sorted(first["only_in_rules_categories"])


def test_multiple_items_in_same_category_count_once():
    result = compare_recommendations(
        ["Block the IOC at the firewall", "Add a block rule to EDR"],
        ["Block the indicator"],
    )

    assert result["agreement"] == 1
    assert result["agreement_categories"] == ["block"]
