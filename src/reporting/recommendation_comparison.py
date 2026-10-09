"""Deterministic category-level comparison for AI and rule recommendations."""

from __future__ import annotations


# Keep terms lowercase; matching uses casefolded recommendation text.
CATEGORY_KEYWORDS = {
    "block": (
        "block",
        "firewall",
        "proxy",
        "edr rule",
        "deny",
    ),
    "hunt": (
        "hunt",
        "investigate",
        "search",
        "siem",
        "logs",
        "historical connection",
        "retrospective",
    ),
    "isolate": (
        "isolate",
        "isolation",
        "quarantine",
        "disconnect from network",
    ),
    "ticket": (
        "ticket",
        "incident case",
        "create a case",
    ),
    "credentials": (
        "credential",
        "password",
        "account secret",
    ),
    "restore_feeds": (
        "restore feed",
        "restore the degraded feeds",
        "feed restoration",
    ),
}


def _normalize(text: str) -> str:
    """Casefold text and collapse whitespace for stable category keys."""
    return " ".join(text.casefold().split())


def _categories(items: list[str] | None) -> tuple[set[str], int]:
    categories: set[str] = set()
    valid_item_count = 0

    if not isinstance(items, list):
        return categories, valid_item_count

    for item in items:
        if not isinstance(item, str):
            continue
        normalized = _normalize(item)
        if not normalized:
            continue

        valid_item_count += 1
        matched = False
        for category, keywords in CATEGORY_KEYWORDS.items():
            if any(keyword.casefold() in normalized for keyword in keywords):
                categories.add(category)
                matched = True
        if not matched:
            categories.add(f"other:{normalized}")

    return categories, valid_item_count


def compare_recommendations(
    ai_items: list[str] | None,
    rule_items: list[str] | None,
) -> dict:
    """Compare recommendation categories, counting each category once.

    Invalid and blank entries are ignored. If either side has no valid entries,
    the comparison is marked incomparable and all result sets and counts are
    empty/zero.
    """
    ai_categories, ai_valid_count = _categories(ai_items)
    rule_categories, rule_valid_count = _categories(rule_items)

    if not ai_valid_count or not rule_valid_count:
        agreement_categories: list[str] = []
        only_in_ai_categories: list[str] = []
        only_in_rules_categories: list[str] = []
        comparable = False
    else:
        agreement_categories = sorted(ai_categories & rule_categories)
        only_in_ai_categories = sorted(ai_categories - rule_categories)
        only_in_rules_categories = sorted(rule_categories - ai_categories)
        comparable = True

    return {
        "agreement": len(agreement_categories),
        "only_in_ai": len(only_in_ai_categories),
        "only_in_rules": len(only_in_rules_categories),
        "agreement_categories": agreement_categories,
        "only_in_ai_categories": only_in_ai_categories,
        "only_in_rules_categories": only_in_rules_categories,
        "comparable": comparable,
    }
