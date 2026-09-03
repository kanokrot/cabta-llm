"""
Regression test for safe_evaluate_condition bare-{{var}} bug.

Confirmed root cause (playbook_engine.py lines ~210-303):
_SIMPLE_COND / _IN_COND / _VAR_IN_TUPLE all require an operator (==, !=,
>, >=, <, <=) or the 'in' keyword. A condition that is just a bare
variable/dotted-path placeholder (e.g. "{{hash_reputation_check.malicious}}")
never matches any of them, falls through to the "Unrecognised pattern"
branch, and returns False unconditionally -- regardless of the actual
value in context.

This breaks any playbook condition written as bare {{var}} whether used
alone, in an "or" clause, or in an "and" clause (forensic_triage.yaml:130
is the confirmed real-world example: evaluate_triage -> confirm_incident).

These tests are expected to FAIL on the unpatched code and PASS once
safe_evaluate_condition gains a branch that resolves a bare var via
_resolve_var and returns bool(value) before falling through to the
"Unrecognised pattern" default.
"""

import pytest

from src.agent.playbook_engine import safe_evaluate_condition


def test_bare_dotted_var_true():
    """A bare {{var.path}} with a truthy nested value should be True."""
    context = {"hash_reputation_check": {"malicious": True}}
    assert safe_evaluate_condition(
        "{{hash_reputation_check.malicious}}", context
    ) is True


def test_bare_flat_var_true():
    """A bare {{var}} with a truthy top-level value should be True."""
    context = {"single_true": True}
    assert safe_evaluate_condition("{{single_true}}", context) is True


def test_full_comparison_still_works():
    """Control case: syntax with an explicit operator already works."""
    context = {"process_ip_reputation_any_malicious": True}
    assert safe_evaluate_condition(
        "process_ip_reputation_any_malicious == true", context
    ) is True


def test_or_condition_true_via_bare_hash_malicious():
    """
    Exact shape from forensic_triage.yaml:130 (evaluate_triage step).
    hash_reputation_check.malicious=True should make the OR True even
    though the other two clauses are False.
    """
    context = {
        "hash_reputation_check": {"malicious": True},
        "process_ip_reputation_any_malicious": False,
        "persistence_check": {"suspicious": False},
    }
    condition = (
        "{{hash_reputation_check.malicious}} or "
        "process_ip_reputation_any_malicious == true or "
        "{{persistence_check.suspicious}}"
    )
    assert safe_evaluate_condition(condition, context) is True


def test_or_condition_true_via_bare_persistence_suspicious():
    """
    Same shape as above, but persistence_check.suspicious=True instead.
    Should also make the OR True.
    """
    context = {
        "hash_reputation_check": {"malicious": False},
        "process_ip_reputation_any_malicious": False,
        "persistence_check": {"suspicious": True},
    }
    condition = (
        "{{hash_reputation_check.malicious}} or "
        "process_ip_reputation_any_malicious == true or "
        "{{persistence_check.suspicious}}"
    )
    assert safe_evaluate_condition(condition, context) is True


def test_or_condition_false_when_all_clauses_false():
    """Control case: when every clause is genuinely False, result is False."""
    context = {
        "hash_reputation_check": {"malicious": False},
        "process_ip_reputation_any_malicious": False,
        "persistence_check": {"suspicious": False},
    }
    condition = (
        "{{hash_reputation_check.malicious}} or "
        "process_ip_reputation_any_malicious == true or "
        "{{persistence_check.suspicious}}"
    )
    assert safe_evaluate_condition(condition, context) is False


def test_and_condition_true_with_bare_var():
    """AND-condition with a bare var on the left should also resolve correctly."""
    context = {"left": True, "right": True}
    assert safe_evaluate_condition("{{left}} and right == true", context) is True


def test_bare_var_list_truthy_when_nonempty():
    """A bare variable resolving to a non-empty list should be True."""
    context = {"ips": ["1.2.3.4"]}
    assert safe_evaluate_condition("{{ips}}", context) is True


def test_bare_var_list_falsy_when_empty():
    """A bare variable resolving to an empty list should be False."""
    context = {"ips": []}
    assert safe_evaluate_condition("{{ips}}", context) is False


def test_bare_var_falsy_when_unresolvable():
    """An unresolvable bare variable should remain False."""
    assert safe_evaluate_condition("{{missing.path}}", {}) is False


def test_bare_var_no_dot_path():
    """A truthy flat string variable should be True."""
    context = {"suspicious_file_path": "C:\\evidence\\sample.bin"}
    assert safe_evaluate_condition("{{suspicious_file_path}}", context) is True
