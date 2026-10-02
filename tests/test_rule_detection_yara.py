"""Real yara-python match/no-match evidence for generated YARA rules."""

from __future__ import annotations

import sys

import pytest
import yara

from src.detection.rule_generator import RuleGenerator


def _emit(text: str) -> None:
    sys.__stdout__.write(text + "\n")
    sys.__stdout__.flush()


GENERIC_BUFFER = (
    b"powershell -encodedcommand powershell -executionpolicy bypass "
    b"powershell -windowstyle hidden WScript.Shell Shell( .Run( .Exec("
)
CLEAN_BUFFER = b"hello world, benign text"


YARA_CASES = [
    pytest.param(
        "two-indicators-one-ioc",
        ["VirtualAllocEx", "WriteProcessMemory"],
        ["http://evil.example/callback"],
        True,
        False,
        id="two-indicators-one-ioc",
    ),
    pytest.param(
        "one-indicator-no-ioc",
        ["VirtualAllocEx"],
        [],
        True,
        False,
        id="one-indicator-no-ioc",
    ),
    pytest.param(
        "no-indicator-two-iocs",
        [],
        ["http://evil.example/a", "http://evil.example/b"],
        True,
        False,
        id="no-indicator-two-iocs",
    ),
    pytest.param(
        "no-indicator-no-ioc",
        [],
        [],
        False,
        False,
        id="no-indicator-no-ioc",
    ),
]


@pytest.mark.parametrize(
    ("case_name", "indicators", "iocs", "expected_own_match", "expected_generic_match"),
    YARA_CASES,
)
def test_generated_yara_real_match_matrix(
    case_name: str,
    indicators: list[str],
    iocs: list[str],
    expected_own_match: bool,
    expected_generic_match: bool,
):
    file_data = {
        "filename": f"{case_name}.exe",
        "sha256": "a" * 64,
        "md5": "b" * 32,
        "malware_family": "TestFamily",
        "suspicious_indicators": indicators,
        "iocs": iocs,
    }
    rule_text = RuleGenerator.generate_file_rules(file_data)["yara"]

    _emit(f"YARA CASE: {case_name}")
    _emit("GENERATED RULE:")
    _emit(rule_text)
    own_parts = indicators + iocs
    own_buffer = " ".join(own_parts).encode("utf-8")
    if not rule_text:
        _emit("COMPILE: NOT_AVAILABLE (empty rule)")
        own_match = False
        clean_match = False
        generic_match = False
    else:
        try:
            rules = yara.compile(source=rule_text)
        except Exception as exc:  # pragma: no cover - evidence is asserted below
            _emit(f"COMPILE: FAIL {type(exc).__name__}: {exc}")
            raise
        _emit("COMPILE: PASS")
        own_match = bool(rules.match(data=own_buffer))
        clean_match = bool(rules.match(data=CLEAN_BUFFER))
        generic_match = bool(rules.match(data=GENERIC_BUFFER))
    _emit(f"OWN_BUFFER: {own_buffer!r}")
    _emit(f"OWN_MATCH: {own_match}")
    _emit(f"CLEAN_MATCH: {clean_match}")
    _emit(f"GENERIC_MATCH: {generic_match}")

    assert own_match is expected_own_match, (
        f"{case_name}: own_match={own_match}; expected={expected_own_match}"
    )
    assert clean_match is False
    assert generic_match is expected_generic_match


def test_generated_yara_escapes_quote_backslash_and_non_ascii():
    file_data = {
        "filename": "escaped.exe",
        "sha256": "c" * 64,
        "md5": "d" * 32,
        "suspicious_indicators": ['quote" slash\\ café'],
        "iocs": [],
    }
    rule_text = RuleGenerator.generate_file_rules(file_data)["yara"]
    _emit("YARA CASE: quote-backslash-non-ascii")
    _emit("GENERATED RULE:")
    _emit(rule_text)
    try:
        yara.compile(source=rule_text)
    except Exception as exc:
        _emit(f"COMPILE: FAIL {type(exc).__name__}: {exc}")
        raise
    _emit("COMPILE: PASS")
