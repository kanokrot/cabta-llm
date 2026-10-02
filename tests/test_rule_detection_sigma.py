"""Real event evaluation evidence for generated Sigma rules."""

from __future__ import annotations

import sys

import pytest
import yaml

from src.detection.rule_generator import RuleGenerator
from src.detection.rule_validator import validate_rule
from tests.helpers.sigma_subset_matcher import match_sigma_document


def _emit(text: str) -> None:
    sys.__stdout__.write(text + "\n")
    sys.__stdout__.flush()


IOC_CASES = [
    pytest.param(
        "ipv4",
        "203.0.113.42",
        {"dst_ip": "203.0.113.42", "src_ip": "198.51.100.10"},
        {"dst_ip": "198.51.100.10", "src_ip": "198.51.100.11"},
        id="ipv4",
    ),
    pytest.param(
        "domain",
        "malicious.example",
        {"query": "www.malicious.example"},
        {"query": "www.benign.example"},
        id="domain",
    ),
    pytest.param(
        "url",
        "https://malicious.example/payload",
        {"c-uri": "https://malicious.example/payload?id=1"},
        {"c-uri": "https://benign.example/payload"},
        id="url",
    ),
    pytest.param(
        "sha256",
        "a" * 64,
        {"Hashes": "SHA256=" + "a" * 64},
        {"Hashes": "SHA256=" + "b" * 64},
        id="sha256",
    ),
]


@pytest.mark.parametrize(
    ("ioc_type", "ioc", "positive_event", "negative_event"),
    IOC_CASES,
)
def test_generated_sigma_ioc_match_matrix(
    ioc_type: str,
    ioc: str,
    positive_event: dict[str, str],
    negative_event: dict[str, str],
):
    rule_text = RuleGenerator.generate_ioc_rules(
        ioc, ioc_type, {"verdict": "MALICIOUS", "malware_family": "TestFamily"}
    )["sigma"]
    document = yaml.safe_load(rule_text)
    positive_match = match_sigma_document(document, positive_event)
    negative_match = match_sigma_document(document, negative_event)

    _emit(f"SIGMA CASE: IOC {ioc_type}")
    _emit("GENERATED RULE:")
    _emit(rule_text)
    _emit(f"POSITIVE_EVENT: {positive_event!r}")
    _emit(f"POSITIVE_MATCH: {positive_match}")
    _emit(f"NEGATIVE_EVENT: {negative_event!r}")
    _emit(f"NEGATIVE_MATCH: {negative_match}")
    _emit(f"AUTHOR: {document.get('author')!r}")
    _emit(f"REFERENCES: {document.get('references')!r}")

    assert positive_match is True
    assert negative_match is False
    assert document["author"] == "Ugur Ates"
    assert document["references"] == [
        "https://github.com/ugur-ates/blue-team-assistant"
    ]


@pytest.mark.parametrize(
    ("scenario", "event"),
    [
        (
            "file-image-path",
            {
                "Image": r"C:\Users\x\malware.exe",
                "OriginalFileName": "benign.exe",
                "Hashes": "SHA256=not-the-sample",
            },
        ),
        (
            "file-sha256",
            {
                "Image": r"C:\Users\x\benign.exe",
                "OriginalFileName": "benign.exe",
                "Hashes": "SHA256=" + "a" * 64,
            },
        ),
    ],
)
def test_generated_sigma_file_positive_events(scenario: str, event: dict[str, str]):
    file_data = {
        "filename": "malware.exe",
        "sha256": "a" * 64,
        "md5": "b" * 32,
        "malware_family": "TestFamily",
        "suspicious_indicators": [],
        "iocs": [],
    }
    rule_text = RuleGenerator.generate_file_rules(file_data)["sigma"]
    document = yaml.safe_load(rule_text)
    actual = match_sigma_document(document, event)

    _emit(f"SIGMA CASE: {scenario}")
    _emit("GENERATED RULE:")
    _emit(rule_text)
    _emit(f"EVENT: {event!r}")
    _emit(f"MATCH: {actual}")

    assert actual is True


def test_sigma_unknown_selection_condition_is_recorded():
    rule_text = RuleGenerator.generate_ioc_rules(
        "203.0.113.42", "ipv4", {}
    )["sigma"]
    document = yaml.safe_load(rule_text)
    document["detection"]["condition"] = "selection_missing"
    mutated_rule = yaml.safe_dump(document, sort_keys=False)
    validation = validate_rule("sigma", mutated_rule)

    _emit("SIGMA CASE: unknown-condition-selection")
    _emit("RULE:")
    _emit(mutated_rule)
    _emit(f"VALIDATION: {validation!r}")

    assert validation["valid"] is False
    assert validation["status"] == "pysigma_rejected"
    assert "Sigma condition references undefined selection: selection_missing" in validation["errors"]
