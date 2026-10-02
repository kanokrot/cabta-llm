"""Real yara-python match/no-match evidence for generated YARA rules."""

from __future__ import annotations

import hashlib

import yara

from src.detection.rule_generator import RuleGenerator
from src.tools.malware_analyzer import MalwareAnalyzer


CLEAN_BUFFER = b"hello world, benign text"


def test_generated_yara_hash_and_ioc_rule():
    sample = b"sample executable bytes"
    ioc = "http://evil.example/callback"
    file_data = {
        "filename": "hash-and-ioc.exe",
        "sha256": hashlib.sha256(sample).hexdigest(),
        "md5": "b" * 32,
        "suspicious_indicators": ["DIE: Packed with UPX"],
        "iocs": [ioc],
    }
    rule_text = RuleGenerator.generate_file_rules(file_data)["yara"]

    rules = yara.compile(source=rule_text)
    hash_match = bool(rules.match(data=sample))
    ioc_match = bool(rules.match(data=ioc.encode("ascii")))
    clean_match = bool(rules.match(data=CLEAN_BUFFER))
    assert "$sus_" not in rule_text
    assert hash_match is True
    assert ioc_match is True
    assert clean_match is False


def test_generated_yara_hash_only_rule():
    sample = b"hash-only sample"
    file_data = {
        "filename": "hash-only.exe",
        "sha256": hashlib.sha256(sample).hexdigest(),
        "md5": "b" * 32,
        "iocs": [],
    }
    rule_text = RuleGenerator.generate_file_rules(file_data)["yara"]

    rules = yara.compile(source=rule_text)
    own_match = bool(rules.match(data=sample))
    different_match = bool(rules.match(data=b"different sample"))
    assert own_match is True
    assert different_match is False


def test_generated_yara_ioc_rule_matches_ascii_and_utf16():
    ioc = "http://evil.example/utf16"
    file_data = {
        "filename": "ioc-only.exe",
        "sha256": "",
        "md5": "b" * 32,
        "iocs": [ioc],
    }
    rule_text = RuleGenerator.generate_file_rules(file_data)["yara"]

    rules = yara.compile(source=rule_text)
    ascii_match = bool(rules.match(data=ioc.encode("ascii")))
    utf16_match = bool(rules.match(data=ioc.encode("utf-16-le")))
    clean_match = bool(rules.match(data=CLEAN_BUFFER))
    assert ascii_match is True
    assert utf16_match is True
    assert clean_match is False


def test_generated_yara_escapes_quote_backslash_and_non_ascii():
    file_data = {
        "filename": "escaped.exe",
        "sha256": "",
        "md5": "d" * 32,
        "iocs": ['quote" slash\\ café'],
    }
    rule_text = RuleGenerator.generate_file_rules(file_data)["yara"]
    yara.compile(source=rule_text)


def test_generated_yara_empty_inputs_return_empty():
    assert RuleGenerator.generate_file_rules({"filename": "empty.exe"})["yara"] == ""


def test_generated_yara_rule_names_compile_for_special_filenames():
    for filename in ["my file (1).exe", "ทดสอบ.exe", "1abc.exe", "a.b-c.exe"]:
        rule_text = RuleGenerator.generate_file_rules({
            "filename": filename,
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "iocs": [],
        })["yara"]
        yara.compile(source=rule_text)


def test_rule_ioc_filter_drops_absent_and_clean_values(tmp_path):
    ascii_ioc = "ascii.example"
    wide_ioc = "wide.example"
    absent_ioc = "absent.example"
    clean_ioc = "clean.example"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(
        ascii_ioc.encode("ascii") + b"\x00" + wide_ioc.encode("utf-16-le")
    )
    results = [
        {"ioc": ascii_ioc, "verdict": "MALICIOUS"},
        {"ioc": wide_ioc, "verdict": "SUSPICIOUS"},
        {"ioc": absent_ioc, "verdict": "MALICIOUS"},
        {"ioc": clean_ioc, "verdict": "CLEAN"},
    ]

    actual = MalwareAnalyzer._filter_rule_iocs(
        str(sample), [clean_ioc, absent_ioc, wide_ioc, ascii_ioc], results
    )
    assert actual == [ascii_ioc, wide_ioc]


def test_file_rule_data_keeps_siem_hash_for_clean_and_yara_for_malicious(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"sample bytes")
    sha256 = hashlib.sha256(sample.read_bytes()).hexdigest()
    hashes = {"sha256": sha256, "md5": "b" * 32}
    yara_analysis = {"tags": []}

    clean_data = MalwareAnalyzer._build_file_rule_data(
        str(sample), hashes, "CLEAN", [], [], yara_analysis
    )
    clean_rules = {}
    assert clean_data["emit_yara"] is False
    assert all(clean_rules.get(rule_type, "") == "" for rule_type in (
        "yara", "kql", "spl", "xql", "dql", "sigma"
    ))

    malicious_data = MalwareAnalyzer._build_file_rule_data(
        str(sample), hashes, "MALICIOUS", [], [], yara_analysis
    )
    malicious_rules = RuleGenerator.generate_file_rules(malicious_data)
    assert "_exact" in malicious_rules["yara"]
    assert sha256 in malicious_rules["kql"]
    assert sha256 in malicious_rules["spl"]
    assert sha256 in malicious_rules["sigma"]

    suspicious_data = MalwareAnalyzer._build_file_rule_data(
        str(sample), hashes, "SUSPICIOUS", [], [], yara_analysis
    )
    suspicious_rules = RuleGenerator.generate_file_rules(suspicious_data)
    assert "_exact" in suspicious_rules["yara"]
    assert sha256 in suspicious_rules["kql"]
    assert sha256 in suspicious_rules["spl"]
    assert sha256 in suspicious_rules["sigma"]


def test_clean_verdict_inputs_emit_no_yara_rule():
    file_data = {
        "filename": "clean.exe",
        "md5": "b" * 32,
        "yara_tags": [],
    }
    rule_text = RuleGenerator.generate_file_rules(file_data)["yara"]
    assert rule_text == ""
