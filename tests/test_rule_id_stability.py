"""Regression tests for stable generated rule identifiers."""

import os
from pathlib import Path
import subprocess
import sys

from src.detection.llm_rule_generator import LLMRuleGenerator
from src.detection.rule_generator import RuleGenerator


EMAIL_DATA = {
    "from": "alerts@example.test",
    "sender_domain": "example.test",
    "subject": "Fixed phishing campaign",
    "urls": ["https://malicious.example/payload"],
    "malicious_iocs": ["fixed-indicator"],
}
YARA_CONTEXT = {
    "sha256": "a" * 64,
    "malware_families": ["TestFamily"],
}


def test_email_gateway_rules_are_stable_within_process():
    first = RuleGenerator.generate_email_rules(EMAIL_DATA)
    second = RuleGenerator.generate_email_rules(EMAIL_DATA)

    assert first["proofpoint"] == second["proofpoint"]
    assert first["microsoft365"] == second["microsoft365"]


def test_fallback_yara_rule_is_stable_within_process():
    generator = LLMRuleGenerator(None)

    first = generator._fallback_yara(YARA_CONTEXT)
    second = generator._fallback_yara(YARA_CONTEXT)

    assert first == second


def test_generated_rule_ids_are_stable_across_processes():
    project_root = Path(__file__).resolve().parents[1]
    script = f"""
from src.detection.llm_rule_generator import LLMRuleGenerator
from src.detection.rule_generator import RuleGenerator

email_rules = RuleGenerator.generate_email_rules({EMAIL_DATA!r})
print(email_rules["proofpoint"])
print(email_rules["microsoft365"])
print(LLMRuleGenerator(None)._fallback_yara({YARA_CONTEXT!r}))
"""

    outputs = []
    for hash_seed in ("1", "2"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = hash_seed
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=project_root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs.append(result.stdout)

    assert outputs[0] == outputs[1]
