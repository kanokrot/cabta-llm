"""Regression coverage for dynamic detection-rule HTML rendering."""

from src.reporting.html_report_generator import HTMLReportGenerator


def _render(rules):
    return HTMLReportGenerator()._render_detection_rules_section(
        rules, "DETECTION RULES"
    )


def test_ioc_shape_renders_all_formats_without_fake_yara_placeholder():
    rules = {
        "kql": "ioc kql content",
        "spl": "ioc spl content",
        "sigma": "ioc sigma content",
        "xql": "ioc xql content",
        "dql": "ioc dql content",
        "suricata": "ioc suricata content",
        "firewall": "ioc firewall content",
    }

    rendered = _render(rules)

    assert rendered.count('class="accordion-item"') == len(rules)
    for content in rules.values():
        assert content in rendered
    assert "No YARA rule generated" not in rendered
    assert "YARA Rule" not in rendered


def test_file_shape_still_renders_yara_and_all_other_formats():
    rules = {
        "kql": "file kql content",
        "spl": "file spl content",
        "yara": "rule file_yara { condition: true }",
        "sigma": "file sigma content",
    }

    rendered = _render(rules)

    assert rendered.count('class="accordion-item"') == len(rules)
    for content in rules.values():
        assert content in rendered
    assert "YARA Rule" in rendered


def test_email_shape_renders_every_gateway_format():
    rules = {
        "kql": "email kql content",
        "sigma": "email sigma content",
        "spl": "email spl content",
        "yara": "email yara content",
        "fortimail": "email fortimail content",
        "proofpoint": "email proofpoint content",
        "mimecast": "email mimecast content",
        "microsoft365": "email microsoft365 content",
    }

    rendered = _render(rules)

    assert rendered.count('class="accordion-item"') == len(rules)
    for content in rules.values():
        assert content in rendered
    assert "FORTIMAIL" in rendered
    assert "MIMECAST" in rendered
    assert "MICROSOFT365" in rendered


def test_capa_list_values_render_as_joined_rules_not_python_repr():
    rules = {
        "yara": ["capa yara rule one", "capa yara rule two"],
        "sigma": ["capa sigma rule one", "capa sigma rule two"],
    }

    rendered = _render(rules)

    for rule_list in rules.values():
        for rule in rule_list:
            assert rule in rendered
    assert "capa yara rule one\n\ncapa yara rule two" in rendered
    assert "capa sigma rule one\n\ncapa sigma rule two" in rendered
    assert "['capa yara rule one'" not in rendered
    assert "['capa sigma rule one'" not in rendered


def test_optional_firewall_fortigate_format_renders_when_present():
    rendered = _render({
        "kql": "ioc kql content",
        "firewall_fortigate": "config firewall address fortigate-content",
    })

    assert "FIREWALL FORTIGATE" in rendered
    assert "config firewall address fortigate-content" in rendered
    assert rendered.count('class="accordion-item"') == 2


def test_empty_rule_values_are_skipped():
    rendered = _render({
        "kql": "real kql content",
        "yara": "",
        "sigma": [],
        "xql": None,
    })

    assert rendered.count('class="accordion-item"') == 1
    assert "real kql content" in rendered
    assert "YARA Rule" not in rendered
    assert "SIGMA Rule" not in rendered
    assert "XQL" not in rendered


def test_empty_rules_dict_returns_empty_string():
    assert _render({}) == ""
