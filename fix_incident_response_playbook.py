"""
fix_incident_response_playbook.py
Fix path bugs in data/playbooks/incident_response.yaml.

Root cause: the `extract_iocs` tool (src/agent/tool_registry.py) returns
    {"iocs": {"ipv4": [...], "domains": [...], "urls": [...],
              "md5": [...], "sha1": [...], "sha256": [...], "sha512": [...], ...}}
but the playbook YAML references flat, non-existent paths like
`extract_incident_iocs.hashes`, `.ips`, `.domains`, `.urls`, `.all_iocs`.
Because `_resolve_var()` in playbook_engine.py returns None (not an error)
for missing paths, every affected `for_each` step silently iterated over
an empty list -- no exception, no visible failure.

This script ONLY edits the YAML file. It does not touch any .py file,
and does not touch MCP tool wiring.

Run from the project root:
    python fix_incident_response_playbook.py
Then review with:
    git diff data\\playbooks\\incident_response.yaml
"""
import re
import sys
from pathlib import Path

PLAYBOOK_PATH = Path("data/playbooks/incident_response.yaml")


def main():
    if not PLAYBOOK_PATH.is_file():
        print(f"ERROR: {PLAYBOOK_PATH} not found. Run this from the project root "
              f"(D:\\ai_cti_automate).")
        sys.exit(1)

    original = PLAYBOOK_PATH.read_text(encoding="utf-8")
    content = original

    # ------------------------------------------------------------------
    # Group A: simple for_each path fixes (field exists, just nested
    # under `iocs`, and hashes/ips need to collapse to one concrete type)
    # ------------------------------------------------------------------
    replacements = [
        (r'for_each:\s*"extract_incident_iocs\.hashes"',
         'for_each: "extract_incident_iocs.iocs.sha256"'),
        (r'for_each:\s*"extract_incident_iocs\.ips"',
         'for_each: "extract_incident_iocs.iocs.ipv4"'),
        (r'for_each:\s*"extract_incident_iocs\.domains"',
         'for_each: "extract_incident_iocs.iocs.domains"'),
        (r'for_each:\s*"extract_incident_iocs\.urls"',
         'for_each: "extract_incident_iocs.iocs.urls"'),
    ]
    for pattern, repl in replacements:
        content, n = re.subn(pattern, repl, content)
        print(f"  {pattern!r}: {n} replacement(s)")

    # ------------------------------------------------------------------
    # Group B (safe): {{extract_incident_iocs.all_iocs}} -> the whole
    # iocs dict, for the 4 non-for_each interpolation sites
    # (zeek_log_analysis, suricata_alert_analysis, monitor_and_assess,
    # verify_clean).
    # ------------------------------------------------------------------
    content, n = re.subn(
        r"\{\{extract_incident_iocs\.all_iocs\}\}",
        "{{extract_incident_iocs.iocs}}",
        content,
    )
    print(f"  {{{{extract_incident_iocs.all_iocs}}}} interpolation: {n} replacement(s)")

    # ------------------------------------------------------------------
    # Group B (threatfox_check): split the single for_each: all_iocs step
    # into 4 typed steps (ipv4 / domains / urls / sha256), preserving
    # sequential flow (no on_success/on_failure was set on the original,
    # so none is set on the replacements either -- falls through to the
    # next step, feodo_check, exactly as before).
    # ------------------------------------------------------------------
    old_threatfox = (
        "  - name: threatfox_check\n"
        "    tool: mcp:threat-intel-free/threatfox_ioc_lookup\n"
        "    for_each: \"extract_incident_iocs.all_iocs\"\n"
        "    params:\n"
        "      indicator: \"{{item}}\"\n"
        "    description: Check all IOCs in ThreatFox\n"
    )
    new_threatfox = (
        "  - name: threatfox_check_ipv4\n"
        "    tool: mcp:threat-intel-free/threatfox_ioc_lookup\n"
        "    for_each: \"extract_incident_iocs.iocs.ipv4\"\n"
        "    params:\n"
        "      indicator: \"{{item}}\"\n"
        "    description: Check IPv4 IOCs in ThreatFox\n"
        "\n"
        "  - name: threatfox_check_domains\n"
        "    tool: mcp:threat-intel-free/threatfox_ioc_lookup\n"
        "    for_each: \"extract_incident_iocs.iocs.domains\"\n"
        "    params:\n"
        "      indicator: \"{{item}}\"\n"
        "    description: Check domain IOCs in ThreatFox\n"
        "\n"
        "  - name: threatfox_check_urls\n"
        "    tool: mcp:threat-intel-free/threatfox_ioc_lookup\n"
        "    for_each: \"extract_incident_iocs.iocs.urls\"\n"
        "    params:\n"
        "      indicator: \"{{item}}\"\n"
        "    description: Check URL IOCs in ThreatFox\n"
        "\n"
        "  - name: threatfox_check_sha256\n"
        "    tool: mcp:threat-intel-free/threatfox_ioc_lookup\n"
        "    for_each: \"extract_incident_iocs.iocs.sha256\"\n"
        "    params:\n"
        "      indicator: \"{{item}}\"\n"
        "    description: Check SHA256 hash IOCs in ThreatFox\n"
    )

    if old_threatfox in content:
        content = content.replace(old_threatfox, new_threatfox)
        print("  threatfox_check block: 1 replacement (split into 4 steps)")
    else:
        print("  WARNING: threatfox_check block not found verbatim -- "
              "NOT split. Check for whitespace/formatting drift and "
              "edit manually if needed.")

    # ------------------------------------------------------------------
    # Write back only if something changed
    # ------------------------------------------------------------------
    if content == original:
        print("\nNo changes made (file already matches, or patterns didn't match).")
        return

    PLAYBOOK_PATH.write_text(content, encoding="utf-8")
    print(f"\nWrote changes to {PLAYBOOK_PATH}")
    print("Next steps:")
    print(r"  git diff data\playbooks\incident_response.yaml")
    print(r"  python -c ""import yaml; yaml.safe_load(open('data/playbooks/incident_response.yaml', encoding='utf-8')); print('OK - valid YAML')""")


if __name__ == "__main__":
    main()
