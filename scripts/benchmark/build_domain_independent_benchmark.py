#!/usr/bin/env python3
"""Build a domain-independent benchmark without modifying existing datasets."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BACKUP = REPO_ROOT / "data" / "benchmark" / "benchmark_iocs_v2_backup.json"
DEFAULT_CASE_CONTROL = REPO_ROOT / "scripts" / "adhoc" / "case_control_malicious.json"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "benchmark" / "benchmark_iocs_v3_domain_independent.json"


def normalize_ioc(value):
    return str(value or "")


def normalize_label_source(value):
    return str(value or "").strip().lower().replace(" ", "_")


def label_providers(row):
    provenance = row.get("source_provenance") or {}
    providers = provenance.get("providers") or []
    if not providers:
        providers = [item.get("source") for item in provenance.get("evidence", [])]
    return list(dict.fromkeys(
        normalize_label_source(provider)
        for provider in providers
        if provider
    ))


def build_domain_record(row, collected_at):
    evidence = (row.get("source_provenance") or {}).get("evidence", [])
    providers = label_providers(row)
    first_seen = next((item.get("first_seen") for item in evidence if item.get("first_seen")), None)
    return {
        "ioc": normalize_ioc(row["domain"]),
        "ioc_type": "domain",
        "expected_verdict": "MALICIOUS",
        "source": providers[0] if providers else "unknown",
        "label_sources": providers,
        "label_provenance": {
            "providers": providers,
            "evidence": evidence,
        },
        "first_seen": first_seen,
        "collected_at": collected_at,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", type=Path, default=DEFAULT_BACKUP)
    parser.add_argument("--case-control", type=Path, default=DEFAULT_CASE_CONTROL)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    backup = json.loads(args.backup.read_text(encoding="utf-8"))
    case_control = json.loads(args.case_control.read_text(encoding="utf-8"))
    backup_iocs = [normalize_ioc(row.get("ioc")) for row in backup]
    backup_ioc_set = set(backup_iocs)
    duplicate_backup_iocs = {ioc for ioc in backup_iocs if backup_iocs.count(ioc) > 1}

    removed = [
        row for row in backup
        if (
            row.get("ioc_type") == "domain"
            and row.get("expected_verdict") == "MALICIOUS"
            and row.get("source") == "circl_misp_feed_osint"
        )
    ]
    filtered = [row for row in backup if row not in removed]
    filtered_iocs = [normalize_ioc(row.get("ioc")) for row in filtered]
    filtered_ioc_set = set(filtered_iocs)

    case_rows = case_control.get("domains", [])
    case_by_ioc = {}
    for row in case_rows:
        ioc = normalize_ioc(row.get("domain"))
        if ioc:
            case_by_ioc.setdefault(ioc, row)
    candidate_iocs = sorted(set(case_by_ioc))
    overlap_before = set(candidate_iocs) & filtered_ioc_set
    eligible = [ioc for ioc in candidate_iocs if ioc not in filtered_ioc_set]
    if len(eligible) < args.count:
        raise SystemExit(f"only {len(eligible)} eligible ThreatFox domains; need {args.count}")

    rng = random.Random(args.seed)
    selected_iocs = rng.sample(eligible, args.count)
    selected_records = [
        build_domain_record(case_by_ioc[ioc], case_control.get("collected_at_utc"))
        for ioc in selected_iocs
    ]
    selected_ioc_set = {normalize_ioc(row["ioc"]) for row in selected_records}
    overlap_after = selected_ioc_set & filtered_ioc_set
    duplicate_selected = len(selected_records) - len(selected_ioc_set)
    if overlap_after or duplicate_selected:
        raise SystemExit(
            f"dedup invariant failed: overlap_after={len(overlap_after)} "
            f"duplicate_selected={duplicate_selected}"
        )

    output_rows = filtered + selected_records
    output_iocs = [normalize_ioc(row.get("ioc")) for row in output_rows]
    output_unique = len(set(output_iocs))
    if output_unique != len(output_rows):
        raise SystemExit(f"output duplicate invariant failed: rows={len(output_rows)} unique={output_unique}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output_rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"backup_rows={len(backup)}")
    print(f"removed_circl_malicious_domains={len(removed)}")
    print(f"filtered_rows={len(filtered)}")
    print(f"case_control_unique_domains={len(candidate_iocs)}")
    print(f"overlap_with_filtered_before_sampling={len(overlap_before)}")
    print(f"eligible_after_dedup={len(eligible)}")
    print(f"selected_threatfox_domains={len(selected_records)}")
    print(f"overlap_after_sampling={len(overlap_after)}")
    print(f"output_rows={len(output_rows)}")
    print(f"output_unique_ioc={output_unique}")
    print(f"seed={args.seed}")
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
