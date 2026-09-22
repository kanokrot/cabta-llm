#!/usr/bin/env python3
"""Build a standalone CLEAN IOC additions file without touching the base benchmark.

The additions are deliberately sourced from:
  * the current Tranco standard list (domains), and
  * public DNS resolver IPv4 addresses documented by their operators.

The existing benchmark is used only as a read-only exclusion set.  Deduplication
is performed using the existing records' ``ioc`` field, never their ``source``.
"""

import argparse
import csv
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = REPO_ROOT / "data" / "benchmark" / "benchmark_iocs_v2_backup.json"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "benchmark" / "benchmark_iocs_clean_additions_2026-09-22.json"
TRANCO_LIST_ID = "8P4GV"
TRANCO_LIST_URL = f"https://tranco-list.eu/list/{TRANCO_LIST_ID}/1000000"

# Official operator pages document these as public DNS resolver addresses.
# The base benchmark already contains 8.8.8.8, 1.1.1.1, and 9.9.9.9; those
# are intentionally not repeated here.
KNOWN_GOOD_IPS = (
    ("1.0.0.1", "cloudflare-public-dns", "https://developers.cloudflare.com/1.1.1.1/ip-addresses/"),
    ("1.1.1.2", "cloudflare-public-dns-malware-filter", "https://developers.cloudflare.com/1.1.1.1/ip-addresses/"),
    ("1.0.0.2", "cloudflare-public-dns-malware-filter", "https://developers.cloudflare.com/1.1.1.1/ip-addresses/"),
    ("1.1.1.3", "cloudflare-public-dns-family-filter", "https://developers.cloudflare.com/1.1.1.1/ip-addresses/"),
    ("1.0.0.3", "cloudflare-public-dns-family-filter", "https://developers.cloudflare.com/1.1.1.1/ip-addresses/"),
    ("8.8.4.4", "google-public-dns", "https://developers.google.com/speed/public-dns/docs/using"),
    ("149.112.112.112", "quad9-public-dns", "https://docs.quad9.net/services/"),
    ("9.9.9.10", "quad9-unfiltered", "https://docs.quad9.net/services/"),
    ("149.112.112.10", "quad9-unfiltered", "https://docs.quad9.net/services/"),
    ("9.9.9.11", "quad9-secure", "https://docs.quad9.net/services/"),
    ("149.112.112.11", "quad9-secure", "https://docs.quad9.net/services/"),
    ("9.9.9.12", "quad9-secure-with-threat-blocking", "https://docs.quad9.net/services/"),
    ("149.112.112.12", "quad9-secure-with-threat-blocking", "https://docs.quad9.net/services/"),
    ("208.67.222.222", "opendns-public-dns", "https://www.opendns.com/setupguide/"),
    ("208.67.220.220", "opendns-public-dns", "https://www.opendns.com/setupguide/"),
    ("208.67.222.123", "opendns-familyshield", "https://www.opendns.com/setupguide/"),
    ("208.67.220.123", "opendns-familyshield", "https://www.opendns.com/setupguide/"),
    ("94.140.14.14", "adguard-dns-default", "https://adguard-dns.io/kb/general/dns-providers/"),
    ("94.140.15.15", "adguard-dns-default", "https://adguard-dns.io/kb/general/dns-providers/"),
    ("94.140.14.15", "adguard-dns-family", "https://adguard-dns.io/kb/general/dns-providers/"),
    ("94.140.15.16", "adguard-dns-family", "https://adguard-dns.io/kb/general/dns-providers/"),
    ("185.228.168.9", "cleanbrowsing-security-filter", "https://cleanbrowsing.org/support/troubleshooting/using-traceroute-to-test-dns"),
    ("185.228.169.9", "cleanbrowsing-security-filter", "https://cleanbrowsing.org/support/troubleshooting/using-traceroute-to-test-dns"),
    ("185.228.168.168", "cleanbrowsing-family-filter", "https://cleanbrowsing.org/setup"),
    ("185.228.169.168", "cleanbrowsing-family-filter", "https://cleanbrowsing.org/setup"),
)


def load_json_records(path: Path):
    records = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError(f"expected a JSON list in {path}")
    return records


def is_domain(value: str) -> bool:
    if not value or value.startswith(".") or value.endswith("."):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return False
    return "." in value and all(part and len(part) <= 63 for part in value.split("."))


def fetch_new_tranco_domains(csv_path: Path, existing_iocs: set[str], count: int, now: str):
    selected = []
    scanned_rows = 0
    existing_overlap = 0
    seen_new = set()

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) < 2:
                continue
            try:
                rank = int(row[0].strip())
            except ValueError:
                continue
            domain = row[1].strip().lower().rstrip(".")
            scanned_rows += 1
            if not is_domain(domain):
                continue
            if domain in existing_iocs:
                existing_overlap += 1
                continue
            if domain in seen_new:
                continue
            seen_new.add(domain)
            selected.append(
                {
                    "ioc": domain,
                    "ioc_type": "domain",
                    "expected_verdict": "CLEAN",
                    "source": "tranco_top_sites",
                    "tags": ["top-site", f"tranco-list-{TRANCO_LIST_ID}", f"tranco-rank-{rank}"],
                    "first_seen": None,
                    "collected_at": now,
                    "source_url": TRANCO_LIST_URL,
                }
            )
            if len(selected) >= count:
                break

    if len(selected) < count:
        raise RuntimeError(
            f"Tranco provided only {len(selected)} new domains; needed {count} "
            f"after deduplicating the base benchmark"
        )
    return selected, scanned_rows, existing_overlap


def build_ip_records(existing_iocs: set[str], now: str):
    records = []
    existing_overlap = 0
    seen = set()
    for value, provider, source_url in KNOWN_GOOD_IPS:
        parsed = ipaddress.ip_address(value)
        if not parsed.is_global:
            raise ValueError(f"known-good IP is not public/global: {value}")
        if value in existing_iocs:
            existing_overlap += 1
            continue
        if value in seen:
            continue
        seen.add(value)
        records.append(
            {
                "ioc": value,
                "ioc_type": "ip",
                "expected_verdict": "CLEAN",
                "source": "manual_known_good",
                "tags": ["public-dns", provider],
                "first_seen": None,
                "collected_at": now,
                "source_url": source_url,
            }
        )
    return records, existing_overlap


def main():
    parser = argparse.ArgumentParser(description="Build standalone CLEAN IOC benchmark additions")
    parser.add_argument("--tranco-csv", type=Path, required=True, help="downloaded rank,domain Tranco CSV")
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE, help="read-only base benchmark JSON")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="new additions JSON output")
    parser.add_argument("--domain-count", type=int, default=225, help="new Tranco domains to add (default: 225)")
    args = parser.parse_args()

    base_records = load_json_records(args.base)
    existing_iocs = {record["ioc"] for record in base_records if isinstance(record, dict) and "ioc" in record}
    if len(existing_iocs) != len(base_records):
        raise ValueError("base benchmark contains duplicate or missing ioc fields")

    now = datetime.now(timezone.utc).isoformat()
    domains, scanned_rows, domain_overlap = fetch_new_tranco_domains(
        args.tranco_csv, existing_iocs, args.domain_count, now
    )
    ips, ip_overlap = build_ip_records(existing_iocs, now)
    records = domains + ips
    new_iocs = [record["ioc"] for record in records]
    if len(new_iocs) != len(set(new_iocs)):
        raise ValueError("generated additions contain duplicate ioc fields")
    if existing_iocs.intersection(new_iocs):
        raise ValueError("generated additions overlap the base benchmark")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"[dedup] base records={len(base_records)}, unique base ioc={len(existing_iocs)}")
    print(f"[dedup] Tranco rows scanned={scanned_rows}, base-ioc overlaps={domain_overlap}, new domains={len(domains)}")
    print(f"[dedup] known-good IP candidates={len(KNOWN_GOOD_IPS)}, base-ioc overlaps={ip_overlap}, new IPs={len(ips)}")
    print(f"[done] new CLEAN additions={len(records)} (domains={len(domains)}, IPs={len(ips)})")
    print(f"[done] wrote {args.output}")


if __name__ == "__main__":
    main()
