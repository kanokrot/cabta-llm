#!/usr/bin/env python3
"""Prepare a public-data proxy holdout without using target-feed results as labels.

This script reads already downloaded evidence only, except for optional DNS/TLS
observations used to derive public-IP and certificate candidates.  It never
writes to the IOC cache and never calls the target threat-intelligence feeds.

The output is deliberately called a proxy holdout: Tranco/Cloudflare popularity
does not prove that an indicator is clean, and a certificate observed at a
verified phishing host is an association, not a certificate blacklist label.
"""

from __future__ import annotations

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import ipaddress
import json
import random
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
GROUP_A = REPO_ROOT / "scripts" / "eval" / "eval_results_group_a_v2.jsonl"
THREATFOX = REPO_ROOT / "evidence_raw" / "threatfox" / "threatfox_export_2026-09-16.json"
URLHAUS = REPO_ROOT / "evidence_raw" / "urlhaus" / "urlhaus_export_2026-09-16.json"
PHISHTANK = REPO_ROOT / "evidence_raw" / "phishtank" / "verified_online.json"
CLOUDFLARE = REPO_ROOT / "evidence_raw" / "cloudflare" / "top_1000000_domains.csv"

TARGET_SOURCES = (
    "feodotracker", "tor_exit_nodes", "sslblacklist", "usom",
    "spamhaus", "c2_trackers",
)

# Shared hosting can make a host-level phishing label too broad.  Keep these
# out of the certificate derivation pool; exact URLs remain valid evidence.
SHARED_HOST_SUFFIXES = (
    "appspot.com", "bubbleapps.io", "blogspot.com", "cloudapp.azure.com",
    "firebaseapp.com", "github.io", "googleusercontent.com", "myshopify.com",
    "netlify.app", "onrender.com", "pages.dev", "web.app", "weebly.com",
    "wixsite.com", "wordpress.com", "vercel.app",
)

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def norm(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4 and ip.is_global
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    return bool(DOMAIN_RE.fullmatch(norm(value)))


def record_id(ioc_type: str, ioc: str, label: str) -> str:
    raw = f"{ioc_type}|{norm(ioc)}|{label}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:20]


def load_group_a() -> dict[str, set[str]]:
    result: dict[str, set[str]] = {"ip": set(), "domain": set(), "sha1": set()}
    with GROUP_A.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            ioc_type = norm(row.get("expected_ioc_type"))
            value = norm(row.get("ioc"))
            if ioc_type in result and value:
                result[ioc_type].add(value)
    return result


def load_threatfox() -> tuple[list[dict], set[str], set[str]]:
    data = json.loads(THREATFOX.read_text(encoding="utf-8")).get("data", [])
    ip_rows: dict[str, dict] = {}
    domain_rows: dict[str, dict] = {}
    for row in data:
        ioc_type = row.get("ioc_type")
        value = row.get("ioc", "")
        if ioc_type == "ip:port":
            host = value.rsplit(":", 1)[0].strip("[]") if ":" in value else value
            host = norm(host)
            if is_public_ipv4(host):
                current = ip_rows.get(host)
                if current is None or int(row.get("confidence_level") or 0) > int(current.get("confidence_level") or 0):
                    ip_rows[host] = row
        elif ioc_type == "domain":
            domain = norm(value)
            if is_domain(domain):
                current = domain_rows.get(domain)
                if current is None or int(row.get("confidence_level") or 0) > int(current.get("confidence_level") or 0):
                    domain_rows[domain] = row
    return list(ip_rows.values()) + list(domain_rows.values()), set(ip_rows), set(domain_rows)


def load_urlhaus_hosts() -> set[str]:
    data = json.loads(URLHAUS.read_text(encoding="utf-8")).get("urls", [])
    return {norm(row.get("host")) for row in data if norm(row.get("host"))}


def load_phishtank() -> tuple[list[dict], set[str]]:
    rows = json.loads(PHISHTANK.read_text(encoding="utf-8"))
    hosts: set[str] = set()
    usable: list[dict] = []
    for row in rows:
        if row.get("verified") != "yes" or row.get("online") != "yes":
            continue
        parsed = urlsplit(row.get("url", ""))
        host = norm(parsed.hostname)
        if not host or not is_domain(host):
            continue
        hosts.add(host)
        usable.append(row)
    return usable, hosts


def load_cloudflare() -> list[str]:
    with CLOUDFLARE.open(encoding="utf-8-sig", newline="") as handle:
        rows = csv.reader(handle)
        values = [norm(row[0]) for row in rows if row and norm(row[0]) != "domain"]
    return [value for value in values if is_domain(value)]


def shared_host(host: str) -> bool:
    return any(host == suffix or host.endswith("." + suffix) for suffix in SHARED_HOST_SUFFIXES)


def base_record(ioc: str, ioc_type: str, label: str, quality: str, provider: str, evidence_ref: str, rationale: str, collected_at: str) -> dict:
    return {
        "record_id": record_id(ioc_type, ioc, label),
        "ioc": ioc,
        "ioc_type": ioc_type,
        "expected_label": label,
        "label_quality": quality,
        "label_provenance": {
            "provider": provider,
            "evidence_ref": evidence_ref,
            "confirmation_date": collected_at[:10],
            "rationale": rationale,
        },
        "selection_provenance": {
            "candidate_source": provider,
            "collected_at": collected_at,
            "disjoint_from_group_a_eval": True,
        },
        "target_source_overlap": {source: None for source in TARGET_SOURCES},
        "target_source_overlap_status": "pending_source_calls",
    }


def tls_sha1(host: str, timeout: float = 2.0) -> str | None:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                certificate = tls.getpeercert(binary_form=True)
        return hashlib.sha1(certificate).hexdigest() if certificate else None
    except (OSError, ssl.SSLError, ValueError):
        return None


def collect_tls_sha1(candidates: list[tuple[str, dict]], limit: int, max_attempts: int) -> dict[str, tuple[str, dict]]:
    """Collect certificate hashes concurrently with a bounded attempt count."""
    selected: dict[str, tuple[str, dict]] = {}
    attempts = candidates[:max_attempts]
    with ThreadPoolExecutor(max_workers=24) as pool:
        futures = {pool.submit(tls_sha1, host): (host, row) for host, row in attempts}
        for future in as_completed(futures):
            host, row = futures[future]
            try:
                sha1 = future.result()
            except Exception:
                sha1 = None
            if sha1 and sha1 not in selected:
                selected[sha1] = (host, row)
                if len(selected) >= limit:
                    for pending in futures:
                        if not pending.done():
                            pending.cancel()
                    break
    return selected


def resolve_ipv4(host: str) -> set[str]:
    values: set[str] = set()
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        for info in infos:
            address = info[4][0]
            if is_public_ipv4(address):
                values.add(address)
    except OSError:
        pass
    return values


def build(args: argparse.Namespace) -> dict:
    collected_at = now_utc()
    group_a = load_group_a()
    _, threatfox_ips, threatfox_domains = load_threatfox()
    urlhaus_hosts = load_urlhaus_hosts()
    phishtank_rows, phishtank_hosts = load_phishtank()
    cloudflare_domains = load_cloudflare()

    records: list[dict] = []
    used: set[tuple[str, str]] = set()
    rng = random.Random(args.seed)

    # ThreatFox is used as external malicious evidence; target-feed results
    # are not consulted here.
    malicious_ip_rows = []
    raw_tf = json.loads(THREATFOX.read_text(encoding="utf-8")).get("data", [])
    seen_ips: set[str] = set()
    for row in sorted(raw_tf, key=lambda x: (int(x.get("confidence_level") or 0), x.get("first_seen", "")), reverse=True):
        if row.get("ioc_type") != "ip:port":
            continue
        value = row.get("ioc", "")
        ip = norm(value.rsplit(":", 1)[0].strip("[]")) if ":" in value else norm(value)
        if not is_public_ipv4(ip) or ip in seen_ips or ip in group_a["ip"]:
            continue
        seen_ips.add(ip)
        malicious_ip_rows.append((ip, row))
    for ip, row in malicious_ip_rows[: args.malicious_ip]:
        records.append(base_record(
            ip, "ip", "MALICIOUS", "external_evidence", "ThreatFox",
            f"local:{THREATFOX.name}#id={row.get('id')}",
            f"ThreatFox {row.get('threat_type', 'IOC')} confidence={row.get('confidence_level')}; reporter={row.get('reporter')}",
            collected_at,
        ))
        used.add(("ip", ip))

    # PhishTank provides independently verified phishing evidence for domains.
    phish_candidates = []
    seen_hosts: set[str] = set()
    for row in sorted(phishtank_rows, key=lambda x: x.get("verification_time", ""), reverse=True):
        host = norm(urlsplit(row.get("url", "")).hostname)
        if not host or host in seen_hosts or host in group_a["domain"]:
            continue
        seen_hosts.add(host)
        phish_candidates.append((host, row))
    rng.shuffle(phish_candidates)
    for host, row in phish_candidates[: args.malicious_domain]:
        records.append(base_record(
            host, "domain", "MALICIOUS", "external_evidence", "PhishTank",
            row.get("phish_detail_url") or f"local:{PHISHTANK.name}#phish_id={row.get('phish_id')}",
            "Host served a PhishTank record verified by the community and online at source collection time",
            collected_at,
        ))
        used.add(("domain", host))

    malicious_external = set(group_a["domain"]) | threatfox_domains | urlhaus_hosts | phishtank_hosts
    clean_domain_candidates = [
        domain for domain in cloudflare_domains
        if domain not in malicious_external and ("domain", domain) not in used
    ]
    rng.shuffle(clean_domain_candidates)

    # Keep a larger candidate pool for DNS/TLS derivation, but reserve the
    # first selected domains for the explicit clean-domain stratum.
    clean_domain_rows = clean_domain_candidates[: args.clean_domain]
    for domain in clean_domain_rows:
        records.append(base_record(
            domain, "domain", "CLEAN", "proxy", "Cloudflare Radar ranking",
            f"local:{CLOUDFLARE.name}",
            "Popular domain in the dated Cloudflare ranking; popularity is a clean proxy, not absolute ground truth",
            collected_at,
        ))
        used.add(("domain", domain))

    if args.network:
        # Use additional popular domains to derive public IP proxy records.
        clean_ip_candidates: list[tuple[str, str]] = []
        seen_ip: set[str] = set(group_a["ip"]) | threatfox_ips | {x for x in urlhaus_hosts if is_public_ipv4(x)}
        for domain in clean_domain_candidates[args.clean_domain:]:
            for ip in sorted(resolve_ipv4(domain)):
                if ip in seen_ip:
                    continue
                seen_ip.add(ip)
                clean_ip_candidates.append((ip, domain))
                if len(clean_ip_candidates) >= args.clean_ip:
                    break
            if len(clean_ip_candidates) >= args.clean_ip:
                break
        for ip, domain in clean_ip_candidates:
            records.append(base_record(
                ip, "ip", "CLEAN", "proxy", "Cloudflare Radar + public DNS",
                f"local:{CLOUDFLARE.name}#domain={domain}",
                f"Public IPv4 observed from a Cloudflare-ranked domain ({domain}); this is a clean proxy",
                collected_at,
            ))
            used.add(("ip", ip))

        # Derive malicious certificate associations from current TLS handshakes
        # to verified phishing hosts, avoiding common shared-hosting suffixes.
        cert_candidates = [(host, row) for host, row in phish_candidates if not shared_host(host)]
        cert_rows = collect_tls_sha1(cert_candidates, args.malicious_sha1, args.max_tls_attempts)
        for sha1, (host, row) in list(cert_rows.items())[: args.malicious_sha1]:
            if ("sha1", sha1) in used:
                continue
            records.append(base_record(
                sha1, "sha1", "MALICIOUS", "external_association", "PhishTank + observed TLS certificate",
                row.get("phish_detail_url") or f"local:{PHISHTANK.name}#phish_id={row.get('phish_id')}",
                f"SHA1 of certificate observed at verified phishing host {host}; not sourced from SSLBL",
                collected_at,
            ))
            used.add(("sha1", sha1))

        clean_cert_candidates = [(domain, {}) for domain in clean_domain_candidates[args.clean_domain:] if not shared_host(domain)]
        clean_cert_rows = collect_tls_sha1(clean_cert_candidates, args.clean_sha1, args.max_tls_attempts)
        for sha1, (domain, _) in list(clean_cert_rows.items())[: args.clean_sha1]:
            if ("sha1", sha1) in used:
                continue
            records.append(base_record(
                sha1, "sha1", "CLEAN", "proxy", "Cloudflare Radar + observed TLS certificate",
                f"local:{CLOUDFLARE.name}#domain={domain}",
                f"Certificate observed from a Cloudflare-ranked domain ({domain}); certificate presence is not proof of benignness",
                collected_at,
            ))
            used.add(("sha1", sha1))

    counts = {
        label: {ioc_type: sum(r["expected_label"] == label and r["ioc_type"] == ioc_type for r in records) for ioc_type in ("ip", "domain", "sha1")}
        for label in ("MALICIOUS", "CLEAN")
    }
    target_counts = {"MALICIOUS": args.malicious_ip + args.malicious_domain + args.malicious_sha1, "CLEAN": args.clean_ip + args.clean_domain + args.clean_sha1}
    ready = counts == {
        "MALICIOUS": {"ip": args.malicious_ip, "domain": args.malicious_domain, "sha1": args.malicious_sha1},
        "CLEAN": {"ip": args.clean_ip, "domain": args.clean_domain, "sha1": args.clean_sha1},
    }
    return {
        "generated_at_utc": collected_at,
        "status": "ready_for_overlap_checks" if ready else "partial_not_ready_for_weight_fit",
        "label_policy": {
            "target_source_results_are_not_labels": True,
            "clean_label_quality": "proxy",
            "independent_ground_truth_complete": False,
        },
        "design": {
            "total_records_target": sum(target_counts.values()),
            "label_balance_target": target_counts,
            "actual_records": len(records),
            "actual_counts": counts,
            "seed": args.seed,
        },
        "source_snapshots": {
            "threatfox": str(THREATFOX.relative_to(REPO_ROOT)),
            "urlhaus": str(URLHAUS.relative_to(REPO_ROOT)),
            "phishtank": str(PHISHTANK.relative_to(REPO_ROOT)),
            "cloudflare": str(CLOUDFLARE.relative_to(REPO_ROOT)),
        },
        "records": records,
        "limitations": [
            "CLEAN records derived from public popularity/DNS/TLS observations are proxy labels, not absolute clean ground truth.",
            "PhishTank-host certificate associations require source-specific review because shared certificates may serve multiple sites.",
            "SSLBL, FeodoTracker, Tor, USOM, Spamhaus, and C2 overlap is still pending and must be collected after this manifest is frozen.",
            "A complete independent holdout requires source-specific positive coverage and must remain exploratory until adequacy is demonstrated.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260916)
    parser.add_argument("--network", action="store_true", help="derive public IPs and TLS certificate hashes via DNS/TLS")
    parser.add_argument("--max-tls-attempts", type=int, default=300)
    parser.add_argument("--malicious-ip", type=int, default=60)
    parser.add_argument("--clean-ip", type=int, default=60)
    parser.add_argument("--malicious-domain", type=int, default=30)
    parser.add_argument("--clean-domain", type=int, default=30)
    parser.add_argument("--malicious-sha1", type=int, default=30)
    parser.add_argument("--clean-sha1", type=int, default=30)
    args = parser.parse_args()
    artifact = build(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": artifact["status"],
        "actual_records": artifact["design"]["actual_records"],
        "actual_counts": artifact["design"]["actual_counts"],
        "output": str(args.output),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
