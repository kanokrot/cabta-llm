#!/usr/bin/env python3
"""Cross-check domain false negatives against independent threat feeds.

The CIRCL/MISP value in the benchmark is retained as label provenance, not
counted as independent confirmation.  ThreatFox and URLhaus are queried by
IOC/host, while the OpenPhish community feed is downloaded once and matched
by exact hostname.  Results are written to a new JSONL artifact only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
import certifi

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.utils.config import load_config


DEFAULT_INPUT = REPO_ROOT / "scripts" / "eval" / "output" / "domain_false_negatives_weightsum_2026-09-22.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "scripts" / "eval" / "output" / "domain_false_negative_cross_check_2026-09-22.jsonl"
OPENPHISH_FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"


def load_rows(path: Path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def hostname_from_url(value: str):
    try:
        return (urlsplit(value.strip()).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


async def fetch_openphish(session):
    async with session.get(OPENPHISH_FEED_URL) as response:
        response.raise_for_status()
        text = await response.text()
    hosts = set()
    for line in text.splitlines():
        host = hostname_from_url(line)
        if host:
            hosts.add(host)
    return {"feed_url": OPENPHISH_FEED_URL, "line_count": len(text.splitlines()), "host_count": len(hosts), "hosts": hosts}


async def query_threatfox(session, domain, api_key):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Auth-Key"] = api_key
    payload = {"query": "search_ioc", "search_term": domain, "exact_match": True}
    try:
        async with session.post(THREATFOX_API_URL, json=payload, headers=headers) as response:
            body = await response.json(content_type=None)
            if response.status != 200:
                return {"status": "error", "http_status": response.status, "body": body}
            raw_data = body.get("data") or []
            if not isinstance(raw_data, list):
                raw_data = []
            matches = [
                item for item in raw_data
                if isinstance(item, dict)
                and str(item.get("ioc", "")).strip().lower().rstrip(".") == domain
            ]
            return {
                "status": body.get("query_status"),
                "found": bool(matches),
                "matches": matches,
            }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


async def query_urlhaus_host(session, domain, api_key):
    headers = {"Auth-Key": api_key} if api_key else {}
    try:
        async with session.post(URLHAUS_HOST_URL, data={"host": domain}, headers=headers) as response:
            body = await response.json(content_type=None)
            if response.status != 200:
                return {"status": "error", "http_status": response.status, "body": body}
            found = body.get("query_status") == "ok" and int(body.get("url_count", 0) or 0) > 0
            return {
                "status": body.get("query_status"),
                "found": found,
                "url_count": body.get("url_count", 0),
                "first_seen": body.get("firstseen"),
                "blacklists": body.get("blacklists", {}),
            }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


async def main_async(args):
    rows = load_rows(args.input)
    config = load_config()
    api_keys = config.get("api_keys", {})
    abuse_key = api_keys.get("threatfox") or api_keys.get("abusech") or ""
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    connector = aiohttp.TCPConnector(ssl=ssl_context, limit=args.concurrency)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        openphish = await fetch_openphish(session)
        semaphore = asyncio.Semaphore(args.concurrency)

        async def check(row):
            domain = row["ioc"].lower().rstrip(".")
            async with semaphore:
                threatfox, urlhaus = await asyncio.gather(
                    query_threatfox(session, domain, abuse_key),
                    query_urlhaus_host(session, domain, abuse_key),
                )
            openphish_found = domain in openphish["hosts"]
            independent_sources = []
            if threatfox.get("found"):
                independent_sources.append("threatfox")
            if urlhaus.get("found"):
                independent_sources.append("urlhaus")
            if openphish_found:
                independent_sources.append("openphish")
            return {
                "ioc": row["ioc"],
                "label_source": row.get("runtime_source"),
                "benchmark_tags": row.get("benchmark_tags", []),
                "circl_label_evidence": row.get("runtime_source") == "circl_misp_feed_osint",
                "threatfox": threatfox,
                "urlhaus": urlhaus,
                "openphish": {"found": openphish_found, "feed_url": openphish["feed_url"]},
                "independent_evidence_sources": independent_sources,
            }

        results = await asyncio.gather(*(check(row) for row in rows))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for result in results:
            handle.write(json.dumps(result, ensure_ascii=False) + "\n")

    counts = {
        "rows": len(results),
        "circl_label_evidence": sum(r["circl_label_evidence"] for r in results),
        "threatfox_found": sum(r["threatfox"].get("found", False) for r in results),
        "urlhaus_found": sum(r["urlhaus"].get("found", False) for r in results),
        "openphish_found": sum(r["openphish"].get("found", False) for r in results),
        "any_independent_evidence": sum(bool(r["independent_evidence_sources"]) for r in results),
    }
    print(json.dumps(counts, ensure_ascii=False))
    print(f"output={args.output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
