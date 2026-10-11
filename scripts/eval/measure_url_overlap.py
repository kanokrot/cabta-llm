#!/usr/bin/env python3
"""Freeze C2 feeds and measure URL overlap without invoking system scoring."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from scripts.eval.build_independent_url_holdout import (  # noqa: E402
    DEFAULT_SEED, USER_AGENT, git_metadata, read_rows, sha256_bytes, write_json,
)
from src.utils.api_key_validator import get_valid_key  # noqa: E402
from src.utils.config import load_config  # noqa: E402


THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
C2_FEEDS = {
    "montysecurity_combined": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/combined.csv",
    "drb_ra_30day": "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
    "jmousqueton": "https://raw.githubusercontent.com/jmousqueton/C2-Tracker/main/c2-tracker.csv",
    "stamparm_maltrail": "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/c2.txt",
    "c2_all_ips": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/ips/all.txt",
    "c2_cobalt_strike": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Cobalt%20Strike.csv",
    "c2_metasploit": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Metasploit.csv",
    "c2_sliver": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Sliver.csv",
    "c2_brute_ratel": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Brute%20Ratel%20C4.csv",
    "c2_havoc": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Havoc.csv",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def request_raw(url: str, payload: dict[str, Any] | None = None,
                headers: dict[str, str] | None = None, timeout: float = 30) -> tuple[bytes, int]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = {"User-Agent": USER_AGENT}
    request_headers.update(headers or {})
    if data is not None:
        request_headers.setdefault("Content-Type", "application/json")
    request = Request(url, data=data, headers=request_headers, method="POST" if data is not None else "GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.read(), int(response.status)
    except HTTPError as exc:
        return exc.read(), int(exc.code)
    except URLError as exc:
        raise RuntimeError(f"request failed ({type(exc.reason).__name__})") from exc


def save_response(path: Path, body: bytes, url: str, fetched_at: str, status_code: int,
                  request_kind: str) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    metadata = {"fetched_at_utc": fetched_at, "source_url": url,
                "http_status": status_code, "request_kind": request_kind,
                "sha256": sha256_bytes(body), "byte_count": len(body)}
    write_json(path.with_suffix(path.suffix + ".metadata.json"), metadata)
    return metadata


def threatfox_status(body: bytes, http_status: int) -> tuple[str, list[dict[str, Any]]]:
    if http_status != 200:
        return "error", []
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "error", []
    state = payload.get("query_status")
    if state == "no_result":
        return "miss", []
    if state != "ok":
        return "error", []
    data = payload.get("data") or []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return "error", []
    records = [row for row in data if isinstance(row, dict)]
    return ("hit", records) if records else ("error", [])


def _host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def load_threatfox_key(config_path: str | None = None) -> str | None:
    config = load_config(config_path)
    keys = config.get("api_keys", {})
    return get_valid_key(keys, "threatfox") or get_valid_key(keys, "abusech")


def _lookup_threatfox(value: str, label: str, key: str, raw_dir: Path,
                      delay: float, retries: int, backoff: float,
                      timeout: float) -> dict[str, Any]:
    request_payload = {"query": "search_ioc", "search_term": value}
    headers = {"Auth-Key": key}
    attempts: list[dict[str, Any]] = []
    for attempt in range(retries + 1):
        fetched_at = utc_now()
        attempt_path = raw_dir / f"{label}_attempt_{attempt + 1}.json"
        try:
            body, status_code = request_raw(THREATFOX_API, request_payload, headers, timeout)
            meta = save_response(attempt_path, body, THREATFOX_API, fetched_at, status_code, label)
            state, records = threatfox_status(body, status_code)
            attempts.append({"status": state, "http_status": status_code, "raw": str(attempt_path), **meta})
            retryable = state == "error" and status_code not in {401, 403}
            if not retryable or attempt >= retries:
                return {"status": state, "records": records, "attempts": attempts}
            time.sleep(backoff * (2 ** attempt))
        except Exception as exc:
            attempts.append({"status": "error", "error": type(exc).__name__, "raw": None,
                             "fetched_at_utc": fetched_at})
            if attempt >= retries:
                return {"status": "error", "records": [], "attempts": attempts}
            time.sleep(backoff * (2 ** attempt))
        if delay:
            time.sleep(delay)
    return {"status": "error", "records": [], "attempts": attempts}


def _freeze_feeds(out_dir: Path, timeout: float) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    frozen: dict[str, dict[str, Any]] = {}
    failures = []
    for name, url in C2_FEEDS.items():
        fetched_at = utc_now()
        raw_path = out_dir / "c2_feeds" / f"{name}.raw"
        try:
            body, status = request_raw(url, timeout=timeout)
            meta = save_response(raw_path, body, url, fetched_at, status, "c2_feed")
            state = "ok" if status == 200 else "error"
            frozen[name] = {"status": state, "http_status": status, "path": str(raw_path),
                            "text": body.decode("utf-8", errors="replace"), **meta}
            if state != "ok":
                failures.append({"source": name, "reason": f"http_{status}"})
        except Exception as exc:
            frozen[name] = {"status": "error", "path": str(raw_path),
                            "error": type(exc).__name__, "fetched_at_utc": fetched_at}
            failures.append({"source": name, "reason": type(exc).__name__})
    return frozen, failures


def _c2_flags(url: str, frozen: dict[str, dict[str, Any]]) -> dict[str, Any]:
    host = _host(url)
    exact_sources, host_sources, failed = [], [], []
    for name, feed in frozen.items():
        if feed.get("status") != "ok":
            failed.append(name)
            continue
        text = feed.get("text", "")
        # Match the implementation at threat_intel.py:855: case-insensitive literal substring.
        if url.lower() in text.lower():
            exact_sources.append(name)
        if host and host.lower() in text.lower():
            host_sources.append(name)
    return {"exact_url_match": bool(exact_sources), "exact_url_sources": exact_sources,
            "host_level_match": bool(host_sources), "host_level_sources": host_sources,
            "status": "error" if failed and len(failed) == len(frozen) else "partial" if failed else "ok",
            "failed_feeds": failed,
            "matcher": "case-insensitive literal substring over raw frozen feed text"}


def measure(input_path: Path, out_dir: Path, *, delay: float, retries: int,
            backoff: float, timeout: float, seed: int,
            config_path: str | None = None, key: str | None = None) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = read_rows(input_path)
    auth_key = key if key is not None else load_threatfox_key(config_path)
    if not auth_key:
        raise RuntimeError("ThreatFox API key is not configured in the project config; value was not printed")
    frozen, feed_failures = _freeze_feeds(out_dir, timeout)
    output_rows = []
    dropped = list(feed_failures)
    counts = {"input_rows": len(rows), "malicious": 0, "clean": 0,
              "threatfox_url_hit": 0, "threatfox_host_hit": 0, "source_errors": 0}
    raw_dir = out_dir / "threatfox_raw"
    for index, row in enumerate(rows):
        ioc = row.get("ioc")
        if not isinstance(ioc, str):
            dropped.append({"row_index": index, "reason": "missing_ioc"})
            continue
        row_id = hashlib.sha256(ioc.encode("utf-8")).hexdigest()[:16]
        host = _host(ioc)
        exact_result = _lookup_threatfox(ioc, f"{row_id}_url", auth_key, raw_dir,
                                         delay, retries, backoff, timeout)
        if delay:
            time.sleep(delay)
        host_result = (_lookup_threatfox(host, f"{row_id}_host", auth_key, raw_dir,
                                         delay, retries, backoff, timeout) if host else
                       {"status": "error", "records": [], "attempts": []})
        if delay:
            time.sleep(delay)
        exact_records = exact_result["records"]
        host_records = host_result["records"]
        exact_hit = exact_result["status"] == "hit" and any(record.get("ioc") == ioc for record in exact_records)
        host_hit = host_result["status"] == "hit" and bool(host_records)
        c2 = _c2_flags(ioc, frozen)
        status_error = exact_result["status"] == "error" or host_result["status"] == "error" or c2["status"] != "ok"
        if status_error:
            counts["source_errors"] += 1
            dropped.append({"ioc": ioc, "reason": "one_or_more_source_errors"})
        verdict = str(row.get("expected_verdict", "")).upper()
        if verdict == "MALICIOUS":
            counts["malicious"] += 1
        elif verdict == "CLEAN":
            counts["clean"] += 1
        counts["threatfox_url_hit"] += int(exact_hit)
        counts["threatfox_host_hit"] += int(host_hit)
        output_rows.append({
            "ioc": ioc,
            "round": row.get("round", row.get("sampling_source", row.get("source"))),
            "expected_verdict": row.get("expected_verdict"),
            "sampling_source": row.get("sampling_source", row.get("source")),
            "c2": c2,
            "threatfox": {
                "exact_url": {"status": exact_result["status"], "hit": exact_hit,
                              "raw_responses": exact_result["attempts"]},
                "host": {"query": host, "status": host_result["status"], "hit": host_hit,
                         "raw_responses": host_result["attempts"]},
            },
        })
    flags_path = out_dir / "url_overlap_flags.json"
    write_json(flags_path, output_rows)
    # Totals by round and expected label are saved to make the audit denominator explicit.
    summary: dict[str, Any] = {}
    for row in output_rows:
        key_round = str(row["round"])
        label = str(row["expected_verdict"])
        bucket = summary.setdefault(key_round, {}).setdefault(label, {"rows": 0, "c2_exact": 0,
            "c2_host": 0, "threatfox_exact": 0, "threatfox_host": 0})
        bucket["rows"] += 1
        bucket["c2_exact"] += int(row["c2"]["exact_url_match"])
        bucket["c2_host"] += int(row["c2"]["host_level_match"])
        bucket["threatfox_exact"] += int(row["threatfox"]["exact_url"]["hit"])
        bucket["threatfox_host"] += int(row["threatfox"]["host"]["hit"])
    summary_path = out_dir / "url_overlap_summary.csv"
    with summary_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("round", "expected_verdict", "rows", "c2_exact", "c2_host",
                         "threatfox_exact", "threatfox_host"))
        for round_name in sorted(summary):
            for expected_verdict in sorted(summary[round_name]):
                bucket = summary[round_name][expected_verdict]
                writer.writerow((round_name, expected_verdict, bucket["rows"],
                                 bucket["c2_exact"], bucket["c2_host"],
                                 bucket["threatfox_exact"], bucket["threatfox_host"]))
    manifest_path = out_dir / "measure_url_overlap_manifest.json"
    manifest = {"script": Path(__file__).name, "input_file": str(input_path), "seed": seed,
                "counts_by_stage": counts, "overlap_by_round_and_label": summary,
                "overlap_table_csv": str(summary_path),
                "c2_feed_files": {name: {k: v for k, v in item.items() if k != "text"}
                                  for name, item in frozen.items()},
                "dropped_items": dropped,
                "threatfox_match_rule": "search_ioc using original URL and its hostname; response errors are not misses",
                **git_metadata()}
    write_json(manifest_path, manifest)
    return flags_path, manifest_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-file", type=Path, required=True, help="frozen dataset JSON")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=2.0,
                        help="seconds between ThreatFox requests (default 2; 16 seconds is for VirusTotal/eval only)")
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--backoff-seconds", type=float, default=2.0)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--config", help="project config path; otherwise project load_config search order is used")
    args = parser.parse_args()
    try:
        flags, manifest = measure(args.input_file, args.out_dir, delay=args.delay,
                                  retries=args.retries, backoff=args.backoff_seconds,
                                  timeout=args.timeout, seed=args.seed,
                                  config_path=args.config)
    except Exception as exc:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        write_json(args.out_dir / "measure_url_overlap_manifest.json", {
            "script": Path(__file__).name, "seed": args.seed,
            "counts_by_stage": {}, "dropped_items": [{"reason": "run_failed", "error": type(exc).__name__}],
            **git_metadata(),
        })
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"Wrote {flags} and {manifest}")


if __name__ == "__main__":
    main()
