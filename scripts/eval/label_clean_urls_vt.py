#!/usr/bin/env python3
"""Label frozen clean URL candidates with the pre-registered VirusTotal rule."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from scripts.eval.build_independent_url_holdout import (  # noqa: E402
    DEFAULT_SEED, USER_AGENT, git_metadata, read_rows, sha256_bytes, write_json,
)
from src.utils.api_key_validator import get_valid_key  # noqa: E402
from src.utils.config import load_config  # noqa: E402


VT_URLS_ENDPOINT = "https://www.virustotal.com/api/v3/urls/"
EXCLUDED_ENGINES = {"MalwareURL", "Hunt.io Intelligence", "Criminal IP"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def label_report(payload: Any, http_status: int) -> tuple[str, int | None, str | None]:
    if http_status == 404:
        return "NO_REPORT", None, "http_404"
    if http_status != 200:
        return "SOURCE_ERROR", None, f"http_{http_status}"
    if not isinstance(payload, dict):
        return "SOURCE_ERROR", None, "invalid_json_shape"
    data = payload.get("data") or {}
    attributes = data.get("attributes") if isinstance(data, dict) else None
    results = attributes.get("last_analysis_results") if isinstance(attributes, dict) else None
    if not isinstance(results, dict) or not results:
        return "NO_REPORT", None, "missing_last_analysis_results"
    malicious_count = 0
    for key, value in results.items():
        if not isinstance(value, dict):
            continue
        name = value.get("engine_name") or key
        if name not in EXCLUDED_ENGINES and value.get("category") == "malicious":
            malicious_count += 1
    if malicious_count == 0:
        return "CLEAN", malicious_count, None
    if malicious_count <= 2:
        return "AMBIGUOUS", malicious_count, None
    return "MALICIOUS", malicious_count, None


def _request_report(url: str, api_key: str, timeout: float) -> tuple[bytes, int]:
    endpoint = VT_URLS_ENDPOINT + url_id(url)
    request = Request(endpoint, headers={"x-apikey": api_key, "Accept": "application/json",
                                        "User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.read(), int(response.status)
    except HTTPError as exc:
        return exc.read(), int(exc.code)
    except URLError as exc:
        raise RuntimeError(f"VirusTotal request failed ({type(exc.reason).__name__})") from exc


def _load_api_key(config_path: str | None = None) -> str | None:
    config = load_config(config_path)
    return get_valid_key(config.get("api_keys", {}), "virustotal")


def label_candidates(input_path: Path, out_dir: Path, *, target: int = 200,
                     delay: float = 16.0, seed: int = DEFAULT_SEED,
                     timeout: float = 30, config_path: str | None = None,
                     api_key: str | None = None) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    candidates = read_rows(input_path)  # Preserve the seeded order from the builder.
    key = api_key if api_key is not None else _load_api_key(config_path)
    if not key:
        raise RuntimeError("VirusTotal API key is not configured; key value was not printed")
    raw_dir = out_dir / "virustotal_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    labels: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    counts = {"input_candidates": len(candidates), "reports_fetched": 0, "resumed": 0,
              "CLEAN": 0, "AMBIGUOUS": 0, "MALICIOUS": 0, "NO_REPORT": 0,
              "SOURCE_ERROR": 0, "clean_selected": 0, "clean_over_target": 0}
    report_metadata: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        ioc = candidate.get("ioc")
        if not isinstance(ioc, str):
            dropped.append({"row_index": index, "reason": "missing_ioc"})
            continue
        token = hashlib.sha256(ioc.encode("utf-8")).hexdigest()
        raw_path = raw_dir / f"{token}.json"
        metadata_path = raw_dir / f"{token}.metadata.json"
        resumed = raw_path.exists()
        fetched_at = None
        if resumed:
            raw_bytes = raw_path.read_bytes()
            try:
                payload = json.loads(raw_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                label, malicious_count, reason = "SOURCE_ERROR", None, "cached_raw_invalid_json"
                status_code = None
            else:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {}
                status_code = metadata.get("http_status")
                fetched_at = metadata.get("fetched_at_utc")
                if status_code is None:
                    status_code = 404 if (isinstance(payload, dict) and
                        (payload.get("error", {}).get("code") == "NotFoundError" if isinstance(payload.get("error"), dict) else False)) else 200
                label, malicious_count, reason = label_report(payload, int(status_code))
            counts["resumed"] += 1
            if metadata_path.exists():
                report_metadata.append(json.loads(metadata_path.read_text(encoding="utf-8")))
        else:
            fetched_at = utc_now()
            try:
                raw_bytes, status_code = _request_report(ioc, key, timeout)
            except Exception as exc:
                dropped.append({"ioc": ioc, "reason": "request_error", "error": type(exc).__name__})
                counts["SOURCE_ERROR"] += 1
                continue
            # Persist the raw response bytes before parsing or labeling.
            raw_path.write_bytes(raw_bytes)
            metadata = {"ioc_sha256": token, "fetched_at_utc": fetched_at,
                        "request_url": VT_URLS_ENDPOINT + url_id(ioc),
                        "http_status": status_code, "sha256": sha256_bytes(raw_bytes),
                        "byte_count": len(raw_bytes)}
            write_json(metadata_path, metadata)
            counts["reports_fetched"] += 1
            try:
                payload = json.loads(raw_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                label, malicious_count, reason = "SOURCE_ERROR", None, "invalid_json_response"
            else:
                label, malicious_count, reason = label_report(payload, status_code)
            report_metadata.append(metadata)
            if delay and index + 1 < len(candidates):
                time.sleep(delay)
        counts[label] += 1
        common = {"ioc": ioc, "ioc_type": "url", "source": candidate.get("source", "Tranco"),
                  "sampling_source": candidate.get("sampling_source", "tranco"),
                  "collected_at": candidate.get("collected_at", fetched_at or utc_now()),
                  "round": candidate.get("round", "tranco"), "vt_label": label,
                  "malicious_engine_count": malicious_count, "vt_raw_file": str(raw_path),
                  "vt_raw_sha256": sha256_bytes(raw_path.read_bytes()), "resumed": resumed}
        if label == "CLEAN":
            common.update({"expected_verdict": "CLEAN", "label_source": "virustotal_3tier"})
            if counts["clean_selected"] < target:
                labels.append(common)
                counts["clean_selected"] += 1
            else:
                counts["clean_over_target"] += 1
                dropped.append({"ioc": ioc, "reason": "clean_over_target"})
        else:
            dropped.append({"ioc": ioc, "reason": reason or label.lower(), "vt_label": label,
                            "malicious_engine_count": malicious_count})
    output_path = out_dir / "clean_labeled.json"
    write_json(output_path, labels)
    manifest_path = out_dir / "label_clean_urls_vt_manifest.json"
    manifest = {"script": Path(__file__).name, "input_file": str(input_path), "seed": seed,
                "target": target, "delay_seconds": delay, "counts_by_stage": counts,
                "reports": report_metadata, "dropped_items": dropped,
                "output_file": str(output_path), **git_metadata()}
    write_json(manifest_path, manifest)
    return output_path, manifest_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-file", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--target", type=int, default=200)
    parser.add_argument("--delay", type=float, default=16.0)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--config", help="project config path; otherwise project load_config search order is used")
    args = parser.parse_args()
    try:
        output, manifest = label_candidates(args.input_file, args.out_dir,
                                            target=args.target, delay=args.delay,
                                            seed=args.seed, timeout=args.timeout,
                                            config_path=args.config)
    except Exception as exc:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        write_json(args.out_dir / "label_clean_urls_vt_manifest.json", {
            "script": Path(__file__).name, "input_file": str(args.input_file),
            "seed": args.seed, "counts_by_stage": {},
            "dropped_items": [{"reason": "run_failed", "error": type(exc).__name__}],
            **git_metadata(),
        })
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"Wrote {output} and {manifest}")


if __name__ == "__main__":
    main()
