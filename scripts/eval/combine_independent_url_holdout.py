#!/usr/bin/env python3
"""Combine the two frozen malicious rounds and VT-labeled clean URLs."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from scripts.eval.build_independent_url_holdout import DEFAULT_SEED, write_json  # noqa: E402


INPUT_ORDER = ("openphish", "phishtank", "clean")
INPUT_NAMES = {
    "openphish": "malicious_openphish.json",
    "phishtank": "malicious_phishtank.json",
    "clean": "clean_labeled.json",
}
FORBIDDEN_LABELS = {"PENDING", "AMBIGUOUS", "NO_REPORT", "SOURCE_ERROR"}
REQUIRED_FIELDS = (
    "ioc", "ioc_type", "expected_verdict", "source", "collected_at",
    "sampling_source", "label_source", "round",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_metadata() -> dict[str, Any]:
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
                                capture_output=True, text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT,
                                    capture_output=True, text=True, check=True).stdout.strip())
        return {"script_git_commit": commit, "script_git_dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"script_git_commit": None, "script_git_dirty": None}


def load_rows(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"expected a JSON array of objects: {path}")
    return value


def combine(inputs: dict[str, Path], out_dir: Path) -> tuple[Path, Path]:
    if set(inputs) != set(INPUT_ORDER):
        raise ValueError(f"inputs must be exactly {', '.join(INPUT_ORDER)}")
    rows_by_file: dict[str, list[dict[str, Any]]] = {}
    hashes: dict[str, str] = {}
    dropped: list[dict[str, Any]] = []
    for name in INPUT_ORDER:
        path = inputs[name]
        if not path.is_file():
            raise FileNotFoundError(f"missing {name} input: {path}")
        rows_by_file[name] = load_rows(path)
        hashes[name] = sha256_file(path)

    combined: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    per_file: dict[str, dict[str, Any]] = {}
    for name in INPUT_ORDER:
        label_counts: Counter[str] = Counter()
        round_counts: Counter[str] = Counter()
        for index, row in enumerate(rows_by_file[name]):
            ioc = row.get("ioc")
            label = str(row.get("expected_verdict") or "").upper()
            label_counts[label or "MISSING"] += 1
            round_counts[str(row.get("round") or "MISSING")] += 1
            missing = [field for field in REQUIRED_FIELDS if field not in row or row[field] is None]
            if not isinstance(ioc, str) or not ioc:
                missing.append("ioc(nonempty string)")
            if missing:
                dropped.append({"input": name, "row_index": index,
                                "ioc": ioc if isinstance(ioc, str) else None,
                                "reason": "missing_required_fields", "fields": missing})
                continue
            if label in FORBIDDEN_LABELS or label not in {"MALICIOUS", "CLEAN"}:
                dropped.append({"input": name, "row_index": index, "ioc": ioc,
                                "reason": "invalid_or_unfinalized_label", "label": label or None})
                continue
            vt_label = str(row.get("vt_label") or "").upper()
            if vt_label in FORBIDDEN_LABELS or (vt_label and vt_label != label):
                dropped.append({"input": name, "row_index": index, "ioc": ioc,
                                "reason": "invalid_or_conflicting_vt_label",
                                "vt_label": vt_label})
                continue
            wanted = "CLEAN" if name == "clean" else "MALICIOUS"
            if label != wanted:
                dropped.append({"input": name, "row_index": index, "ioc": ioc,
                                "reason": "label_source_mismatch", "expected": wanted,
                                "actual": label})
                continue
            if name == "clean" and row.get("label_source") != "virustotal_3tier":
                dropped.append({"input": name, "row_index": index, "ioc": ioc,
                                "reason": "clean_label_source_mismatch",
                                "actual": row.get("label_source")})
                continue
            if ioc in seen:
                dropped.append({"input": name, "row_index": index, "ioc": ioc,
                                "reason": "duplicate_ioc", "first_input": seen[ioc]})
                continue
            seen[ioc] = name
            combined.append(dict(row))
        per_file[name] = {
            "path": str(inputs[name]), "input_rows": len(rows_by_file[name]),
            "sha256": hashes[name], "round_counts": dict(round_counts),
            "label_counts": dict(label_counts),
        }

    if dropped:
        reasons = Counter(item["reason"] for item in dropped)
        raise ValueError(f"refusing combined output; invalid rows: {dict(reasons)}")

    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / "combined_holdout.json"
    # Ensure stable UTF-8 output while keeping each IOC string untouched.
    output_bytes = (json.dumps(combined, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    output_path.write_bytes(output_bytes)
    manifest_path = out_dir / "combine_manifest.json"
    counts_by_round: dict[str, Counter[str]] = {}
    counts_by_label: Counter[str] = Counter()
    for row in combined:
        round_name = str(row["round"])
        counts_by_round.setdefault(round_name, Counter())[str(row["expected_verdict"])] += 1
        counts_by_label[str(row["expected_verdict"])] += 1
    manifest = {
        "script": Path(__file__).name,
        "created_at_utc": utc_now(),
        "seed": DEFAULT_SEED,
        "input_order": list(INPUT_ORDER),
        "inputs": per_file,
        "counts_by_stage": {
            "input_rows": sum(len(rows) for rows in rows_by_file.values()),
            "output_rows": len(combined), "dropped_rows": 0,
            "counts_by_file": {name: len(rows_by_file[name]) for name in INPUT_ORDER},
            "counts_by_round_and_label": {key: dict(value) for key, value in sorted(counts_by_round.items())},
            "counts_by_label": dict(counts_by_label),
        },
        "output": {"path": str(output_path), "row_count": len(combined),
                   "sha256": hashlib.sha256(output_bytes).hexdigest()},
        "dropped_items": [],
        **git_metadata(),
    }
    write_json(manifest_path, manifest)
    return output_path, manifest_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openphish", type=Path, required=True, help="malicious_openphish.json")
    parser.add_argument("--phishtank", type=Path, required=True, help="malicious_phishtank.json")
    parser.add_argument("--clean", type=Path, required=True, help="clean_labeled.json from VT labeler")
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        output, manifest = combine(
            {"openphish": args.openphish, "phishtank": args.phishtank, "clean": args.clean},
            args.out_dir,
        )
    except Exception as exc:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        write_json(args.out_dir / "combine_manifest.json", {
            "script": Path(__file__).name, "created_at_utc": utc_now(),
            "seed": DEFAULT_SEED,
            "counts_by_stage": {}, "dropped_items": [{"reason": "combine_failed", "error": str(exc)}],
            **git_metadata(),
        })
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"Wrote {output} and {manifest}")


if __name__ == "__main__":
    main()
