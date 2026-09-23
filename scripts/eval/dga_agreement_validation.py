"""Validate agreement between the rule-based and LLM DGA judges.

The benchmark's expected verdict is retained only as a proxy bucket label.  It
is not treated as a DGA ground-truth label.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_PATH = REPO_ROOT / "data" / "benchmark" / "benchmark_iocs_v2.json"
CONFIG_PATH = REPO_ROOT / "config.yaml"
OUTPUT_PATH = Path(__file__).resolve().parent / "output" / "dga_agreement_raw.jsonl"
LOG_PATH = Path(__file__).resolve().parent / "output" / "dga_agreement.log"
CSV_SOURCE = "chrmor/DGA_domains_dataset"

_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT)
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
_file_handler = logging.FileHandler(LOG_PATH, mode="w", encoding="utf-8")
_file_handler.setLevel(logging.INFO)
_file_handler.setFormatter(logging.Formatter(_LOG_FORMAT))
logging.getLogger().addHandler(_file_handler)

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.utils.dga_detector import detect_dga  # noqa: E402
from src.utils.llm_dga_judge import judge_domain  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare rule-based and LLM DGA judgments for benchmark domains."
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help=(
            "Load headerless label,family,domain records from this CSV "
            "instead of the default benchmark JSON."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process at most this many domains (useful for a dry-run).",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip domains already present in the incremental JSONL output.",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Read the existing JSONL output and print its summary without making calls.",
    )
    return parser.parse_args()


def load_config() -> Dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file)
    return config if isinstance(config, dict) else {}


def load_csv_domain_records(csv_path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        for row_number, row in enumerate(reader, start=1):
            if len(row) != 3:
                raise ValueError(
                    f"Expected 3 columns (label,family,domain) on line "
                    f"{row_number}, got {len(row)}: {row!r}"
                )
            label, family, domain = row
            label = label.strip().lower()
            family = family.strip().lower()
            domain = domain.strip().lower().rstrip(".")

            if not domain:
                continue
            if label not in {"dga", "legit"}:
                raise ValueError(
                    f"Unsupported label on line {row_number}: {label!r}"
                )

            is_dga = label == "dga"
            records.append(
                {
                    "ioc": domain,
                    "ioc_type": "domain",
                    "source": CSV_SOURCE,
                    "ground_truth_label": label,
                    "ground_truth_is_dga": is_dga,
                    "ground_truth_family": family if is_dga else None,
                    "raw_source_tag": family,
                }
            )

    if not records:
        raise ValueError("Dataset contains no usable records")

    return records


def load_domain_records(csv_path: Path | None = None) -> List[Dict[str, Any]]:
    if csv_path is not None:
        return load_csv_domain_records(csv_path)

    with BENCHMARK_PATH.open("r", encoding="utf-8") as benchmark_file:
        records = json.load(benchmark_file)
    return [
        record
        for record in records
        if isinstance(record, dict) and record.get("ioc_type") == "domain"
    ]


def read_output_records() -> List[Dict[str, Any]]:
    if not OUTPUT_PATH.exists():
        return []

    records: List[Dict[str, Any]] = []
    with OUTPUT_PATH.open("r", encoding="utf-8") as output_file:
        for line_number, line in enumerate(output_file, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"Warning: skipping malformed JSONL line {line_number}: {exc}",
                    file=sys.stderr,
                )
                continue
            if isinstance(record, dict) and isinstance(record.get("domain"), str):
                records.append(record)
    return records


def completed_domains(records: Iterable[Dict[str, Any]]) -> Set[str]:
    return {record["domain"] for record in records if isinstance(record.get("domain"), str)}


def validate_resume_source(
    existing_records: Iterable[Dict[str, Any]],
    expected_source: str | None,
) -> None:
    if expected_source is None:
        return

    existing_sources = {
        record.get("source")
        for record in existing_records
    }
    if existing_sources and existing_sources != {expected_source}:
        raise ValueError(
            "Cannot use --resume with --csv because the existing output "
            "contains records from a different dataset. Use --csv without "
            "--resume to replace the output, or remove/use a separate output "
            "file before resuming."
        )


def build_output_record(
    benchmark_record: Dict[str, Any],
    rule_result: Dict[str, Any],
    llm_result: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "domain": benchmark_record["ioc"],
        "expected_verdict": benchmark_record.get("expected_verdict"),
        "source": benchmark_record.get("source"),
        "rule_result": rule_result,
        "rule_is_dga": bool(rule_result.get("is_dga", False)),
        "llm_judgment": llm_result,
        "llm_verdict": llm_result.get("llm_verdict", "uncertain"),
    }


async def evaluate_domain(
    benchmark_record: Dict[str, Any],
    config: Dict[str, Any],
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    domain = benchmark_record["ioc"]
    rule_result = detect_dga(domain)
    async with semaphore:
        llm_result = await judge_domain(domain, config)
    return build_output_record(benchmark_record, rule_result, llm_result)


async def run_evaluation(
    domain_records: List[Dict[str, Any]],
    config: Dict[str, Any],
    resume: bool,
    limit: int | None,
    dataset_source: str | None = None,
) -> List[Dict[str, Any]]:
    existing_records = read_output_records()
    if resume:
        validate_resume_source(existing_records, dataset_source)
    done_domains = completed_domains(existing_records) if resume else set()
    pending = [
        record for record in domain_records if record["ioc"] not in done_domains
    ]
    if limit is not None:
        if limit < 0:
            raise ValueError("--limit must be zero or greater")
        pending = pending[:limit]

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    semaphore = asyncio.Semaphore(3)
    write_mode = "a" if resume else "w"

    print(
        f"Domains in benchmark: {len(domain_records)}; "
        f"already completed: {len(done_domains)}; "
        f"to process: {len(pending)}"
    )

    with OUTPUT_PATH.open(write_mode, encoding="utf-8") as output_file:
        tasks = [
            asyncio.create_task(evaluate_domain(record, config, semaphore))
            for record in pending
        ]
        completed = 0
        for task in asyncio.as_completed(tasks):
            result = await task
            output_file.write(json.dumps(result, ensure_ascii=False) + "\n")
            output_file.flush()
            completed += 1
            print(
                f"[{completed}/{len(pending)}] {result['domain']} "
                f"rule_is_dga={result['rule_is_dga']} "
                f"llm_verdict={result['llm_verdict']}"
            )

    return read_output_records()


def format_rate(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "n/a (0 records)"
    return f"{numerator}/{denominator} ({numerator / denominator:.2%})"


def print_summary(records: List[Dict[str, Any]]) -> None:
    comparable = [
        record
        for record in records
        if isinstance(record.get("rule_is_dga"), bool)
        and isinstance(record.get("llm_verdict"), str)
    ]
    agreement_count = sum(
        record["rule_is_dga"] == (record["llm_verdict"] == "dga")
        for record in comparable
    )

    print("\n=== DGA AGREEMENT SUMMARY ===")
    print(f"records available: {len(records)}")
    print(f"records compared: {len(comparable)}")
    print(
        "agreement rate (rule_is_dga == (llm_verdict == 'dga')): "
        f"{format_rate(agreement_count, len(comparable))}"
    )
    print(
        "llm_verdict breakdown: "
        + ", ".join(
            f"{verdict}={count}"
            for verdict, count in sorted(
                Counter(record["llm_verdict"] for record in comparable).items()
            )
        )
    )

    for bucket in ("MALICIOUS", "CLEAN"):
        bucket_records = [
            record
            for record in comparable
            if str(record.get("expected_verdict", "")).upper() == bucket
        ]
        rule_dga = sum(record["rule_is_dga"] for record in bucket_records)
        llm_dga = sum(record["llm_verdict"] == "dga" for record in bucket_records)
        print(f"\n{bucket} bucket: {len(bucket_records)} records")
        print(
            "  rule detector is_dga=True: "
            f"{format_rate(rule_dga, len(bucket_records))}"
        )
        print(
            "  LLM verdict='dga': "
            f"{format_rate(llm_dga, len(bucket_records))}"
        )
        print(
            "  rule detector breakdown: "
            f"is_dga=True={rule_dga}, is_dga=False={len(bucket_records) - rule_dga}"
        )
        print(
            "  LLM breakdown: "
            + ", ".join(
                f"{verdict}={count}"
                for verdict, count in sorted(
                    Counter(record["llm_verdict"] for record in bucket_records).items()
                )
            )
        )

    other_labels = [
        record
        for record in comparable
        if str(record.get("expected_verdict", "")).upper()
        not in {"MALICIOUS", "CLEAN"}
    ]
    if other_labels:
        print(f"\nOther expected_verdict labels: {len(other_labels)}")

    print(
        "\nWARNING: expected_verdict is not DGA ground truth. "
        "MALICIOUS/CLEAN bucket results are proxy statistics only; "
        "they do not establish whether a domain is DGA."
    )


def main() -> None:
    args = parse_args()
    if args.summary_only:
        print_summary(read_output_records())
        return

    domain_records = load_domain_records(args.csv)
    config = load_config()
    records = asyncio.run(
        run_evaluation(
            domain_records=domain_records,
            config=config,
            resume=args.resume,
            limit=args.limit,
            dataset_source=CSV_SOURCE if args.csv is not None else None,
        )
    )
    print_summary(records)
    print(f"\nRaw output: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
