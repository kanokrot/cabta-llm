"""
scripts/eval/eval_benchmark.py  (stratified sampling version)

รัน IOC จาก benchmark dataset ผ่าน IOCInvestigator.investigate() จริง
แล้วบันทึกผลแบบ incremental (resumable) ไม่แก้โค้ด production ใดๆ

เปลี่ยนจากเดิม: ใช้ stratified sampling แทน pure random —
ดึง CLEAN ทั้งหมดเสมอ (n เล็ก ไม่อยากสุ่มทิ้ง) + สุ่ม MALICIOUS
ตามจำนวนที่ต้องการ เพื่อให้วัด precision/recall ได้มีความหมาย

Usage:
  python scripts/eval/eval_benchmark.py --malicious-limit 0 --seed 42
  python scripts/eval/eval_benchmark.py --malicious-limit 0 --seed 42 --resume
  python scripts/eval/eval_benchmark.py --malicious-limit 50 --seed 42  # optional sample
"""
import argparse
import asyncio
import json
import random
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.tools.ioc_investigator import IOCInvestigator
from src.utils.config import load_config

BENCHMARK_PATH = REPO_ROOT / "data" / "benchmark" / "benchmark_iocs_v2.json"
RESULTS_PATH = REPO_ROOT / "scripts" / "eval" / "eval_results_group_a_v2.jsonl"


def load_benchmark_stratified(malicious_limit, seed):
    """
    Stratified sample: เอา CLEAN ทั้งหมดเสมอ (dataset เล็ก ไม่อยากสุ่มทิ้ง)
    + สุ่ม MALICIOUS ตามจำนวนที่ขอ (malicious_limit=0 แปลว่าเอาหมด)
    """
    records = json.loads(BENCHMARK_PATH.read_text(encoding="utf-8"))

    clean_records = [r for r in records if r["expected_verdict"] == "CLEAN"]
    malicious_records = [r for r in records if r["expected_verdict"] == "MALICIOUS"]
    other_records = [r for r in records if r["expected_verdict"] not in ("CLEAN", "MALICIOUS")]

    if other_records:
        print(f"[warn] พบ {len(other_records)} record ที่ expected_verdict ไม่ใช่ "
              f"CLEAN/MALICIOUS (เช่น BENIGN) — รวมเข้าไปด้วยทั้งหมด")

    if malicious_limit and malicious_limit < len(malicious_records):
        rng = random.Random(seed)
        malicious_records = rng.sample(malicious_records, malicious_limit)

    combined = clean_records + malicious_records + other_records
    print(f"[sample] CLEAN={len(clean_records)} (ทั้งหมด, ไม่สุ่มทิ้ง) "
          f"MALICIOUS={len(malicious_records)} (สุ่ม seed={seed}) "
          f"OTHER={len(other_records)} -> รวม {len(combined)}")

    # สลับลำดับเพื่อไม่ให้ CLEAN ทั้งหมดติดกันตอนรัน (เผื่อพังกลางทางจะได้มีทั้งสองฝั่งใน partial results)
    rng2 = random.Random(seed + 1)
    rng2.shuffle(combined)
    return combined


def load_existing_results():
    done = {}
    if RESULTS_PATH.exists():
        for line_number, line in enumerate(
            RESULTS_PATH.read_text(encoding="utf-8").splitlines(), 1
        ):
            if line.strip():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    preview = line[:200]
                    if len(line) > 200:
                        preview += "..."
                    print(
                        f"[warn] skipping invalid JSON at line {line_number}: "
                        f"{preview!r} ({exc.msg})"
                    )
                    continue
                done[row["ioc"]] = row
    return done


async def evaluate(records, delay_seconds, resume):
    config = load_config()
    investigator = IOCInvestigator(config)

    done = load_existing_results() if resume else {}
    mode = "a" if resume else "w"
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    written_count = 0

    with RESULTS_PATH.open(mode, encoding="utf-8") as out:
        try:
            for i, rec in enumerate(records, 1):
                ioc = rec["ioc"]
                if ioc in done:
                    print(f"[{i}/{len(records)}] skip (already done): {ioc}")
                    continue
                print(f"[{i}/{len(records)}] investigating ({rec['expected_verdict']}): {ioc}")
                try:
                    result = await investigator.investigate(ioc)
                except Exception as exc:
                    result = {"error": str(exc)}

                row = {
                    "ioc": ioc,
                    "expected_verdict": rec["expected_verdict"],
                    "expected_ioc_type": rec["ioc_type"],
                    "source": rec.get("source"),
                    "predicted_verdict": result.get("verdict"),
                    "predicted_ioc_type": result.get("ioc_type"),
                    "threat_score": result.get("threat_score"),
                    "sources_checked": result.get("sources_checked"),
                    "sources_flagged": result.get("sources_flagged"),
                    "trusted_shortcut": "trusted_hostname" in result,
                    "error": result.get("error"),
                }
                out.write(json.dumps(row, ensure_ascii=False) + "\n")
                out.flush()
                written_count += 1
                time.sleep(delay_seconds)  # กัน rate limit (VT free tier = 4 req/min)
        except (KeyboardInterrupt, asyncio.CancelledError):
            out.flush()
            print(
                f"\n[stop] Ctrl+C received; flushed output and wrote "
                f"{written_count} new record(s) in this run."
            )


def main():
    parser = argparse.ArgumentParser(description="Evaluate CABTA scoring against benchmark dataset (stratified)")
    parser.add_argument("--malicious-limit", type=int, default=0,
                         help="จำนวน MALICIOUS ที่จะสุ่ม (default 0 = เอาทั้งหมด). "
                              "CLEAN จะถูกดึงมาทั้งหมดเสมอไม่ว่าจะตั้งค่านี้เป็นอะไร")
    parser.add_argument("--seed", type=int, default=42,
                         help="random seed สำหรับ reproducible subsample")
    parser.add_argument("--delay", type=float, default=16.0,
                         help="วินาทีหน่วงระหว่าง IOC (default 16 = ~4/min, ตาม VT free tier)")
    parser.add_argument("--resume", action="store_true",
                         help="ข้าม IOC ที่ทำไปแล้วใน eval_results.jsonl")
    args = parser.parse_args()

    records = load_benchmark_stratified(args.malicious_limit or None, args.seed)
    print(f"Evaluating {len(records)} IOC(s) total, delay={args.delay}s, resume={args.resume}")
    asyncio.run(evaluate(records, args.delay, args.resume))
    print(f"\nDone. Raw results: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
