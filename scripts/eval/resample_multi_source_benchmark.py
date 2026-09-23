import json
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def count_flagged_sources(record):
    """นับเฉพาะ Source ที่ตรวจพบภัยคุกคามจริง (flagged == True หรือ score > 0)"""
    if "sources_flagged" in record:
        return int(record["sources_flagged"])

    sources = (
        record.get("sources")
        or record.get("source_details")
        or record.get("matches")
        or []
    )

    count = 0
    if isinstance(sources, list):
        for s in sources:
            if isinstance(s, dict):
                if (
                    s.get("flagged") is True
                    or s.get("matched") is True
                    or float(s.get("score", 0)) > 0
                ):
                    count += 1
            elif isinstance(s, str):
                count += 1
    elif isinstance(sources, dict):
        for k, v in sources.items():
            if isinstance(v, dict):
                if (
                    v.get("flagged") is True
                    or v.get("matched") is True
                    or float(v.get("score", 0)) > 0
                ):
                    count += 1
            elif v:
                count += 1
    else:
        count = int(record.get("sources_count", 0))

    return count


def create_stratified_multi_source_dataset(
    input_file, output_file, target_total=1000, seed=42
):
    random.seed(seed)

    path = PROJECT_ROOT / "scripts" / "eval" / input_file
    if not path.exists():
        print(f"Error: ไม่พบไฟล์ {input_file}")
        return

    with open(path, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]

    # แยก Bucket ตามจำนวน Flagged Sources
    b0_1 = []
    b2 = []
    b3_plus = []

    for r in records:
        cnt = count_flagged_sources(r)
        if cnt >= 3:
            b3_plus.append(r)
        elif cnt == 2:
            b2.append(r)
        else:
            b0_1.append(r)

    print(
        f"Original Flagged Counts -> 0-1 Src: {len(b0_1)}, 2 Src: {len(b2)}, 3+ Src: {len(b3_plus)}"
    )

    if not b2:
        print("Error: ไม่พบเคส 2 Sources สำหรับทำ Resample")
        return

    # ตั้งเป้าหมายจำนวนตัวอย่างตามสัดส่วน
    target_b2 = min(250, len(b2) * 10)  # Oversample เคส 2 Sources
    target_b3 = (
        min(100, len(b3_plus) * 20) if b3_plus else len(b2)
    )  # Oversample เคส 3+ Sources
    target_b0_1 = min(650, len(b0_1))

    resampled_b0_1 = random.sample(b0_1, target_b0_1)
    resampled_b2 = [random.choice(b2) for _ in range(target_b2)]
    resampled_b3_plus = (
        [random.choice(b3_plus) for _ in range(target_b3)]
        if b3_plus
        else [random.choice(b2) for _ in range(target_b3)]
    )

    final_dataset = resampled_b0_1 + resampled_b2 + resampled_b3_plus
    random.shuffle(final_dataset)

    out_path = PROJECT_ROOT / "scripts" / "eval" / output_file
    with open(out_path, "w", encoding="utf-8") as f:
        for item in final_dataset:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    print(f"\nSuccessfully generated stratified dataset -> {output_file}")
    print(
        f"New Distribution -> 0-1 Src: {len(resampled_b0_1)}, 2 Src: {len(resampled_b2)}, 3+ Src: {len(resampled_b3_plus)} (Total: {len(final_dataset)})\n"
    )


if __name__ == "__main__":
    create_stratified_multi_source_dataset(
        "eval_results_group_a_v3_rich.jsonl",
        "eval_results_stratified_balanced.jsonl",
    )