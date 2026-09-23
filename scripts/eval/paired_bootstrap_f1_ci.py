# 2026-09-21: script นี้ย้อน threat_score ของ 2-source ด้วย 1.20 (3+ ด้วย 1.30) ตามสมมติฐาน v3_rich/count รุ่นเดิม.
# grid_search_boost_v2.py ใช้ 1.15/1.30 จึงกู้ base และผลต่างกันเมื่ออ่านไฟล์เดียวกัน.
# gate ยืนยันว่า v3_rich ตรงกับ count+1.15/1.30; การหารด้วย 1.20 ไม่ได้ย้อนสูตรที่บันทึกไว้ตรง ๆ.
# ใช้ recompute_boost.py คำนวณจาก sources.*.score. หลักฐาน: evidence/source_weights_2026-09-21/final_boost_2026-09-21/gate_results.txt,
# S1_results.txt และ recompute_boost.py.
"""
Paired bootstrap CI สำหรับเปรียบเทียบ Baseline (15%/30%) vs Optimal (20%/30%)

หลักการ: ในแต่ละ bootstrap iteration เราสุ่ม resample ตัวอย่าง (ด้วยการคืนกลับ)
จาก dataset จริง (N=894) เพียงครั้งเดียว แล้วคำนวณ F1 ของทั้งสองสูตรบน "sample เดียวกัน"
เพราะ baseline กับ optimal เป็น correlated (ไม่ independent) การดู CI ของผลต่าง
โดยตรงจะแม่นกว่าการเอา CI สองเส้นมาเทียบด้วยตา

รายงานผลแบบตรงไปตรงมา: n=894 total records, แต่ระบุ n=22 (2-source) และ n=2 (3+-source)
เป็น subgroup size จริง ไม่มีการ duplicate/oversample ใดๆ ทั้งสิ้น
"""
import json
import argparse
import sys
import numpy as np
from pathlib import Path
from sklearn.metrics import f1_score

PROJECT_ROOT = Path(__file__).resolve().parents[2] if len(Path(__file__).resolve().parents) > 2 else Path(".")
sys.path.insert(0, str(PROJECT_ROOT))


def count_flagged_sources(record):
    if "sources_flagged" in record:
        return int(record["sources_flagged"])
    sources = record.get("sources") or record.get("source_details") or []
    count = 0
    if isinstance(sources, list):
        for s in sources:
            if isinstance(s, dict) and (s.get("flagged") is True or float(s.get("score", 0)) > 0):
                count += 1
            elif isinstance(s, str):
                count += 1
    return count


def calculate_f1(records, indices, b1, b2):
    y_true = []
    y_pred = []

    for idx in indices:
        r = records[idx]

        gt = str(r.get("expected_verdict", "")).upper()
        target = 1 if gt in ("MALICIOUS", "DGA") else 0
        y_true.append(target)

        cnt = count_flagged_sources(r)
        threat_score = float(r.get("threat_score", r.get("dga_confidence", r.get("score", 40.0))))

        if cnt >= 3:
            true_base = threat_score / 1.30
        elif cnt == 2:
            true_base = threat_score / 1.20
        else:
            true_base = threat_score

        multiplier = 1.0 + b2 if cnt >= 3 else (1.0 + b1 if cnt == 2 else 1.0)
        final_score = min(100.0, true_base * multiplier)

        y_pred.append(1 if final_score >= 50.0 else 0)

    return f1_score(y_true, y_pred, average="macro", zero_division=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=PROJECT_ROOT / "scripts" / "eval" / "eval_results_group_a_v3_rich.jsonl",
    )
    args = parser.parse_args()
    file_path = args.input
    if not file_path.exists():
        # fallback: allow running from repo root or scripts/eval directly
        alt = Path("scripts/eval/eval_results_group_a_v3_rich.jsonl")
        file_path = alt if alt.exists() else file_path

    if not file_path.exists():
        print(f"Error: ไม่พบไฟล์ {file_path}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]

    n_records = len(records)
    n_2src = sum(1 for r in records if count_flagged_sources(r) == 2)
    n_3plus = sum(1 for r in records if count_flagged_sources(r) >= 3)

    original_indices = list(range(n_records))
    f1_baseline_point = calculate_f1(records, original_indices, b1=0.15, b2=0.30)
    f1_optimal_point = calculate_f1(records, original_indices, b1=0.20, b2=0.30)
    diff_point = f1_optimal_point - f1_baseline_point

    print(f"[{file_path.name} | N={n_records} total | n(2-src)={n_2src} | n(3+-src)={n_3plus}]")
    print(f"หมายเหตุ: n(2-src) และ n(3+-src) คือจำนวน record จริงในแต่ละ bucket ไม่มีการ duplicate/oversample")
    print()
    print(f"Point estimate: Baseline F1={f1_baseline_point:.4f}  Optimal F1={f1_optimal_point:.4f}  Diff={diff_point:+.4f}")
    print()
    print("--- Paired Bootstrap (1,000 iterations, resample ทั้ง dataset ต่อรอบ) ---")

    np.random.seed(42)
    n_iterations = 1000
    diffs = []
    baselines = []
    optimals = []

    for i in range(n_iterations):
        sample_indices = np.random.choice(n_records, size=n_records, replace=True)
        f1_b = calculate_f1(records, sample_indices, b1=0.15, b2=0.30)
        f1_o = calculate_f1(records, sample_indices, b1=0.20, b2=0.30)
        baselines.append(f1_b)
        optimals.append(f1_o)
        diffs.append(f1_o - f1_b)

    ci_diff_lower, ci_diff_upper = np.percentile(diffs, [2.5, 97.5])
    ci_base_lower, ci_base_upper = np.percentile(baselines, [2.5, 97.5])
    ci_opt_lower, ci_opt_upper = np.percentile(optimals, [2.5, 97.5])

    pct_positive = 100.0 * np.mean(np.array(diffs) > 0)

    print()
    print("=" * 70)
    print(f"Baseline (15%/30%) : F1={f1_baseline_point:.4f}  95% CI: [{ci_base_lower:.4f}, {ci_base_upper:.4f}]")
    print(f"Optimal  (20%/30%) : F1={f1_optimal_point:.4f}  95% CI: [{ci_opt_lower:.4f}, {ci_opt_upper:.4f}]")
    print(f"Diff (Opt - Base)  : {diff_point:+.4f}  95% CI: [{ci_diff_lower:+.4f}, {ci_diff_upper:+.4f}]")
    print(f"% of bootstrap iterations where Optimal > Baseline: {pct_positive:.1f}%")
    print("=" * 70)
    print()
    if ci_diff_lower > 0:
        print("=> ผลต่างเป็นบวกอย่างมีนัยสำคัญที่ 95% CI (CI ของ diff ไม่คร่อมศูนย์)")
    else:
        print("=> 95% CI ของผลต่างคร่อมศูนย์ - ไม่สามารถสรุปได้อย่างมั่นใจ 95% ว่า Optimal ดีกว่า Baseline จริง")
        print("   (แม้ point estimate จะสูงกว่า แต่ยังอยู่ในขอบเขตของ sampling noise)")

    print()
    print("--- คำเตือนเรื่อง 3+-source bucket ---")
    print(f"n={n_3plus} record เท่านั้น - ค่า b2 (3+-source boost) ไม่สามารถ calibrate ได้อย่างมีความหมาย")
    print("ผลจาก grid search แสดงว่า b2 ในช่วง 20%-40% ให้ F1 เท่ากันทุกค่า (saturated)")
    print("=> คงค่า b2=30% ไว้ตามหลักวิศวกรรมเดิม ไม่ใช่เพราะมี empirical evidence สนับสนุนเฉพาะเจาะจง")


if __name__ == "__main__":
    main()
