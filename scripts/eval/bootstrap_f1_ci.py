import json
import sys
import numpy as np
from pathlib import Path
from sklearn.metrics import f1_score

PROJECT_ROOT = Path(__file__).resolve().parents[2]
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

        # ถอดตัวคูณ Production เดิมออกก่อน (Reverse-engineer true base score)
        if cnt >= 3:
            true_base = threat_score / 1.30
        elif cnt == 2:
            true_base = threat_score / 1.15
        else:
            true_base = threat_score

        # คำนวณด้วยตัวคูณใหม่ที่ต้องการทดสอบ
        multiplier = 1.0 + b2 if cnt >= 3 else (1.0 + b1 if cnt == 2 else 1.0)
        final_score = min(100.0, true_base * multiplier)

        y_pred.append(1 if final_score >= 50.0 else 0)

    return f1_score(y_true, y_pred, average="macro", zero_division=0)

def main():
    file_path = PROJECT_ROOT / "scripts" / "eval" / "eval_results_group_a_v3_rich.jsonl"
    if not file_path.exists():
        print(f"Error: ไม่พบไฟล์ {file_path.name}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]

    n_records = len(records)

    # คำนวณ Point Estimate
    original_indices = list(range(n_records))
    f1_baseline = calculate_f1(records, original_indices, b1=0.15, b2=0.30)
    f1_optimal = calculate_f1(records, original_indices, b1=0.20, b2=0.30)

    print("\n--- Running Bootstrap Resampling (1,000 Iterations) ---")
    np.random.seed(42)
    n_iterations = 1000

    bootstrap_baseline = []
    bootstrap_optimal = []

    for i in range(n_iterations):
        sample_indices = np.random.choice(n_records, size=n_records, replace=True)
        bootstrap_baseline.append(calculate_f1(records, sample_indices, b1=0.15, b2=0.30))
        bootstrap_optimal.append(calculate_f1(records, sample_indices, b1=0.20, b2=0.30))

    ci_lower_base, ci_upper_base = np.percentile(bootstrap_baseline, [2.5, 97.5])
    ci_lower_opt, ci_upper_opt = np.percentile(bootstrap_optimal, [2.5, 97.5])

    print("\n=================================================================")
    print(f"[{file_path.name} | N = {n_records}]")
    print("=================================================================")
    print(f"Baseline (15% / 30%) : Macro F1 = {f1_baseline:.4f}  |  95% CI: [{ci_lower_base:.4f}, {ci_upper_base:.4f}]")
    print(f"Optimal  (20% / 30%) : Macro F1 = {f1_optimal:.4f}  |  95% CI: [{ci_lower_opt:.4f}, {ci_upper_opt:.4f}]")
    print("=================================================================")

if __name__ == "__main__":
    main()
