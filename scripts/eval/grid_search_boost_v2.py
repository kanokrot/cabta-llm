# 2026-09-21: grid รุ่นเดิมย้อนคะแนน 2-source ด้วย 1.15 และ 3+ ด้วย 1.30 สำหรับข้อมูล v3_rich/count.
# paired_bootstrap_f1_ci.py ใช้ 1.20/1.30 จึงกู้ base และผลต่างกันเมื่อใช้ไฟล์เดียวกัน.
# gate ยืนยัน v3_rich/count+1.15/1.30; ใช้ recompute_boost.py คำนวณใหม่จาก source scores.
# หลักฐาน: evidence/source_weights_2026-09-21/final_boost_2026-09-21/gate_results.txt,
# S1_results.txt และ recompute_boost.py.
"""
Grid search สำหรับหา multi-source boost parameter (2-source / 3+-source)
ใช้ schema จริงของ eval_results_group_a_v2.jsonl:
    ioc, expected_verdict, expected_ioc_type, source, predicted_verdict,
    predicted_ioc_type, threat_score, sources_checked, sources_flagged,
    trusted_shortcut, error

สำคัญ:
- จำนวน source ที่ใช้กำหนด boost คือ `sources_flagged` (จำนวน source ที่ตรวจพบว่าภัยจริง)
  ไม่ใช่ `sources_checked` (จำนวน source ที่ถูกเรียกทั้งหมด)
- `threat_score` เป็นคะแนน "หลัง" บวก multi-source boost และ cap ที่ 100 แล้ว
  (มาจากการรันระบบจริง ไม่ใช่คะแนนดิบ) สคริปต์นี้จึง "ย้อนสูตรกลับ" โดยหารด้วย
  multiplier ปัจจุบัน (1.15 / 1.30) เพื่อประมาณ base_score ก่อน boost
- record ที่ threat_score == 100 (โดน cap) ถูกคัดออกจาก grid search เพราะย้อนสูตร
  กลับไม่ได้ — ไม่รู้ค่าจริงก่อน cap สคริปต์รายงานจำนวนที่คัดออกให้เห็นชัดเจน
  แทนที่จะซ่อนไว้
- นี่คือค่า "ประมาณ" ไม่ใช่ base_score ที่วัดตรง ๆ (ยังมี approximation error
  จากการ reverse) — ใช้เป็นสัญญาณเบื้องต้น ไม่ใช่หลักฐานยืนยันขั้นสุดท้าย
"""
import sys
import json
from pathlib import Path
from collections import Counter
from sklearn.metrics import f1_score, precision_score, recall_score

CURRENT_B1 = 0.15  # 2-source boost ที่ใช้ในระบบจริงตอนนี้
CURRENT_B2 = 0.30  # 3+-source boost ที่ใช้ในระบบจริงตอนนี้


def current_multiplier(n_flagged: int) -> float:
    if n_flagged >= 3:
        return 1.0 + CURRENT_B2
    elif n_flagged == 2:
        return 1.0 + CURRENT_B1
    return 1.0


def load_real_dataset(path: Path):
    dataset = []
    skipped_missing = 0
    skipped_capped = 0
    skipped_error = 0
    verdict_values = Counter()

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                skipped_missing += 1
                continue

            if row.get("error"):
                skipped_error += 1
                continue

            expected_verdict = row.get("expected_verdict")
            sources_flagged = row.get("sources_flagged")
            threat_score = row.get("threat_score")

            if expected_verdict is None or sources_flagged is None or threat_score is None:
                skipped_missing += 1
                continue

            verdict_values[expected_verdict] += 1

            # ย้อนสูตรกลับหา base_score — คัด record ที่โดน cap ออก
            if threat_score >= 100:
                skipped_capped += 1
                continue

            mult = current_multiplier(int(sources_flagged))
            base_score_approx = threat_score / mult

            ground_truth = 1 if str(expected_verdict).upper() == "MALICIOUS" else 0

            dataset.append({
                "sources_flagged": int(sources_flagged),
                "base_score": base_score_approx,
                "ground_truth": ground_truth,
            })

    print(f"Loaded {len(dataset)} usable records")
    print(f"Skipped: {skipped_missing} missing-field/malformed, "
          f"{skipped_error} error!=null, {skipped_capped} capped-at-100 (base_score unrecoverable)")
    print(f"expected_verdict value distribution: {dict(verdict_values)}")
    return dataset


def evaluate_boost(dataset, b1, b2):
    y_true = [d["ground_truth"] for d in dataset]
    y_pred = []

    for d in dataset:
        n = d["sources_flagged"]
        base = d["base_score"]

        if n >= 3:
            multiplier = 1.0 + b2
        elif n == 2:
            multiplier = 1.0 + b1
        else:
            multiplier = 1.0

        final_score = min(100.0, base * multiplier)
        y_pred.append(1 if final_score >= 50.0 else 0)

    f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    prec = precision_score(y_true, y_pred, average="macro", zero_division=0)
    rec = recall_score(y_true, y_pred, average="macro", zero_division=0)
    return f1, prec, rec


def main():
    if len(sys.argv) < 2:
        print("Usage: python grid_search_boost_v2.py <path_to_eval_results.jsonl>")
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    dataset = load_real_dataset(path)

    dist = Counter(d["sources_flagged"] for d in dataset)
    print(f"sources_flagged distribution (post-filter): {dict(sorted(dist.items()))}")
    n_at_2 = dist.get(2, 0)
    n_at_3plus = sum(v for k, v in dist.items() if k >= 3)
    if n_at_2 < 10 or n_at_3plus < 10:
        print(f"\n⚠ WARNING: only {n_at_2} records at exactly 2 sources_flagged, "
              f"{n_at_3plus} at 3+. Grid search result for that bucket will be "
              f"unreliable/meaningless with this few samples — treat as a coverage "
              f"limitation, not a null result, if this fires.\n")

    if len(dataset) < 30:
        print(f"⚠ WARNING: only {len(dataset)} usable records total — underpowered, "
              f"report as preliminary only.\n")

    beta1_range = [0.05, 0.10, 0.15, 0.20, 0.25]
    beta2_range = [0.15, 0.20, 0.25, 0.30, 0.35, 0.40]

    best_f1 = -1.0
    best_params = None

    print("=" * 70)
    print(f"{'2-Src (b1)':<14}{'3+-Src (b2)':<14}{'Precision':<12}{'Recall':<12}{'Macro F1':<12}")
    print("=" * 70)

    for b1 in beta1_range:
        for b2 in beta2_range:
            f1, prec, rec = evaluate_boost(dataset, b1, b2)
            print(f"{b1*100:>5.0f}%        {b2*100:>5.0f}%        "
                  f"{prec:.4f}      {rec:.4f}      {f1:.4f}")
            if f1 > best_f1:
                best_f1 = f1
                best_params = (b1, b2)

    print("=" * 70)
    if best_params:
        print(f"\nOptimal on real (reverse-derived) data: "
              f"2-sources={best_params[0]*100:.1f}%, 3+-sources={best_params[1]*100:.1f}% "
              f"(Macro F1={best_f1:.4f})")

    cur_f1, cur_prec, cur_rec = evaluate_boost(dataset, CURRENT_B1, CURRENT_B2)
    print(f"Current production values (15%/30%): "
          f"Precision={cur_prec:.4f} Recall={cur_rec:.4f} Macro F1={cur_f1:.4f}")


if __name__ == "__main__":
    main()
