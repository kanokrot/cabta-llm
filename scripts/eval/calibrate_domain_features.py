#!/usr/bin/env python3
"""Calibrate domain-only heuristic features on a separate validation split.

This artifact is deliberately separate from the benchmark test results.  It
uses the existing ThreatFox-vs-Tranco case-control data for feature
calibration, but does not use CIRCL benchmark membership or runtime verdicts
as a feature.  No production scorer is changed by this script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

if str(REPO_ROOT := Path(__file__).resolve().parents[2]) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.utils.dga_detector import detect_dga


DEFAULT_MALICIOUS = REPO_ROOT / "scripts" / "adhoc" / "case_control_malicious.json"
DEFAULT_CLEAN = REPO_ROOT / "scripts" / "adhoc" / "case_control_clean.json"
DEFAULT_WHOIS = REPO_ROOT / "scripts" / "adhoc" / "case_control_whois_results.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "scripts" / "eval" / "output" / "domain_feature_calibration_2026-09-22.json"

FEATURE_NAMES = ("dga_confidence", "is_dga", "newly_registered", "age_days_observed")


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_whois(path: Path):
    return {
        row["domain"].lower().rstrip("."): row
        for row in (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    }


def stable_validation_split(domain: str) -> str:
    bucket = int(hashlib.sha256(domain.encode("utf-8")).hexdigest()[:8], 16) % 5
    return "validation" if bucket == 0 else "train"


def build_rows(malicious_path: Path, clean_path: Path, whois_path: Path):
    whois = load_whois(whois_path)
    rows = []
    for path, label in ((malicious_path, 1), (clean_path, 0)):
        payload = load_json(path)
        for item in payload["domains"]:
            domain = item["domain"].lower().rstrip(".")
            dga = detect_dga(domain)
            age = whois.get(domain, {})
            age_days = age.get("age_days")
            rows.append({
                "domain": domain,
                "label": label,
                "split": stable_validation_split(domain),
                "features": [
                    float(dga.get("confidence", 0)),
                    float(bool(dga.get("is_dga"))),
                    float(bool(age.get("is_newly_registered"))),
                    float(age_days is not None),
                ],
            })
    return rows


def metrics(model, x, y, threshold):
    probabilities = model.predict_proba(x)[:, 1]
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, predictions, labels=[0, 1]).ravel()
    return {
        "threshold": threshold,
        "accuracy": float(accuracy_score(y, predictions)),
        "precision": float(precision_score(y, predictions, zero_division=0)),
        "recall": float(recall_score(y, predictions, zero_division=0)),
        "f1": float(f1_score(y, predictions, zero_division=0)),
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--malicious", type=Path, default=DEFAULT_MALICIOUS)
    parser.add_argument("--clean", type=Path, default=DEFAULT_CLEAN)
    parser.add_argument("--whois", type=Path, default=DEFAULT_WHOIS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    rows = build_rows(args.malicious, args.clean, args.whois)
    train = [row for row in rows if row["split"] == "train"]
    validation = [row for row in rows if row["split"] == "validation"]
    x_train = np.asarray([row["features"] for row in train])
    y_train = np.asarray([row["label"] for row in train])
    x_validation = np.asarray([row["features"] for row in validation])
    y_validation = np.asarray([row["label"] for row in validation])

    model = make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42),
    )
    model.fit(x_train, y_train)

    threshold_metrics = [
        metrics(model, x_validation, y_validation, round(i / 100, 2))
        for i in range(1, 100)
    ]
    best_f1 = max(threshold_metrics, key=lambda item: (item["f1"], item["recall"], -item["threshold"]))
    precision_constrained = [item for item in threshold_metrics if item["precision"] >= 0.8]
    best_recall_precision_80 = max(
        precision_constrained,
        key=lambda item: (item["recall"], item["f1"], -item["threshold"]),
        default=None,
    )

    classifier = model[-1]
    report = {
        "data": {
            "malicious_path": str(args.malicious),
            "clean_path": str(args.clean),
            "whois_path": str(args.whois),
            "total": len(rows),
            "train": len(train),
            "validation": len(validation),
            "train_label_counts": {"clean": int(sum(y_train == 0)), "malicious": int(sum(y_train == 1))},
            "validation_label_counts": {"clean": int(sum(y_validation == 0)), "malicious": int(sum(y_validation == 1))},
            "split": "sha256(domain) bucket 0/5 validation; remaining buckets train",
        },
        "features": list(FEATURE_NAMES),
        "model": {
            "type": "StandardScaler + LogisticRegression(class_weight=balanced)",
            "coefficients_scaled": [float(value) for value in classifier.coef_[0]],
            "intercept": float(classifier.intercept_[0]),
        },
        "validation": {
            "best_f1": best_f1,
            "best_recall_with_precision_at_least_0_80": best_recall_precision_80,
            "selected_thresholds": threshold_metrics,
        },
        "guardrails": {
            "not_production_scoring": True,
            "does_not_use_circl_benchmark_membership": True,
            "does_not_modify_existing_jsonl": True,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "total": len(rows),
        "train": len(train),
        "validation": len(validation),
        "best_f1": best_f1,
        "best_recall_with_precision_at_least_0_80": best_recall_precision_80,
        "output": str(args.output),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
