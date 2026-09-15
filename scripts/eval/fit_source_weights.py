"""Ad-hoc statistical fit of threat-intelligence source reliability weights.

This is an analysis script only.  It reads the evaluation JSONL and the IOC
cache, and never writes to either data source or to production scoring code.

The cache stores one row per (IOC, IOC type, source), and ``queried_at`` is the
time that row was written/refreshed.  ``eval_results.jsonl`` does not contain a
timestamp field, so the latest evaluation window is inferred from the latest
contiguous cache burst ending near the JSONL file mtime.  This is printed as a
raw data provenance fact before any model output.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.scoring.intelligent_scoring import IntelligentScoring  # read-only


EVAL_RESULTS_PATH = REPO_ROOT / "scripts" / "eval" / "eval_results_group_a_v2.jsonl"
CACHE_DB_PATH = Path(r"C:\Users\ACER\.blue-team-assistant\cache\ioc_cache.db")
ROUND_GAP_MINUTES = 5.0
N_SPLITS = 5
RANDOM_STATE = 42

# These are the values in intelligent_scoring.py as inspected for this run.
# Note that the production file uses 0.5 for its explicit low-confidence list;
# 0.8 is the fallback for an unknown source.  The distinction is printed below
# because it differs from the shorthand 1.5/1.0/0.8 description in the task.
HIGH_CONFIDENCE_SOURCES = {
    "virustotal",
    "abuseipdb",
    "feodotracker",
    "threatfox",
    "malwarebazaar",
}
MEDIUM_CONFIDENCE_SOURCES = {
    "alienvault",
    "urlhaus",
    "c2_trackers",
    "greynoise",
    "shodan",
    "criminalip",
    "ipqualityscore",
    "spamhaus",
    "pulsedive",
    "censys",
    "ip2proxy",
    "threatzone",
    "triage",
    "usom",
}
LOW_CONFIDENCE_SOURCES = {
    "tor_exit_nodes",
    "circl",
    "phishtank",
    "sslblacklist",
}


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO timestamp and make timezone-naive values explicitly UTC."""

    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_eval_rows(path: Path) -> List[Dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise ValueError("eval_results.jsonl contains no eval rows")
    print(f"Loaded {len(rows)} eval rows from {path}")
    if len({row["ioc"] for row in rows}) != len(rows):
        raise ValueError("eval_results.jsonl contains duplicate IOC values")
    invalid = [row["expected_verdict"] for row in rows if row.get("expected_verdict") not in {"MALICIOUS", "CLEAN"}]
    if invalid:
        raise ValueError(f"Unexpected expected_verdict values: {invalid}")
    return rows


def load_cache_rows(path: Path, iocs: Sequence[str]) -> List[Dict[str, Any]]:
    placeholders = ",".join("?" for _ in iocs)
    connection = sqlite3.connect(str(path))
    try:
        result = connection.execute(
            f"""
            SELECT ioc, ioc_type, source, result_json, queried_at, ttl_hours
            FROM ioc_cache
            WHERE ioc IN ({placeholders})
            """,
            list(iocs),
        ).fetchall()
    finally:
        connection.close()

    rows: List[Dict[str, Any]] = []
    for ioc, ioc_type, source, result_json, queried_at, ttl_hours in result:
        try:
            parsed_result = json.loads(result_json)
        except (TypeError, json.JSONDecodeError):
            parsed_result = {}
        rows.append(
            {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "source": source,
                "result": parsed_result,
                "queried_at": queried_at,
                "queried_at_dt": parse_timestamp(queried_at),
                "ttl_hours": ttl_hours,
            }
        )
    return rows


def infer_latest_round_window(
    cache_rows: Sequence[Mapping[str, Any]], eval_path: Path
) -> Tuple[datetime, datetime, datetime, datetime]:
    """Infer the most recent contiguous cache burst for the eval IOC set."""

    if not cache_rows:
        raise ValueError("No cache rows match the eval IOC set")

    ordered = sorted({row["queried_at_dt"] for row in cache_rows})
    cache_min = ordered[0]
    cache_max = ordered[-1]
    eval_file_mtime = datetime.fromtimestamp(eval_path.stat().st_mtime, tz=timezone.utc)

    # Work backward from the newest row.  Older evals are separated from the
    # latest run by a much larger gap than the within-run API calls.
    start = cache_max
    for previous, current in zip(reversed(ordered[:-1]), reversed(ordered[1:])):
        if (current - previous) > timedelta(minutes=ROUND_GAP_MINUTES):
            start = current
            break
        start = previous

    return start, cache_max, cache_min, eval_file_mtime


def select_latest_round_rows(
    cache_rows: Sequence[Mapping[str, Any]], start: datetime, end: datetime
) -> List[Dict[str, Any]]:
    """Select the latest burst and retain only the newest source row per IOC."""

    selected = [row for row in cache_rows if start <= row["queried_at_dt"] <= end]
    latest_by_key: Dict[Tuple[str, str], Mapping[str, Any]] = {}
    for row in selected:
        key = (str(row["ioc"]), str(row["source"]))
        old = latest_by_key.get(key)
        if old is None or row["queried_at_dt"] > old["queried_at_dt"]:
            latest_by_key[key] = row
    return [dict(row) for row in latest_by_key.values()]


def build_feature_matrix(
    eval_rows: Sequence[Mapping[str, Any]], cache_rows: Sequence[Mapping[str, Any]]
) -> Tuple[pd.DataFrame, pd.DataFrame, List[str]]:
    sources = sorted({str(row["source"]) for row in cache_rows})
    cache_by_ioc_source = {(str(row["ioc"]), str(row["source"])): row for row in cache_rows}

    feature_records: List[Dict[str, Any]] = []
    presence_records: List[Dict[str, bool]] = []
    index: List[str] = []
    for eval_row in eval_rows:
        ioc = str(eval_row["ioc"])
        index.append(ioc)
        values: Dict[str, Any] = {}
        presence: Dict[str, bool] = {}
        for source in sources:
            cached = cache_by_ioc_source.get((ioc, source))
            presence[source] = cached is not None
            values[source] = (
                int(IntelligentScoring._get_source_score(cached["result"]))
                if cached is not None
                else 0
            )
        values["is_malicious"] = int(eval_row["expected_verdict"] == "MALICIOUS")
        feature_records.append(values)
        presence_records.append(presence)

    feature_df = pd.DataFrame(feature_records, index=index)
    feature_df.index.name = "ioc"
    presence_df = pd.DataFrame(presence_records, index=index)
    presence_df.index.name = "ioc"
    return feature_df, presence_df, sources


def current_hardcoded_weight(source: str) -> float:
    source_lower = source.lower()
    if source_lower in HIGH_CONFIDENCE_SOURCES:
        return 1.5
    if source_lower in MEDIUM_CONFIDENCE_SOURCES:
        return 1.0
    if source_lower in LOW_CONFIDENCE_SOURCES:
        return 0.5
    return 0.8


def fit_cross_validated(
    feature_df: pd.DataFrame, sources: Sequence[str]
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    x = feature_df.loc[:, list(sources)].to_numpy(dtype=float)
    y = feature_df["is_malicious"].to_numpy(dtype=int)
    splitter = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)

    coefficient_rows: List[Dict[str, Any]] = []
    fold_coefficients: List[np.ndarray] = []
    metric_rows: List[Dict[str, Any]] = []

    for fold, (train_idx, test_idx) in enumerate(splitter.split(x, y), start=1):
        scaler = StandardScaler()
        x_train = scaler.fit_transform(x[train_idx])
        x_test = scaler.transform(x[test_idx])

        model = LogisticRegression(
            penalty="l2",
            C=1.0,
            class_weight="balanced",
            max_iter=2000,
        )
        model.fit(x_train, y[train_idx])
        probabilities = model.predict_proba(x_test)[:, 1]
        predictions = (probabilities >= 0.5).astype(int)
        fold_coefficients.append(model.coef_[0].copy())
        metric_rows.append(
            {
                "fold": fold,
                "accuracy": accuracy_score(y[test_idx], predictions),
                "precision": precision_score(y[test_idx], predictions, zero_division=0),
                "recall": recall_score(y[test_idx], predictions, zero_division=0),
                "n_test": len(test_idx),
                "n_test_clean": int((y[test_idx] == 0).sum()),
                "n_test_malicious": int((y[test_idx] == 1).sum()),
            }
        )

    coefficient_array = np.vstack(fold_coefficients)
    for position, source in enumerate(sources):
        per_fold = coefficient_array[:, position]
        coefficient_rows.append(
            {
                "source": source,
                "mean_coef": per_fold.mean(),
                "std_coef": per_fold.std(ddof=1),
                "coef_per_fold": [float(value) for value in per_fold],
            }
        )

    return pd.DataFrame(coefficient_rows), pd.DataFrame(metric_rows)


TIER_DEFINITIONS = {
    "high_tier_score": HIGH_CONFIDENCE_SOURCES,
    "medium_tier_score": MEDIUM_CONFIDENCE_SOURCES,
    "low_tier_score": LOW_CONFIDENCE_SOURCES,
}


def build_tier_feature_matrix(
    feature_df: pd.DataFrame, sources: Sequence[str], aggregation: str
) -> pd.DataFrame:
    """Collapse source score columns into the three production confidence tiers."""

    if aggregation not in {"sum", "max"}:
        raise ValueError(f"Unsupported tier aggregation: {aggregation}")

    tier_df = pd.DataFrame(index=feature_df.index)
    for tier_column, tier_sources in TIER_DEFINITIONS.items():
        available = [source for source in tier_sources if source in sources]
        if not available:
            tier_df[tier_column] = 0.0
            continue
        positive_scores = feature_df.loc[:, available].where(feature_df.loc[:, available] > 0, 0)
        if aggregation == "sum":
            tier_df[tier_column] = positive_scores.sum(axis=1)
        else:
            tier_df[tier_column] = positive_scores.max(axis=1)

    tier_df["is_malicious"] = feature_df["is_malicious"].astype(int)
    tier_df.index.name = feature_df.index.name
    return tier_df


def tier_ranking_report(
    coefficient_df: pd.DataFrame, tier_columns: Sequence[str]
) -> Dict[str, Any]:
    """Compare fitted tier ordering with the assumed high > medium > low order."""

    means = dict(zip(coefficient_df["source"], coefficient_df["mean_coef"]))
    expected_order = list(tier_columns)
    fitted_order = sorted(expected_order, key=lambda tier: means[tier], reverse=True)
    strict_mean_agreement = (
        means["high_tier_score"] > means["medium_tier_score"] > means["low_tier_score"]
    )

    fold_orders: List[List[str]] = []
    fold_agreements: List[bool] = []
    for fold_index in range(N_SPLITS):
        fold_values = {
            row["source"]: row["coef_per_fold"][fold_index]
            for _, row in coefficient_df.iterrows()
        }
        fold_order = sorted(expected_order, key=lambda tier: fold_values[tier], reverse=True)
        fold_orders.append(fold_order)
        fold_agreements.append(
            fold_values["high_tier_score"]
            > fold_values["medium_tier_score"]
            > fold_values["low_tier_score"]
        )

    return {
        "expected_order": expected_order,
        "fitted_mean_order": fitted_order,
        "strict_mean_agreement": strict_mean_agreement,
        "fold_orders": fold_orders,
        "fold_agreements": fold_agreements,
        "fold_agreement_count": sum(fold_agreements),
    }


def print_tier_level_refit(
    feature_df: pd.DataFrame,
    sources: Sequence[str],
    per_source_coefficient_df: pd.DataFrame,
    per_source_metric_df: pd.DataFrame,
) -> None:
    """Run and print the lower-dimensional sum and max tier refits."""

    tier_columns = list(TIER_DEFINITIONS)
    n = len(feature_df)
    n_clean = int((feature_df["is_malicious"] == 0).sum())
    n_malicious = int((feature_df["is_malicious"] == 1).sum())
    minority_events = min(n_clean, n_malicious)

    print("\n=== STEP 6: TIER-LEVEL REFIT (RAW OUTPUT) ===")
    print(
        "tier_definition=high/medium/low source sets from intelligent_scoring.py; "
        "each tier feature includes only scores > 0"
    )
    print("tier_columns=" + str(tier_columns))
    print("ranking_hypothesis=high_tier_score > medium_tier_score > low_tier_score")

    tier_results: List[Dict[str, Any]] = []
    for aggregation in ("sum", "max"):
        tier_df = build_tier_feature_matrix(feature_df, sources, aggregation)
        tier_coefficient_df, tier_metric_df = fit_cross_validated(tier_df, tier_columns)
        ranking = tier_ranking_report(tier_coefficient_df, tier_columns)

        print(f"\n--- {aggregation.upper()} aggregation: raw feature matrix ---")
        print(f"aggregation={aggregation}; shape={tier_df.shape}; p=3; label_column=is_malicious")
        print("raw tier DataFrame.describe()")
        print(tier_df.describe().to_string())
        print("raw tier DataFrame.head(10)")
        print(tier_df.head(10).to_string())
        print("raw tier DataFrame NaN count")
        print(tier_df.isna().sum().to_string())
        constant_features = [
            column for column in tier_columns if tier_df[column].nunique(dropna=False) <= 1
        ]
        print(f"constant_tier_feature_columns={constant_features}")

        print(f"\n--- {aggregation.upper()} aggregation: raw tier coefficient table ---")
        print(tier_coefficient_df.to_string(index=False))
        print("ranking_raw=")
        print(f"expected_order={ranking['expected_order']}")
        print(f"fitted_mean_order={ranking['fitted_mean_order']}")
        print(f"strict_mean_ranking_agreement={ranking['strict_mean_agreement']}")
        print(f"fitted_order_per_fold={ranking['fold_orders']}")
        print(f"strict_ranking_agreement_per_fold={ranking['fold_agreements']}")
        print(
            f"strict_ranking_agreement_folds={ranking['fold_agreement_count']}/{N_SPLITS}"
        )
        if constant_features:
            print(
                "ranking_interpretation=ranking may be numerically strict, but "
                f"constant features {constant_features} have no within-sample variation and their coefficient is not identifiable"
            )
        else:
            print("ranking_interpretation=all three tier features have within-sample variation")

        print(f"\n--- {aggregation.upper()} aggregation: raw EPV ---")
        minority_epv = minority_events / 3
        print(f"n={n}; p=3; n_clean={n_clean}; n_malicious={n_malicious}")
        print(f"minority_events={minority_events}; minority_epv={minority_epv:.6f}")
        print("epv_target_10=10; epv_target_20=20")
        print(f"minimum_minority_events_for_10_EPV=30; for_20_EPV=60")
        print(f"adequacy_against_10_EPV={'FAIL' if minority_epv < 10 else 'MEETS'}")
        print(f"adequacy_against_20_EPV={'FAIL' if minority_epv < 20 else 'MEETS'}")

        print(f"\n--- {aggregation.upper()} aggregation: raw 5-fold CV metrics ---")
        print("threshold=0.5; scaler_fit_scope=training_fold_only")
        print(tier_metric_df.to_string(index=False, float_format=lambda value: f"{value:.6f}"))
        print("tier_cv_mean_std=")
        print(
            tier_metric_df[["accuracy", "precision", "recall"]]
            .agg(["mean", "std"])
            .to_string(float_format=lambda value: f"{value:.6f}")
        )

        tier_summary = tier_metric_df[["accuracy", "precision", "recall"]].mean()
        per_source_summary = per_source_metric_df[["accuracy", "precision", "recall"]].mean()
        comparison = pd.DataFrame(
            [
                {
                    "model": "tier_level_" + aggregation,
                    "parameters": 3,
                    "accuracy": tier_summary["accuracy"],
                    "precision": tier_summary["precision"],
                    "recall": tier_summary["recall"],
                    "comparison_source": "5-fold CV mean",
                },
                {
                    "model": "previous_per_source_model",
                    "parameters": len(sources),
                    "accuracy": per_source_summary["accuracy"],
                    "precision": per_source_summary["precision"],
                    "recall": per_source_summary["recall"],
                    "comparison_source": "already-fit result in STEP 4; no refit",
                },
                {
                    "model": "current_hardcoded_weight_baseline",
                    "parameters": np.nan,
                    "accuracy": np.nan,
                    "precision": 1.00,
                    "recall": 0.66,
                    "comparison_source": "provided baseline; not rerun",
                },
            ]
        )
        tier_results.append(
            {
                "aggregation": aggregation,
                "mean_accuracy": tier_summary["accuracy"],
                "mean_precision": tier_summary["precision"],
                "mean_recall": tier_summary["recall"],
                "ranking_agreement": ranking["strict_mean_agreement"],
            }
        )
        print(f"\n--- {aggregation.upper()} aggregation: raw performance comparison ---")
        print(comparison.to_string(index=False, float_format=lambda value: f"{value:.6f}"))

    print("\n--- STEP 6 raw final comparison: sum vs max ---")
    print(pd.DataFrame(tier_results).to_string(index=False, float_format=lambda value: f"{value:.6f}"))
    print(
        "step6_direct_conclusion=ranking agreement is reported separately for sum and max above; "
        "a strict TRUE means fitted mean and every listed fold follow high > medium > low; "
        "treat any constant-tier TRUE as non-evidence of that tier's reliability"
    )


def pairwise_agreement(source: str, coefficient_df: pd.DataFrame, sources: Sequence[str]) -> Tuple[float, str]:
    weights = {row["source"]: current_hardcoded_weight(row["source"]) for _, row in coefficient_df.iterrows()}
    means = dict(zip(coefficient_df["source"], coefficient_df["mean_coef"]))
    agree = 0
    comparable = 0
    for other in sources:
        if other == source or weights[source] == weights[other]:
            continue
        comparable += 1
        if (means[source] - means[other]) * (weights[source] - weights[other]) > 0:
            agree += 1
    rate = agree / comparable if comparable else float("nan")
    return rate, ("à¹€à¸«à¹‡à¸™à¸”à¹‰à¸§à¸¢" if rate >= 0.5 else "à¹„à¸¡à¹ˆà¹€à¸«à¹‡à¸™à¸”à¹‰à¸§à¸¢") if comparable else "à¹€à¸›à¸£à¸µà¸¢à¸šà¹€à¸—à¸µà¸¢à¸šà¹„à¸¡à¹ˆà¹„à¸”à¹‰"


def build_comparison_table(coefficient_df: pd.DataFrame, sources: Sequence[str]) -> pd.DataFrame:
    comparison = coefficient_df.copy()
    comparison["current_hardcoded_weight"] = comparison["source"].map(current_hardcoded_weight)
    value_range = comparison["mean_coef"].max() - comparison["mean_coef"].min()
    if value_range > 0:
        comparison["heuristic_minmax_weight_0.5_1.5"] = (
            0.5 + (comparison["mean_coef"] - comparison["mean_coef"].min()) / value_range
        )
    else:
        comparison["heuristic_minmax_weight_0.5_1.5"] = 1.0

    comparison["current_rank"] = comparison["current_hardcoded_weight"].rank(
        ascending=False, method="dense"
    ).astype(int)
    comparison["fitted_rank"] = comparison["mean_coef"].rank(ascending=False, method="min").astype(int)
    agreements = [pairwise_agreement(source, coefficient_df, sources) for source in comparison["source"]]
    comparison["pairwise_agreement_pct"] = [rate * 100 for rate, _ in agreements]
    comparison["agreement"] = [label for _, label in agreements]
    return comparison[
        [
            "source",
            "current_hardcoded_weight",
            "heuristic_minmax_weight_0.5_1.5",
            "fitted_rank",
            "current_rank",
            "mean_coef",
            "std_coef",
            "pairwise_agreement_pct",
            "agreement",
        ]
    ].sort_values("fitted_rank")


def print_feature_output(feature_df: pd.DataFrame, presence_df: pd.DataFrame, sources: Sequence[str]) -> None:
    print("\n=== STEP 1: RAW FEATURE MATRIX OUTPUT ===")
    print(f"shape={feature_df.shape}; rows=IOC; source_columns={len(sources)}; label_column=is_malicious")
    print("\n--- raw DataFrame.describe() ---")
    print(feature_df.describe().to_string())
    print("\n--- raw DataFrame.head(10) ---")
    print(feature_df.head(10).to_string())
    print("\n--- pandas NaN count per column ---")
    print(feature_df.isna().sum().to_string())
    print("\n--- structural missing-value count per source (no cache row; score=0 is retained) ---")
    coverage = pd.DataFrame(
        {
            "cache_entry_count": presence_df.loc[:, list(sources)].sum(axis=0).astype(int),
            "missing_value_count": (~presence_df.loc[:, list(sources)]).sum(axis=0).astype(int),
            "coverage_pct": presence_df.loc[:, list(sources)].mean(axis=0).mul(100),
            "flagged_score_gt_0_count": (feature_df.loc[:, list(sources)] > 0).sum(axis=0).astype(int),
        }
    ).sort_values(["coverage_pct", "flagged_score_gt_0_count"], ascending=[True, False])
    print(coverage.to_string(float_format=lambda value: f"{value:.2f}"))


def print_limitation_output(
    feature_df: pd.DataFrame, coefficient_df: pd.DataFrame, metric_df: pd.DataFrame
) -> None:
    n = len(feature_df)
    p = feature_df.shape[1] - 1
    n_clean = int((feature_df["is_malicious"] == 0).sum())
    n_malicious = int((feature_df["is_malicious"] == 1).sum())
    minority_epv = min(n_clean, n_malicious) / p
    malicious_epv = n_malicious / p
    std_threshold = coefficient_df["std_coef"].quantile(0.75)
    unstable = coefficient_df.loc[coefficient_df["std_coef"] >= std_threshold].sort_values(
        "std_coef", ascending=False
    )

    print("\n=== STEP 5: RAW LIMITATION SUMMARY ===")
    print(f"n={n}; p={p}; n_clean={n_clean}; n_malicious={n_malicious}")
    print(f"observations_per_feature={n / p:.4f}")
    print(f"minority_class_events_per_feature={minority_epv:.4f} (10-event rule target=10; 20-event target=20)")
    print(f"malicious_events_per_feature={malicious_epv:.4f} (even if MALICIOUS is treated as event)")
    print(f"minimum minority events for 10 EPV={10 * p}; for 20 EPV={20 * p}")
    print(
        "rule_reference=Peduzzi et al. (1996), J Clin Epidemiol 49(12):1373-1379, "
        "DOI https://doi.org/10.1016/S0895-4356(96)00236-3; traditional >=10 events per variable"
    )
    print(
        "rule_caveat=Vittinghoff & McCulloch (2007), Am J Epidemiol 165(6):710-718, "
        "https://pubmed.ncbi.nlm.nih.gov/17182981/; the rule can be relaxed in some settings, "
        "so EPV alone is not a proof of adequacy"
    )
    print(f"adequacy_against_10_EPV={'FAIL' if minority_epv < 10 else 'MEETS'}")
    print(f"adequacy_against_20_EPV={'FAIL' if minority_epv < 20 else 'MEETS'}")
    print(f"unstable_std_definition=std_coef >= 75th_percentile; threshold={std_threshold:.6f}")
    print("unstable_sources_raw=")
    print(unstable[["source", "mean_coef", "std_coef", "coef_per_fold"]].to_string(index=False))
    print("unstable_source_count=" + str(len(unstable)))
    print(
        "decision=PRELIMINARY_SIGNAL_ONLY; do_not_replace_hardcoded_weights because "
        f"minority EPV={minority_epv:.4f} < 10 and coefficients are fold-sensitive. "
        "Expand the labelled dataset (Phase 2), then repeat with held-out validation and calibration."
    )


def main() -> None:
    eval_rows = load_eval_rows(EVAL_RESULTS_PATH)
    cache_rows_all = load_cache_rows(CACHE_DB_PATH, [row["ioc"] for row in eval_rows])
    start, end, matching_min, eval_mtime = infer_latest_round_window(cache_rows_all, EVAL_RESULTS_PATH)
    latest_rows = select_latest_round_rows(cache_rows_all, start, end)

    print("=== DATA PROVENANCE ===")
    print(f"eval_results_path={EVAL_RESULTS_PATH}")
    print(f"cache_db_path={CACHE_DB_PATH}")
    print(f"eval_rows={len(eval_rows)}; labels={pd.Series([row['expected_verdict'] for row in eval_rows]).value_counts().to_dict()}")
    print("eval_timestamp_field=absent; eval_file_mtime_utc=" + eval_mtime.isoformat())
    print(f"matching_cache_timestamp_min_utc={matching_min.isoformat()}")
    print(f"latest_cache_timestamp_max_utc={end.isoformat()}")
    print(f"inferred_latest_round_start_utc={start.isoformat()}")
    print(f"inferred_latest_round_end_utc={end.isoformat()}")
    print(f"round_gap_threshold_minutes={ROUND_GAP_MINUTES}")
    print(f"matching_cache_rows_all_history={len(cache_rows_all)}; selected_latest_round_rows={len(latest_rows)}")
    print(f"selected_latest_round_ioc_count={len({row['ioc'] for row in latest_rows})}; eval_ioc_without_selected_cache_rows={len(eval_rows) - len({row['ioc'] for row in latest_rows})}")
    print(
        "current_weight_source_note=production intelligent_scoring.py uses explicit low tier=0.5; "
        "unknown-source fallback=0.8 (high=1.5, medium=1.0)"
    )

    feature_df, presence_df, sources = build_feature_matrix(eval_rows, latest_rows)
    print_feature_output(feature_df, presence_df, sources)

    coefficient_df, metric_df = fit_cross_validated(feature_df, sources)
    print("\n=== STEP 2: RAW COEFFICIENT TABLE ===")
    print(coefficient_df.to_string(index=False))

    comparison_df = build_comparison_table(coefficient_df, sources)
    print("\n=== STEP 3: RAW NORMALIZATION AND COMPARISON TABLE ===")
    print(
        "normalization_note=min-max 0.5-1.5 is a heuristic ranking display only; "
        "standardized logistic coefficients are log-odds effects per one SD and are not calibrated source weights"
    )
    print(comparison_df.to_string(index=False, float_format=lambda value: f"{value:.6f}"))

    print("\n=== STEP 4: RAW 5-FOLD CV PERFORMANCE ===")
    print("threshold=0.5 on predicted probability; scaler_fit_scope=training_fold_only")
    print(metric_df.to_string(index=False, float_format=lambda value: f"{value:.6f}"))
    print("--- CV mean/std ---")
    print(metric_df[["accuracy", "precision", "recall"]].agg(["mean", "std"]).to_string(float_format=lambda value: f"{value:.6f}"))
    baseline_df = pd.DataFrame(
        [
            {
                "model": "current_hardcoded_weight_baseline",
                "accuracy": np.nan,
                "precision": 1.00,
                "recall": 0.66,
                "source": "provided baseline from latest eval; not rerun",
            }
        ]
    )
    print("--- baseline comparison (provided numbers; no rerun) ---")
    print(baseline_df.to_string(index=False, float_format=lambda value: f"{value:.6f}"))

    print_limitation_output(feature_df, coefficient_df, metric_df)
    print_tier_level_refit(feature_df, sources, coefficient_df, metric_df)


if __name__ == "__main__":
    main()
