"""Regression coverage for scorer-consistent IOC source display."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.scoring.intelligent_scoring import IntelligentScoring
from src.web.report_source_display import build_source_display_rows, display_source_name
from src.web.source_classification import count_source_classes
from src.web.visibility import ADMIN, serialize_report_job


EVAL_FILES = (
    Path(__file__).resolve().parents[1]
    / "evidence/vt_independent_holdout_2026-09-25/group_a_eval_results.jsonl",
    Path(__file__).resolve().parents[1]
    / "evidence/vt_independent_holdout_2026-09-25/vt_holdout_eval_results_179.jsonl",
)


def _eval_rows():
    for path in EVAL_FILES:
        with path.open(encoding="utf-8") as stream:
            yield from (json.loads(line) for line in stream if line.strip())


def _sample(ioc_type, *, clean=None):
    for row in _eval_rows():
        row_type = row.get("expected_ioc_type")
        if ioc_type == "hash":
            matches_type = row_type in {"hash", "sha256", "md5"}
        else:
            matches_type = row_type == ioc_type
        if not matches_type:
            continue
        raw_sources = row.get("sources") or {}
        flags = sum(
            source.get("status") in {"✓", "✓ FLAGGED", "FLAGGED", "flagged"}
            for source in raw_sources.values()
            if isinstance(source, dict)
        )
        if clean is None or (clean and flags == 0) or (not clean and flags > 0):
            return row, raw_sources
    raise AssertionError(f"No saved evaluation sample for IOC type {ioc_type}")


def _report(source_ioc, ioc_type, sources):
    scored = {"sources": sources}
    threat_score = IntelligentScoring.calculate_ioc_score(scored)
    job = {
        "id": "score-breakdown-regression",
        "analysis_type": "ioc",
        "status": "completed",
        "verdict": "CLEAN" if threat_score < 50 else "MALICIOUS",
        "score": threat_score,
        "user_id": 1,
        "params": {"value": source_ioc, "ioc_type": ioc_type},
        "result": {
            "ioc": source_ioc,
            "ioc_type": ioc_type,
            "threat_score": threat_score,
            "verdict": "CLEAN" if threat_score < 50 else "MALICIOUS",
            "sources": sources,
        },
    }
    result = serialize_report_job(job, role=ADMIN, viewer_user_id=1)["result"]
    return threat_score, result


def _render_report(result):
    templates_dir = Path(__file__).resolve().parents[1] / "templates"
    environment = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    return environment.get_template("report_view.html").render(
        request=SimpleNamespace(
            query_params={},
            url=SimpleNamespace(path="/api/reports/score-breakdown/html"),
            state=SimpleNamespace(user={"role": "admin"}),
        ),
        job={
            "id": "score-breakdown-regression",
            "analysis_type": "ioc",
            "status": "completed",
            "created_at": "2026-10-08T06:50:00+00:00",
            "completed_at": "2026-10-08T06:51:00+00:00",
            "result": result,
        },
        build_source_display_rows=build_source_display_rows,
        display_source_name=display_source_name,
    )


@pytest.mark.parametrize("ioc_type", ["domain", "url", "hash"])
def test_saved_eval_ioc_types_keep_scorer_breakdown_and_display_in_sync(ioc_type):
    eval_row, raw_sources = _sample(ioc_type, clean=False)
    scorer_score, report = _report(eval_row["ioc"], ioc_type, raw_sources)
    breakdown = report["score_breakdown"]
    classes = count_source_classes(report["sources"], breakdown)
    display_rows = build_source_display_rows(
        report["sources"], score_breakdown=breakdown, ioc_type=ioc_type
    )

    # These are the raw source dictionaries retained by the saved evaluator;
    # the test derives the breakdown and view model from that captured shape.
    assert report["threat_score"] == scorer_score
    assert all(
        row["source_class"] == "flagged"
        for row in display_rows
        if row["source_name"] in breakdown
        and breakdown[row["source_name"]]["flagged"] is True
    )
    assert classes["flagged"] == sum(
        item["flagged"] is True for item in breakdown.values()
    )
    scored_rows = [row for row in display_rows if row["scored"]]
    if scored_rows:
        top = max(scored_rows, key=lambda row: row["score"] or 0)
        assert top["score"] == max(
            item["score_used"] or 0
            for item in breakdown.values()
            if item["scored"] is True
        )
        html = _render_report(report)
        assert "Flagged / responded" in html
        assert f"{classes['flagged']} /" in html
        assert f"{top['display_name']} {top['score_text']}" in html


def test_saved_clean_eval_with_no_scored_flags_stays_clean():
    eval_row, raw_sources = _sample("domain", clean=True)
    scorer_score, report = _report(eval_row["ioc"], "domain", raw_sources)
    breakdown = report["score_breakdown"]
    display_rows = build_source_display_rows(
        report["sources"], score_breakdown=breakdown, ioc_type="domain"
    )

    assert scorer_score == 0
    assert not any(item["flagged"] for item in breakdown.values())
    assert not any(row["source_class"] == "flagged" for row in display_rows)
    assert report["verdict"] == "CLEAN"
    html = _render_report(report)
    assert "0 /" in html
    assert "N/A" in html


@pytest.mark.parametrize("flagged_count", [2, 3])
def test_multiple_scored_flags_use_scorer_result_for_boosted_display(flagged_count):
    eval_row, raw_sources = _sample("domain", clean=True)
    sources = dict(raw_sources)
    names = ["feodotracker", "spamhaus", "threatfox"][:flagged_count]
    scores = [60, 70, 80]
    for name, score in zip(names, scores):
        sources[name] = {"status": "✓", "score": score, "found": True}

    # Never recalculate the boost in this test: the score comes directly from
    # IntelligentScoring, so this guards the rendered result against diverging
    # from its existing 1.20 / 1.30 multi-source behavior.
    scorer_score, report = _report(eval_row["ioc"], "domain", sources)
    breakdown = report["score_breakdown"]
    display_rows = build_source_display_rows(
        report["sources"], score_breakdown=breakdown, ioc_type="domain"
    )
    flagged_scored = [
        item for item in breakdown.values()
        if item["flagged"] is True and item["scored"] is True
    ]

    assert len(flagged_scored) >= flagged_count
    assert scorer_score == report["threat_score"]
    assert sum(row["source_class"] == "flagged" for row in display_rows) >= flagged_count
    assert all(
        row["score"] == breakdown[row["source_name"]]["score_used"]
        for row in display_rows
        if row["source_name"] in names
    )
    html = _render_report(report)
    assert f"{flagged_count} /" in html
    assert f"{max(scores[:flagged_count])}" in html


def test_ioc_page_reads_flag_state_from_score_breakdown():
    template = (Path(__file__).resolve().parents[1] / "templates/analysis_ioc.html").read_text(encoding="utf-8")

    # The interactive IOC page counts and labels source cards from the same
    # serialized breakdown consumed by report rows and cards.
    assert "data.score_breakdown[name]" in template
    assert "item.flagged === true" in template
    assert "sourceBreakdown.flagged === true || sourceBreakdown.score_used > 0" in template
    assert "data.source_scoring_weights" in template
    assert "SCORED · Weight:" in template
