import ast
import json
from pathlib import Path

import pytest

from scripts.eval import build_independent_url_holdout as builder
from scripts.eval import combine_independent_url_holdout as combiner
from scripts.eval import compute_holdout_metrics as metrics
from scripts.eval import eval_benchmark
from scripts.eval import label_clean_urls_vt as vt_labeler
from scripts.eval import measure_url_overlap as overlap


FIXTURE_SECRET_VT = "FIXTURE_ONLY_VT_KEY_7b5f"
FIXTURE_SECRET_TF = "FIXTURE_ONLY_THREATFOX_KEY_4d21"


def test_e2e_frozen_url_holdout_pipeline_with_mocks(tmp_path, monkeypatch, capsys):
    evidence = tmp_path / "evidence"
    openphish_dir = evidence / "openphish"
    phishtank_dir = evidence / "phishtank"
    tranco_dir = evidence / "tranco"
    combined_dir = evidence / "combined"
    overlap_dir = evidence / "overlap"

    long_prefix = "https://long.example/"
    long_url = long_prefix + "x" * (2048 - len(long_prefix.encode("utf-8")))
    malicious_urls = [
        "https://Mixed.Example/PathCase",
        "https://percent.example/a%2fb",
        "https://percent.example/a%2Fb",
        "http://port.example:8088/Path",
        "https://error.example/path?Q=Upper",
        "https://slash.example/path/",
        "https://user:pass@userinfo.example/path?token=AbC",
        long_url,
        "https://éxample.example/路径?Q=Á",
    ]
    assert len(long_url.encode("utf-8")) == 2048
    openphish_urls, phishtank_urls = malicious_urls[:5], malicious_urls[5:]
    openphish_file = tmp_path / "openphish_fixture.txt"
    openphish_file.write_bytes(("\n".join(openphish_urls) + "\n").encode("utf-8"))
    phishtank_file = tmp_path / "phishtank_fixture.json"
    phishtank_file.write_text(json.dumps([
        {"url": url, "verified": "yes", "online": "yes"} for url in phishtank_urls
    ], ensure_ascii=False), encoding="utf-8")

    open_path, _ = builder.build("openphish", openphish_dir, len(openphish_urls), 20261011,
                                 openphish_file, [], None, 1)
    phish_path, _ = builder.build("phishtank", phishtank_dir, len(phishtank_urls), 20261011,
                                  phishtank_file, [], None, 1)
    built_open = json.loads(open_path.read_text(encoding="utf-8"))
    built_phish = json.loads(phish_path.read_text(encoding="utf-8"))
    assert {row["ioc"] for row in built_open} == set(openphish_urls)
    assert {row["ioc"] for row in built_phish} == set(phishtank_urls)

    tranco_csv = tmp_path / "tranco_fixture.csv"
    tranco_csv.write_text("1000,clean.example\n", encoding="utf-8")
    clean_url = "https://clean.example/Deep/%2f?Token=UP"
    homepage = b'<a href="/Deep/%2f?Token=UP#frag">deep</a>'
    monkeypatch.setattr(builder, "_fetch_homepage", lambda domain, timeout: (
        homepage, f"https://{domain}/", builder.sha256_bytes(homepage), 200
    ))
    candidates_path, _ = builder.build("tranco", tranco_dir, 1, 20261011,
                                       tranco_csv, [], None, 1, sample_domains=1)
    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    assert candidates[0]["ioc"] == clean_url
    assert candidates[0]["expected_verdict"] == "PENDING"

    # The PENDING candidate is deliberately refused as a final clean input.
    rejected_dir = tmp_path / "rejected"
    with pytest.raises(ValueError, match="refusing combined output"):
        combiner.combine({"openphish": open_path, "phishtank": phish_path,
                          "clean": candidates_path}, rejected_dir)
    assert not (rejected_dir / "combined_holdout.json").exists()

    report = {"data": {"attributes": {"last_analysis_results": {
        "Fixture Engine": {"category": "undetected"},
    }}}}
    report_body = json.dumps(report).encode("utf-8")
    monkeypatch.setattr(vt_labeler, "_request_report", lambda url, api_key, timeout: (
        report_body, 200
    ))
    clean_path, _ = vt_labeler.label_candidates(
        candidates_path, tranco_dir, target=1, delay=0, api_key=FIXTURE_SECRET_VT
    )
    labeled_clean = json.loads(clean_path.read_text(encoding="utf-8"))
    assert [row["ioc"] for row in labeled_clean] == [clean_url]
    assert labeled_clean[0]["label_source"] == "virustotal_3tier"

    combined_path, combine_manifest = combiner.combine(
        {"openphish": open_path, "phishtank": phish_path, "clean": clean_path}, combined_dir
    )
    combined = json.loads(combined_path.read_text(encoding="utf-8"))
    combined_iocs = [row["ioc"] for row in combined]
    assert combined_iocs == ([row["ioc"] for row in built_open]
                             + [row["ioc"] for row in built_phish] + [clean_url])
    assert all(row["expected_verdict"] in {"MALICIOUS", "CLEAN"} for row in combined)
    assert all(row["expected_verdict"] != "PENDING" for row in combined)
    assert json.loads(combine_manifest.read_text(encoding="utf-8"))["output"]["sha256"]

    # Exercise the benchmark's actual JSON loader only; do not call its evaluator.
    loaded = eval_benchmark.load_benchmark_stratified(0, 20261011, combined_path)
    assert {row["ioc"] for row in loaded} == set(combined_iocs)

    request_terms = []

    def mocked_request_raw(url, payload=None, headers=None, timeout=30):
        if payload is None:
            return ("fixture " + malicious_urls[0]).encode("utf-8"), 200
        term = payload["search_term"]
        request_terms.append(term)
        if term == "error.example":
            return b'{"query_status":"error"}', 503
        return b'{"query_status":"no_result"}', 200

    monkeypatch.setattr(overlap, "request_raw", mocked_request_raw)
    flags_path, _ = overlap.measure(combined_path, overlap_dir, delay=0, retries=0,
                                    backoff=0, timeout=1, seed=20261011,
                                    key=FIXTURE_SECRET_TF)
    flags = json.loads(flags_path.read_text(encoding="utf-8"))
    assert [row["ioc"] for row in flags] == combined_iocs
    assert all(ioc in request_terms for ioc in combined_iocs)
    error_flag = next(row for row in flags if row["ioc"] == malicious_urls[4])
    assert error_flag["threatfox"]["host"]["status"] == "error"
    assert error_flag["threatfox"]["host"]["status"] != "miss"
    assert "error.example" in request_terms

    eval_results = tmp_path / "eval_results.jsonl"
    eval_rows = [{"ioc": row["ioc"], "expected_verdict": row["expected_verdict"],
                  "predicted_verdict": row["expected_verdict"], "sources": {}}
                 for row in combined]
    eval_results.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in eval_rows) + "\n",
                            encoding="utf-8")
    metrics_path, _ = metrics.compute(eval_results, flags_path, tmp_path / "metrics.json")
    metric_output = json.loads(metrics_path.read_text(encoding="utf-8"))
    assert metric_output["joined_rows"] == len(combined_iocs)
    assert metric_output["metrics"]["overall"]["confusion_matrix"]["FN"] == 0

    # Every recorded IOC remains the original UTF-8 string through each stage.
    assert [row["ioc"] for row in json.loads(open_path.read_text(encoding="utf-8"))] == [
        row["ioc"] for row in built_open
    ]
    assert [row["ioc"] for row in json.loads(phish_path.read_text(encoding="utf-8"))] == [
        row["ioc"] for row in built_phish
    ]
    for url in malicious_urls + [clean_url]:
        assert url.encode("utf-8") in combined_path.read_bytes()

    # The overlap module imports configuration/key-validation helpers only; it does not import scoring.
    overlap_tree = ast.parse(Path(overlap.__file__).read_text(encoding="utf-8"))
    imported = []
    for node in ast.walk(overlap_tree):
        if isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
        elif isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
    assert not any(name.startswith("src.integrations.threat_intel") or
                   name.startswith("src.scoring") or "IntelligentScoring" in name
                   for name in imported)
    assert "src.utils.api_key_validator" in imported
    assert "src.utils.config" in imported

    captured = capsys.readouterr()
    all_output = "\n".join(path.read_text(encoding="utf-8", errors="replace")
                             for path in evidence.rglob("*") if path.is_file())
    assert FIXTURE_SECRET_VT not in all_output + captured.out + captured.err
    assert FIXTURE_SECRET_TF not in all_output + captured.out + captured.err
