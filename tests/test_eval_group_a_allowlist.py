import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EVAL_PATH = REPO_ROOT / "scripts" / "eval" / "eval_benchmark.py"


def _load_eval_module():
    spec = importlib.util.spec_from_file_location("eval_benchmark_under_test", EVAL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_group_a_only_flag_passes_locked_allowlist(monkeypatch):
    module = _load_eval_module()
    captured = {}

    monkeypatch.setattr(
        module,
        "load_benchmark_stratified",
        lambda limit, seed, benchmark_path=None: [],
    )

    async def fake_evaluate(records, delay_seconds, resume, output=None, allowed_sources=None):
        captured["records"] = records
        captured["delay_seconds"] = delay_seconds
        captured["resume"] = resume
        captured["allowed_sources"] = allowed_sources

    monkeypatch.setattr(module, "evaluate", fake_evaluate)
    monkeypatch.setattr(sys, "argv", [str(EVAL_PATH), "--group-a-only"])

    module.main()

    assert captured["allowed_sources"] == {
        "feodotracker",
        "tor_exit_nodes",
        "c2_trackers",
        "usom",
        "sslblacklist",
        "spamhaus",
        "threatfox",
    }
    assert captured["resume"] is False


def test_default_eval_mode_passes_no_allowlist(monkeypatch):
    module = _load_eval_module()
    captured = {}

    monkeypatch.setattr(
        module,
        "load_benchmark_stratified",
        lambda limit, seed, benchmark_path=None: [],
    )

    async def fake_evaluate(records, delay_seconds, resume, output=None, allowed_sources=None):
        captured["allowed_sources"] = allowed_sources

    monkeypatch.setattr(module, "evaluate", fake_evaluate)
    monkeypatch.setattr(sys, "argv", [str(EVAL_PATH)])

    module.main()

    assert captured["allowed_sources"] is None
