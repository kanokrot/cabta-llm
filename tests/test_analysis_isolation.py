from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analyzers.file_type_router import FileType
from src.tools.malware_analyzer import MalwareAnalyzer


def test_email_wiring_isolated_from_flow_a(monkeypatch):
    from src.web.app import create_app

    app = create_app()
    email = app.state.email_analyzer
    flow_ioc = app.state.ioc_investigator
    flow_malware = app.state.malware_analyzer

    assert email is not None
    assert flow_ioc is not None
    assert flow_malware is not None
    assert email.ioc_investigator is not flow_ioc
    assert email.file_analyzer is not flow_malware
    assert email.ioc_investigator.notification_manager is None
    assert email.file_analyzer.notification_manager is None
    assert email.file_analyzer.ioc_investigator is email.ioc_investigator
    assert email.ioc_investigator.rag_kb is flow_ioc.rag_kb
    assert email.ioc_investigator.threat_intel is flow_ioc.threat_intel
    assert email.file_analyzer.threat_intel is flow_malware.threat_intel
    assert app.state.notification_manager is not None
    assert flow_ioc.notification_manager is app.state.notification_manager
    assert flow_malware.notification_manager is app.state.notification_manager


def _make_stub_analyzer(monkeypatch):
    monkeypatch.setattr(
        "src.tools.malware_analyzer.get_file_info",
        lambda _path: {"filename": "sample.bin", "size": 1},
    )
    monkeypatch.setattr(
        "src.tools.malware_analyzer.calculate_file_hashes",
        lambda _path: {"sha256": "a" * 64, "md5": "b" * 32},
    )
    monkeypatch.setattr(
        "src.tools.malware_analyzer.FileTypeRouter.detect_file_type",
        lambda _path: (FileType.TEXT, {"detection_method": "test"}),
    )
    monkeypatch.setattr(
        "src.tools.malware_analyzer.EntropyAnalyzer.analyze_file_entropy",
        lambda _path: {},
    )
    monkeypatch.setattr(
        "src.tools.malware_analyzer.YaraScanner.interpret_matches",
        lambda _matches: {},
    )
    monkeypatch.setattr(
        "src.tools.malware_analyzer.ToolBasedScoring.calculate_file_score",
        lambda _input: SimpleNamespace(
            combined_score=0,
            verdict="CLEAN",
            contributing_factors=[],
            breakdown={},
            confidence=1.0,
        ),
    )
    monkeypatch.setattr(
        "src.tools.malware_analyzer.FalsePositiveFilter.is_false_positive",
        lambda _file_data, _score: (False, ""),
    )

    analyzer = MalwareAnalyzer.__new__(MalwareAnalyzer)
    analyzer.config = {"analysis": {"enable_llm": False}}
    analyzer.notification_manager = MagicMock()
    analyzer.threat_intel = SimpleNamespace(
        investigate_ioc_comprehensive=AsyncMock(return_value={}),
    )
    analyzer.sandbox = SimpleNamespace(check_file_sandboxes=AsyncMock(return_value={}))
    analyzer.fuzzy_hash_analyzer = SimpleNamespace(analyze_file=MagicMock(return_value={}))
    analyzer.ransomware_analyzer = SimpleNamespace(analyze_file=MagicMock(return_value={}))
    analyzer.string_extractor = SimpleNamespace(
        extract_strings=MagicMock(return_value={"ascii": [], "unicode": []}),
        categorize_suspicious_strings=MagicMock(return_value={}),
        extract_iocs_from_strings=MagicMock(return_value={}),
        extract_registry_keys=MagicMock(return_value=[]),
        extract_mutexes=MagicMock(return_value=[]),
        extract_user_agents=MagicMock(return_value=[]),
        get_interesting_strings=MagicMock(return_value=[]),
    )
    analyzer.yara_scanner = SimpleNamespace(scan_file=MagicMock(return_value=[]))
    analyzer.ioc_investigator = None
    analyzer._get_analyzer = lambda _file_type: None
    analyzer._fallback_analysis = lambda _path: {}
    analyzer._generate_mitre_mapping = lambda *args: []
    analyzer.kill_chain_analyzer = SimpleNamespace(
        analyze=lambda _mapping: SimpleNamespace(to_dict=lambda: {}),
    )
    analyzer.threat_actor_profiler = SimpleNamespace(match_techniques=lambda _ids: {})
    analyzer.llm_analyzer = SimpleNamespace(analyze_file=AsyncMock(return_value={}))
    return analyzer


@pytest.mark.asyncio
async def test_file_analysis_does_not_notify(monkeypatch, tmp_path):
    analyzer = _make_stub_analyzer(monkeypatch)
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"test")

    result = await analyzer.analyze(str(file_path), analysis_id="analysis-1")

    assert "error" not in result
    analyzer.notification_manager.notify.assert_not_called()
