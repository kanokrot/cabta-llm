from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analyzers.file_type_router import FileType
from src.tools.malware_analyzer import MalwareAnalyzer


def _make_analyzer(monkeypatch, config):
    monkeypatch.setattr(
        'src.tools.malware_analyzer.get_file_info',
        lambda _path: {'filename': 'sample.bin', 'size': 1},
    )
    monkeypatch.setattr(
        'src.tools.malware_analyzer.calculate_file_hashes',
        lambda _path: {'sha256': 'a' * 64, 'md5': 'b' * 32},
    )
    monkeypatch.setattr(
        'src.tools.malware_analyzer.FileTypeRouter.detect_file_type',
        lambda _path: (FileType.TEXT, {'detection_method': 'test'}),
    )
    monkeypatch.setattr(
        'src.tools.malware_analyzer.EntropyAnalyzer.analyze_file_entropy',
        lambda _path: {},
    )
    monkeypatch.setattr(
        'src.tools.malware_analyzer.YaraScanner.interpret_matches',
        lambda _matches: {},
    )
    monkeypatch.setattr(
        'src.tools.malware_analyzer.ToolBasedScoring.calculate_file_score',
        lambda _input: SimpleNamespace(
            combined_score=0,
            verdict='CLEAN',
            contributing_factors=[],
            breakdown={},
            confidence=1.0,
        ),
    )
    monkeypatch.setattr(
        'src.tools.malware_analyzer.FalsePositiveFilter.is_false_positive',
        lambda _file_data, _score: (False, ''),
    )

    analyzer = MalwareAnalyzer.__new__(MalwareAnalyzer)
    analyzer.config = config
    analyzer.notification_manager = None
    analyzer.threat_intel = SimpleNamespace(
        investigate_ioc_comprehensive=AsyncMock(return_value={}),
    )
    analyzer.sandbox = SimpleNamespace(check_file_sandboxes=AsyncMock(return_value={}))
    analyzer.fuzzy_hash_analyzer = SimpleNamespace(analyze_file=MagicMock(return_value={}))
    analyzer.ransomware_analyzer = SimpleNamespace(analyze_file=MagicMock(return_value={}))
    analyzer.string_extractor = SimpleNamespace(
        extract_strings=MagicMock(return_value={'ascii': [], 'unicode': []}),
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
    analyzer._notify_verdict = lambda *args: None
    analyzer._generate_mitre_mapping = lambda *args: []
    analyzer.kill_chain_analyzer = SimpleNamespace(
        analyze=lambda _mapping: SimpleNamespace(to_dict=lambda: {}),
    )
    analyzer.threat_actor_profiler = SimpleNamespace(match_techniques=lambda _ids: {})
    analyzer.llm_analyzer = SimpleNamespace(
        analyze_file=AsyncMock(return_value={'verdict': 'CLEAN'}),
    )
    return analyzer


@pytest.mark.asyncio
async def test_disabled_llm_is_not_called_and_result_is_empty(monkeypatch, tmp_path):
    analyzer = _make_analyzer(monkeypatch, {'analysis': {'enable_llm': False}})
    file_path = tmp_path / 'sample.bin'
    file_path.write_bytes(b'test')

    result = await analyzer.analyze(str(file_path))

    analyzer.llm_analyzer.analyze_file.assert_not_awaited()
    assert result['llm_analysis'] == {}


@pytest.mark.asyncio
@pytest.mark.parametrize('config', [{}, {'analysis': {'enable_llm': True}}])
async def test_missing_or_enabled_llm_is_called_once(monkeypatch, tmp_path, config):
    analyzer = _make_analyzer(monkeypatch, config)
    file_path = tmp_path / 'sample.bin'
    file_path.write_bytes(b'test')

    result = await analyzer.analyze(str(file_path))

    analyzer.llm_analyzer.analyze_file.assert_awaited_once()
    assert result['llm_analysis'] == {'verdict': 'CLEAN'}
