import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.rag.rag_knowledge_base import RAGKnowledgeBase
from src.tools.ioc_investigator import IOCInvestigator


class RecordingCollection:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def query(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


def _query_result(*rows):
    return {
        "documents": [[row[0] for row in rows]],
        "metadatas": [[row[1] for row in rows]],
        "distances": [[row[2] for row in rows]],
    }


def _knowledge_base(*responses):
    knowledge_base = object.__new__(RAGKnowledgeBase)
    knowledge_base._collection = RecordingCollection(responses)
    return knowledge_base


def test_query_without_metadata_filter_uses_pure_vector_search():
    knowledge_base = _knowledge_base(
        _query_result(
            ("MITRE guidance", {"category": "mitre_mapping"}, 0.20),
        )
    )

    hits = knowledge_base.query("command execution", max_distance=0.60)

    assert [hit["text"] for hit in hits] == ["MITRE guidance"]
    assert knowledge_base._collection.calls == [
        {
            "query_texts": ["command execution"],
            "n_results": 3,
            "where": None,
        }
    ]


def test_matching_verdict_is_applied_before_vector_similarity():
    knowledge_base = _knowledge_base(
        _query_result(
            (
                "Malicious IOC response",
                {"verdict": "MALICIOUS", "ioc_type": "any"},
                0.25,
            ),
        )
    )

    hits = knowledge_base.query(
        "ipv4 MALICIOUS threat score 85",
        category_filter="playbook",
        max_distance=0.60,
        metadata_filter={
            "verdict": "MALICIOUS",
            "ioc_type": {"$in": ["ipv4", "any"]},
        },
    )

    assert hits[0]["metadata"]["verdict"] == "MALICIOUS"
    assert knowledge_base._collection.calls[0]["where"] == {
        "$and": [
            {"category": "playbook"},
            {"verdict": "MALICIOUS"},
            {"ioc_type": {"$in": ["ipv4", "any"]}},
        ]
    }
    assert len(knowledge_base._collection.calls) == 1


def test_missing_verdict_falls_back_to_unfiltered_vector_search(caplog):
    knowledge_base = _knowledge_base(
        _query_result(),
        _query_result(
            (
                "Suspicious IOC triage",
                {"verdict": "SUSPICIOUS", "ioc_type": "any"},
                0.31,
            ),
        ),
    )

    with caplog.at_level(logging.DEBUG):
        hits = knowledge_base.query(
            "domain CLEAN threat score 10",
            max_distance=0.60,
            metadata_filter={"verdict": "CLEAN"},
        )

    assert [hit["text"] for hit in hits] == ["Suspicious IOC triage"]
    assert [call["where"] for call in knowledge_base._collection.calls] == [
        {"verdict": "CLEAN"},
        None,
    ]
    assert "falling back to unfiltered vector search" in caplog.text


def test_filtered_hits_over_distance_threshold_trigger_unfiltered_fallback():
    knowledge_base = _knowledge_base(
        _query_result(
            (
                "Distant malicious guidance",
                {"verdict": "MALICIOUS", "ioc_type": "any"},
                0.75,
            ),
        ),
        _query_result(
            ("MITRE guidance", {"category": "mitre_mapping"}, 0.20),
        ),
    )

    hits = knowledge_base.query(
        "command execution",
        max_distance=0.60,
        metadata_filter={"verdict": "MALICIOUS"},
    )

    assert [hit["text"] for hit in hits] == ["MITRE guidance"]
    assert len(knowledge_base._collection.calls) == 2


@pytest.mark.asyncio
async def test_ioc_investigator_queries_with_normalized_verdict_and_ioc_type(
    monkeypatch,
):
    investigator = IOCInvestigator.__new__(IOCInvestigator)
    investigator.config = {"analysis": {"enable_llm": False}}
    investigator.threat_intel = MagicMock()
    investigator.threat_intel.investigate_ioc_comprehensive = AsyncMock(
        return_value={
            "sources": {"source": {"malicious": True}},
            "sources_checked": 1,
            "sources_flagged": 1,
        }
    )
    investigator.rag_kb = MagicMock()
    investigator.rag_kb.query.return_value = []

    monkeypatch.setattr(
        "src.tools.ioc_investigator.IntelligentScoring.calculate_ioc_score",
        lambda _results: 85,
    )
    monkeypatch.setattr(
        "src.tools.ioc_investigator.IntelligentScoring.calculate_source_coverage",
        lambda _results: {
            "total_sources_attempted": 1,
            "sources_flagged": 1,
            "sources_clean": 0,
        },
    )
    monkeypatch.setattr(
        "src.tools.ioc_investigator.RuleGenerator.generate_ioc_rules",
        lambda *_args: {},
    )

    await investigator.investigate("1.2.3.4")

    investigator.rag_kb.query.assert_called_once_with(
        "ipv4 MALICIOUS threat score 85",
        max_distance=0.60,
        metadata_filter={
            "verdict": "MALICIOUS",
            "ioc_type": {"$in": ["ipv4", "any"]},
        },
    )
