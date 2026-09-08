"""Unit tests for the file metadata hash-pair reshaping local tool."""

import pytest

from src.agent.tool_registry import extract_file_hash_pairs


def _wrapped(sha256: str):
    return {
        "result": {"hashes": {"sha256": sha256}},
        "server": "forensics_tools",
        "tool": "file_metadata",
    }


@pytest.mark.asyncio
async def test_extracts_hash_pairs_from_mcp_wrapped_results_in_order():
    file_paths = ["a.exe", "b.exe", "c.exe"]
    results = [_wrapped("sha-a"), _wrapped("sha-b"), _wrapped("sha-c")]

    output = await extract_file_hash_pairs(file_paths, results)

    assert output == {
        "pairs": [
            {"file_path": "a.exe", "sha256": "sha-a"},
            {"file_path": "b.exe", "sha256": "sha-b"},
            {"file_path": "c.exe", "sha256": "sha-c"},
        ],
        "hashes": ["sha-a", "sha-b", "sha-c"],
    }


@pytest.mark.asyncio
async def test_extracts_hash_pairs_from_plain_dict_results():
    file_paths = ["a.exe", "b.exe", "c.exe"]
    results = [
        {"hashes": {"sha256": "sha-a"}},
        {"hashes": {"sha256": "sha-b"}},
        {"hashes": {"sha256": "sha-c"}},
    ]

    output = await extract_file_hash_pairs(file_paths, results)

    assert output == {
        "pairs": [
            {"file_path": "a.exe", "sha256": "sha-a"},
            {"file_path": "b.exe", "sha256": "sha-b"},
            {"file_path": "c.exe", "sha256": "sha-c"},
        ],
        "hashes": ["sha-a", "sha-b", "sha-c"],
    }


@pytest.mark.asyncio
async def test_stops_at_shorter_result_list_when_lengths_mismatch():
    file_paths = ["a.exe", "b.exe", "c.exe", "d.exe", "e.exe"]
    results = [_wrapped("sha-a"), _wrapped("sha-b"), _wrapped("sha-c")]

    output = await extract_file_hash_pairs(file_paths, results)

    assert output == {
        "pairs": [
            {"file_path": "a.exe", "sha256": "sha-a"},
            {"file_path": "b.exe", "sha256": "sha-b"},
            {"file_path": "c.exe", "sha256": "sha-c"},
        ],
        "hashes": ["sha-a", "sha-b", "sha-c"],
    }


@pytest.mark.asyncio
async def test_skips_missing_malformed_or_empty_hashes():
    output = await extract_file_hash_pairs(
        ["missing.exe", "empty-dict.exe", "empty-string.exe"],
        [
            _wrapped_result({}),
            _wrapped_result({"hashes": {}}),
            _wrapped_result({"hashes": {"sha256": ""}}),
        ],
    )

    assert output == {"pairs": [], "hashes": []}


@pytest.mark.asyncio
async def test_skips_error_shaped_results_without_dropping_valid_pairs():
    output = await extract_file_hash_pairs(
        ["a.exe", "timeout.exe", "c.exe"],
        [_wrapped("sha-a"), {"error": "timeout"}, _wrapped("sha-c")],
    )

    assert output == {
        "pairs": [
            {"file_path": "a.exe", "sha256": "sha-a"},
            {"file_path": "c.exe", "sha256": "sha-c"},
        ],
        "hashes": ["sha-a", "sha-c"],
    }


@pytest.mark.asyncio
async def test_empty_input_lists_return_empty_pairs_and_hashes():
    output = await extract_file_hash_pairs([], [])

    assert output == {"pairs": [], "hashes": []}


def _wrapped_result(result):
    return {"result": result, "server": "forensics_tools", "tool": "file_metadata"}
