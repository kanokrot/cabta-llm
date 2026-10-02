import json
import struct
from pathlib import Path

import oletools.oleobj as oleobj_module
import pytest

from src.mcp_servers import (
    free_osint_tools,
    malwoverview_tools,
    network_tools,
    osint_tools,
    remnux_tools,
)


def _write_classic_pcap(path, magic, endian):
    ethernet = (b"\x00" * 6) + (b"\x00" * 6) + struct.pack("!H", 0x0800)
    ipv4 = (
        b"\x45\x00"
        + struct.pack("!H", 28)
        + b"\x00\x00\x00\x00"
        + b"\x40\x11\x00\x00"
        + bytes([192, 0, 2, 1])
        + bytes([198, 51, 100, 2])
    )
    packet_data = ethernet + ipv4 + struct.pack("!HHHH", 12345, 53, 8, 0)
    global_header = magic + struct.pack(
        f"{endian}HHIIII", 2, 4, 0, 0, 65535, 1
    )
    packet_header = struct.pack(
        f"{endian}IIII", 1, 0, len(packet_data), len(packet_data)
    )
    path.write_bytes(global_header + packet_header + packet_data)


def test_parse_pcap_classic_passes_file_path(tmp_path):
    pcap = tmp_path / "sample.pcap"
    _write_classic_pcap(pcap, b"\xd4\xc3\xb2\xa1", "<")

    result = json.loads(network_tools.parse_pcap(str(pcap)))

    assert "error" not in result
    assert result["file"] == str(pcap)
    assert result["packets_parsed"] == 1
    assert result["link_type"] == 1
    assert result["packets"][0]["protocol"] == "UDP"


def test_parse_pcap_classic_big_endian(tmp_path):
    pcap = tmp_path / "sample-big-endian.pcap"
    _write_classic_pcap(pcap, b"\xa1\xb2\xc3\xd4", ">")

    result = json.loads(network_tools.parse_pcap(str(pcap)))

    assert "error" not in result
    assert result["packets_parsed"] == 1
    assert result["link_type"] == 1
    assert result["packets"][0]["protocol"] == "UDP"


def test_analyze_zeek_logs_parses_real_tabs(tmp_path):
    zeek = tmp_path / "conn.log"
    zeek.write_text(
        "#separator \\x09\n"
        "#set_separator ,\n"
        "#empty_field (empty)\n"
        "#unset_field -\n"
        "#path conn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\n"
        "1.0\tC1\t192.0.2.1\t1234\t198.51.100.2\t80\ttcp\thttp\n",
        encoding="utf-8",
    )

    result = json.loads(network_tools.analyze_zeek_logs(str(zeek)))

    assert "error" not in result
    assert result["total_records"] == 1
    assert result["sample_records"][0]["id.orig_h"] == "192.0.2.1"


def test_oleobj_extract_passes_file_data(monkeypatch, tmp_path):
    document = tmp_path / "sample.doc"
    document.write_bytes(b"not-an-ole-document")
    captured = {}

    def fake_find_ole(filename, data, xml_parser=None):
        captured["filename"] = filename
        captured["data"] = data
        return iter(())

    monkeypatch.setattr(oleobj_module, "find_ole", fake_find_ole)
    result = json.loads(remnux_tools.oleobj_extract(str(document)))

    assert "error" not in result
    assert captured["filename"] == str(document.resolve())
    assert captured["data"] == b"not-an-ole-document"


def test_oleobj_extract_docx_without_embedded_ole():
    document = Path("scripts/adhoc/probe_fixtures/probe.docx")
    if not document.is_file():
        pytest.skip("NO_SAMPLE: probe.docx fixture is unavailable")

    result = json.loads(remnux_tools.oleobj_extract(str(document)))

    assert "error" not in result
    assert result["objects"] == []
    assert result["object_count"] == 0


def test_oleobj_extract_embedded_ole_object():
    pytest.skip("NO_SAMPLE: no embedded-OLE fixture exists in the repository")


def test_malwoverview_auth_key_headers(monkeypatch):
    captured = []

    def fake_post(url, fields, timeout=20, extra_headers=None):
        captured.append((url, fields, extra_headers))
        return "{}"

    monkeypatch.setattr(malwoverview_tools, "_http_post_form", fake_post)
    test_key = "0123456789abcdef0123456789abcdef"
    monkeypatch.setattr(
        malwoverview_tools,
        "_API_KEYS",
        {"threatfox": test_key},
    )

    malwoverview_tools._query_malwarebazaar_hash("a" * 64)
    malwoverview_tools._query_urlhaus_url("https://example.com")
    malwoverview_tools._query_urlhaus_host("example.com")

    assert captured[0][2] == {"Auth-Key": test_key}
    assert captured[1][2] == {"Auth-Key": test_key}
    assert captured[2][2] == {"Auth-Key": test_key}

    captured.clear()
    monkeypatch.setattr(malwoverview_tools, "_API_KEYS", {})
    malwoverview_tools._query_malwarebazaar_hash("a" * 64)
    malwoverview_tools._query_urlhaus_url("https://example.com")
    malwoverview_tools._query_urlhaus_host("example.com")
    assert captured[0][2] is None
    assert captured[1][2] is None
    assert captured[2][2] is None


def test_feodo_parser_list_of_dicts(monkeypatch):
    requested = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        return json.dumps([
            {"ip_address": "198.51.100.10", "port": 443},
            {"ip_address": "203.0.113.10", "port": 8080},
        ])

    monkeypatch.setattr(
        malwoverview_tools,
        "_http_get",
        fake_get,
    )

    result = malwoverview_tools._query_feodo_tracker_ip("203.0.113.10")

    assert result["found"] is True
    assert result["matches"][0]["port"] == 8080
    assert requested == [
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
    ]


def test_feodo_parser_real_captured_error_shape(monkeypatch):
    captured_shape = {"error": "HTTP Error 404: Not Found"}
    monkeypatch.setattr(
        malwoverview_tools,
        "_http_get",
        lambda *args, **kwargs: json.dumps(captured_shape),
    )

    result = malwoverview_tools._query_feodo_tracker_ip("203.0.113.10")

    assert "error" in result
    assert "404" in result["error"]
    assert result["source"] == "feodo_tracker"


def test_crtsh_uses_working_url_and_preserves_http_error(monkeypatch):
    requested = []

    def fake_get(url, timeout=25):
        requested.append(url)
        return json.dumps({"error": "HTTP Error 404: Not Found"})

    monkeypatch.setattr(free_osint_tools, "_http_get", fake_get)
    result = free_osint_tools.crtsh_subdomain_search("example.com")

    assert "q=%.example.com" in requested[0]
    assert "404" in result["error"]
    assert "crt.sh unavailable" not in result["error"]


def test_subdomain_retries_dict_response_once(monkeypatch):
    responses = [
        json.dumps({"error": "HTTP Error 502: Bad Gateway"}),
        json.dumps([{"name_value": "www.example.com"}]),
    ]
    calls = []

    def fake_request(url, timeout=20):
        calls.append((url, timeout))
        return responses.pop(0)

    sleeps = []
    monkeypatch.setattr(osint_tools.time, "sleep", sleeps.append)
    monkeypatch.setattr(osint_tools, "_safe_request", fake_request)

    result = json.loads(osint_tools.subdomain_enumerate("example.com"))

    assert result["subdomains"] == ["www.example.com"]
    assert len(calls) == 2
    assert sleeps == [2]


def test_malpedia_list_shape(monkeypatch):
    monkeypatch.setattr(
        free_osint_tools,
        "_http_get",
        lambda *args, **kwargs: json.dumps(["lockbit", "emotet"]),
    )

    result = free_osint_tools.malpedia_malware_search("lockbit")

    assert result["total_families"] == 2
    assert result["match_count"] == 1
    assert result["matches"][0]["family"] == "lockbit"


def test_malpedia_dict_shape(monkeypatch):
    monkeypatch.setattr(
        free_osint_tools,
        "_http_get",
        lambda *args, **kwargs: json.dumps({
            "lockbit": {
                "alt_names": ["LockBit"],
                "description": "ransomware",
                "urls": ["https://example.com"],
            }
        }),
    )

    result = free_osint_tools.malpedia_malware_search("lockbit")

    assert result["total_families"] == 1
    assert result["match_count"] == 1
    assert result["matches"][0]["description"] == "ransomware"
