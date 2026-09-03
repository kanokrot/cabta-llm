"""Unit tests for the allowlisted, host-key-verified remote-tools server."""

import socket
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from src.mcp_servers.remote_tools import (
    _extract_ips_from_ss_output,
    autoruns_check,
    event_log_collect,
    netstat_collect,
    process_list_collect,
    system_info_collect,
)


def _command_result(stdout_text: str):
    stdin = MagicMock()
    stdout = MagicMock()
    stderr = MagicMock()
    stdout.read.return_value = stdout_text.encode("utf-8")
    stderr.read.return_value = b""
    stdout.channel.recv_exit_status.return_value = 0
    return stdin, stdout, stderr


def test_extract_ips_from_ss_output_returns_unique_remote_peers():
    raw_output = """\
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp ESTAB 0 0 10.0.0.5:22 198.51.100.20:54321 users:((\"sshd\",pid=10,fd=4))
tcp ESTAB 0 0 10.0.0.5:443 [2001:db8::25]:51000 users:((\"nginx\",pid=20,fd=7))
udp UNCONN 0 0 10.0.0.5:53 198.51.100.20:53000 users:((\"dns\",pid=30,fd=8))
"""

    assert _extract_ips_from_ss_output(raw_output) == [
        "198.51.100.20",
        "2001:db8::25",
    ]


def test_extract_ips_from_ss_output_filters_local_and_wildcard_peers():
    raw_output = """\
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=10,fd=3))
tcp ESTAB 0 0 127.0.0.1:5000 127.0.0.1:51000 users:((\"app\",pid=20,fd=4))
tcp LISTEN 0 128 [::]:443 [::]:* users:((\"nginx\",pid=30,fd=5))
tcp ESTAB 0 0 [::1]:5000 [::1]:51000 users:((\"app\",pid=40,fd=6))
"""

    assert _extract_ips_from_ss_output(raw_output) == []


def test_extract_ips_from_ss_output_uses_only_established_connections():
    raw_output = """\
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp LISTEN 0 128 0.0.0.0:22 203.0.113.99:40000 users:((\"sshd\",pid=10,fd=3))
tcp ESTAB 0 0 10.0.0.5:22 198.51.100.20:54321 users:((\"sshd\",pid=10,fd=4))
tcp TIME-WAIT 0 0 10.0.0.5:443 192.0.2.45:51000
"""

    assert _extract_ips_from_ss_output(raw_output) == ["198.51.100.20"]


def test_extract_ips_from_ss_output_returns_empty_for_listeners_only():
    raw_output = """\
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=10,fd=3))
tcp LISTEN 0 128 [::]:443 [::]:* users:((\"nginx\",pid=20,fd=5))
"""

    assert _extract_ips_from_ss_output(raw_output) == []


def test_extract_ips_from_ss_output_filters_established_local_peers():
    raw_output = """\
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp ESTAB 0 0 127.0.0.1:5000 127.0.0.1:51000 users:((\"app\",pid=20,fd=4))
tcp ESTAB 0 0 [::1]:5000 [::1]:51000 users:((\"app\",pid=30,fd=6))
tcp ESTAB 0 0 10.0.0.5:4000 0.0.0.0:* users:((\"odd\",pid=40,fd=7))
"""

    assert _extract_ips_from_ss_output(raw_output) == []


@pytest.mark.parametrize("raw_output", ["", "not valid ss output", "tcp ???"])
def test_extract_ips_from_ss_output_handles_empty_or_malformed(raw_output):
    assert _extract_ips_from_ss_output(raw_output) == []


@pytest.fixture(autouse=True)
def approved_test_host(monkeypatch, tmp_path):
    """Keep the six original scenarios approved by the new allowlist gate."""
    known_hosts = tmp_path / "known_hosts"
    key_file = tmp_path / "id_test"
    known_hosts.write_text("mock-known-host", encoding="utf-8")
    monkeypatch.setattr(
        "src.mcp_servers.remote_tools._load_allowed_hosts",
        lambda: [
            {
                "host": "192.0.2.10",
                "username": "analyst",
                "key_path": str(key_file),
                "known_hosts_path": str(known_hosts),
            }
        ],
    )
    return known_hosts


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_success(mock_ssh_client, tmp_path):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.exec_command.side_effect = [
        _command_result("Linux test-host 6.1.0"),
        _command_result("test-host"),
        _command_result("up 2 days"),
    ]

    result = system_info_collect("192.0.2.10", "analyst", str(key_file))

    assert result["status"] == "success"
    assert result["error"] is None
    assert result["data"]["system_info"]["hostname"]["stdout"] == "test-host"
    client.connect.assert_called_once_with(
        hostname="192.0.2.10",
        port=22,
        username="analyst",
        key_filename=str(key_file),
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
        auth_timeout=10,
        banner_timeout=10,
    )
    client.close.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_authentication_error(mock_ssh_client, tmp_path):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.connect.side_effect = paramiko.AuthenticationException("denied")

    result = system_info_collect("192.0.2.10", "analyst", str(key_file))

    assert result == {
        "status": "error",
        "error": "SSH authentication failed",
        "data": None,
    }
    client.close.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_connection_timeout(mock_ssh_client, tmp_path):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.connect.side_effect = socket.timeout("timed out")

    result = system_info_collect("192.0.2.10", "analyst", str(key_file))

    assert result == {
        "status": "error",
        "error": "SSH connection timed out",
        "data": None,
    }
    client.close.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_missing_key_does_not_connect(
    mock_ssh_client,
    monkeypatch,
    approved_test_host,
    tmp_path,
):
    missing_key = tmp_path / "missing-key"
    monkeypatch.setattr(
        "src.mcp_servers.remote_tools._load_allowed_hosts",
        lambda: [
            {
                "host": "192.0.2.10",
                "username": "analyst",
                "key_path": str(missing_key),
                "known_hosts_path": str(approved_test_host),
            }
        ],
    )
    client = mock_ssh_client.return_value

    result = system_info_collect("192.0.2.10", "analyst", str(missing_key))

    assert result == {
        "status": "error",
        "error": "SSH private key file was not found",
        "data": None,
    }
    client.connect.assert_not_called()
    client.close.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_closes_client_after_ssh_error(mock_ssh_client, tmp_path):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.connect.side_effect = paramiko.SSHException("transport failed")

    result = system_info_collect("192.0.2.10", "analyst", str(key_file))

    assert result["status"] == "error"
    assert result["error"] == "SSH connection failed"
    client.close.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_error_does_not_expose_credentials(
    mock_ssh_client,
    monkeypatch,
    approved_test_host,
    tmp_path,
):
    key_content = "TOP-SECRET-PRIVATE-KEY-CONTENT"
    key_file = tmp_path / "sensitive-key-name"
    key_file.write_text(key_content, encoding="utf-8")
    monkeypatch.setattr(
        "src.mcp_servers.remote_tools._load_allowed_hosts",
        lambda: [
            {
                "host": "192.0.2.10",
                "username": "analyst",
                "key_path": str(key_file),
                "known_hosts_path": str(approved_test_host),
            }
        ],
    )
    client = mock_ssh_client.return_value
    client.connect.side_effect = paramiko.AuthenticationException(
        f"bad credential {key_content} from {key_file}"
    )

    result = system_info_collect("192.0.2.10", "analyst", str(key_file))
    rendered = repr(result)

    assert key_content not in rendered
    assert str(key_file) not in rendered
    client.close.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_rejects_host_not_in_allowlist(
    mock_ssh_client,
    monkeypatch,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    monkeypatch.setattr(
        "src.mcp_servers.remote_tools._load_allowed_hosts",
        lambda: [],
    )

    result = system_info_collect("198.51.100.20", "analyst", str(key_file))

    assert result == {
        "status": "error",
        "error": "Host is not in the approved allowlist",
        "data": None,
    }
    mock_ssh_client.return_value.connect.assert_not_called()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_accepts_matching_pinned_key(
    mock_ssh_client,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.exec_command.side_effect = [
        _command_result("Linux test-host 6.1.0"),
        _command_result("test-host"),
        _command_result("up 2 days"),
    ]

    result = system_info_collect("192.0.2.10", "analyst", str(key_file))

    assert result["status"] == "success"
    client.connect.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_rejects_key_not_matching_pinned_credential(
    mock_ssh_client,
    tmp_path,
):
    caller_key = tmp_path / "different-key"
    caller_key.write_text("different-mock-private-key-content", encoding="utf-8")

    result = system_info_collect("192.0.2.10", "analyst", str(caller_key))

    assert result == {
        "status": "error",
        "error": "key_path does not match the pinned credential for this host",
        "data": None,
    }
    mock_ssh_client.assert_not_called()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_rejects_allowlist_entry_without_key_path(
    mock_ssh_client,
    monkeypatch,
    approved_test_host,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    monkeypatch.setattr(
        "src.mcp_servers.remote_tools._load_allowed_hosts",
        lambda: [
            {
                "host": "192.0.2.10",
                "username": "analyst",
                "known_hosts_path": str(approved_test_host),
            }
        ],
    )

    result = system_info_collect("192.0.2.10", "analyst", str(key_file))

    assert result == {
        "status": "error",
        "error": "No pinned key_path is configured for this host",
        "data": None,
    }
    mock_ssh_client.assert_not_called()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_missing_known_hosts_does_not_connect(
    mock_ssh_client,
    monkeypatch,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    missing_known_hosts = tmp_path / "missing-known-hosts"
    monkeypatch.setattr(
        "src.mcp_servers.remote_tools._load_allowed_hosts",
        lambda: [
            {
                "host": "192.0.2.10",
                "username": "analyst",
                "key_path": str(key_file),
                "known_hosts_path": str(missing_known_hosts),
            }
        ],
    )

    result = system_info_collect("192.0.2.10", "analyst", str(key_file))

    assert result == {
        "status": "error",
        "error": "SSH known_hosts file was not found",
        "data": None,
    }
    mock_ssh_client.return_value.connect.assert_not_called()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_uses_known_hosts_and_reject_policy(
    mock_ssh_client,
    approved_test_host,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.exec_command.side_effect = [
        _command_result("Linux test-host 6.1.0"),
        _command_result("test-host"),
        _command_result("up 2 days"),
    ]

    result = system_info_collect("192.0.2.10", "analyst", str(key_file))

    assert result["status"] == "success"
    client.load_host_keys.assert_called_once_with(str(approved_test_host))
    policy = client.set_missing_host_key_policy.call_args.args[0]
    assert isinstance(policy, paramiko.RejectPolicy)
    client.connect.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_system_info_collect_reports_bad_host_key(
    mock_ssh_client,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.connect.side_effect = paramiko.BadHostKeyException(
        "192.0.2.10",
        MagicMock(),
        MagicMock(),
    )

    result = system_info_collect("192.0.2.10", "analyst", str(key_file))

    assert result == {
        "status": "error",
        "error": "Host key verification failed",
        "data": None,
    }
    client.close.assert_called_once()


@pytest.mark.parametrize(
    ("tool", "kwargs", "command", "data_key", "output"),
    [
        (process_list_collect, {}, "ps aux", "process_list", "root 1 init"),
        (netstat_collect, {}, "ss -tanp", "network_connections", "LISTEN 0 128"),
        (
            event_log_collect,
            {"time_range": "last_24h"},
            'journalctl --since "24 hours ago" --no-pager',
            "event_logs",
            "systemd: Started service",
        ),
    ],
    ids=["process-list", "netstat", "event-log"],
)
@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_collection_tools_success(
    mock_ssh_client,
    tool,
    kwargs,
    command,
    data_key,
    output,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.exec_command.return_value = _command_result(output)

    result = tool("192.0.2.10", "analyst", str(key_file), **kwargs)

    assert result["status"] == "success"
    assert result["error"] is None
    assert result["data"]["host"] == "192.0.2.10"
    assert result["data"]["port"] == 22
    assert result["data"][data_key]["stdout"] == output
    client.exec_command.assert_called_once_with(command, timeout=10)
    client.close.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_netstat_collect_includes_parsed_remote_ips(mock_ssh_client, tmp_path):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    ss_output = """\
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=10,fd=3))
tcp LISTEN 0 128 10.0.0.5:8080 203.0.113.99:40000 users:(("app",pid=15,fd=5))
tcp ESTAB 0 0 10.0.0.5:22 198.51.100.20:54321 users:(("sshd",pid=10,fd=4))
tcp ESTAB 0 0 [2001:db8::5]:443 [2001:db8::25]:51000 users:(("nginx",pid=20,fd=7))
"""
    client.exec_command.return_value = _command_result(ss_output)

    result = netstat_collect("192.0.2.10", "analyst", str(key_file))

    expected = ["198.51.100.20", "2001:db8::25"]
    assert result["remote_ips"] == expected
    assert result["data"]["network_connections"]["remote_ips"] == expected
    assert "203.0.113.99" not in result["remote_ips"]
    assert result["data"]["network_connections"]["stdout"] == ss_output.strip()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_event_log_collect_exposes_raw_text_alias(mock_ssh_client, tmp_path):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.exec_command.return_value = _command_result("sshd accepted publickey")

    result = event_log_collect("192.0.2.10", "analyst", str(key_file))

    event_logs = result["data"]["event_logs"]
    assert result["raw_text"] == event_logs["stdout"]
    assert event_logs["raw_text"] == event_logs["stdout"]


@pytest.mark.parametrize(
    "tool",
    [process_list_collect, netstat_collect, event_log_collect],
    ids=["process-list", "netstat", "event-log"],
)
@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_collection_tools_reject_host_not_in_allowlist(
    mock_ssh_client,
    tool,
    monkeypatch,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    monkeypatch.setattr(
        "src.mcp_servers.remote_tools._load_allowed_hosts",
        lambda: [],
    )

    result = tool("198.51.100.20", "analyst", str(key_file))

    assert result == {
        "status": "error",
        "error": "Host is not in the approved allowlist",
        "data": None,
    }
    mock_ssh_client.assert_not_called()
    mock_ssh_client.return_value.connect.assert_not_called()


@pytest.mark.parametrize(
    "tool",
    [process_list_collect, netstat_collect, event_log_collect],
    ids=["process-list", "netstat", "event-log"],
)
@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_collection_tools_authentication_error_closes_client(
    mock_ssh_client,
    tool,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.connect.side_effect = paramiko.AuthenticationException("denied")

    result = tool("192.0.2.10", "analyst", str(key_file))

    assert result == {
        "status": "error",
        "error": "SSH authentication failed",
        "data": None,
    }
    client.close.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_autoruns_check_success_no_findings(mock_ssh_client, tmp_path):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.exec_command.side_effect = [
        _command_result("no crontab for analyst"),
        _command_result("sshd.service enabled\nsystemd-journald.service enabled"),
        _command_result(""),
    ]

    result = autoruns_check("192.0.2.10", "analyst", str(key_file))

    assert result["status"] == "success"
    assert result["error"] is None
    assert result["suspicious"] is False
    assert result["suspicious_findings"] == []
    persistence = result["data"]["persistence_check"]
    assert persistence["suspicious"] is False
    assert persistence["suspicious_findings"] == []
    client.close.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_autoruns_check_detects_high_confidence_single_match(
    mock_ssh_client,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.exec_command.side_effect = [
        _command_result("@reboot mkfifo named-pipe"),
        _command_result("sshd.service enabled"),
        _command_result(""),
    ]

    result = autoruns_check("192.0.2.10", "analyst", str(key_file))

    assert result["suspicious"] is True
    assert result["suspicious_findings"] == [
        {
            "keyword": "mkfifo",
            "confidence": "high",
            "source_command": "cron_jobs",
        }
    ]


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_autoruns_check_low_confidence_requires_two_matches(
    mock_ssh_client,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.exec_command.side_effect = [
        _command_result("@daily curl https://example.invalid/health"),
        _command_result("sshd.service enabled"),
        _command_result(""),
    ]

    one_match = autoruns_check("192.0.2.10", "analyst", str(key_file))

    assert one_match["suspicious"] is False
    assert one_match["suspicious_findings"] == [
        {
            "keyword": "curl",
            "confidence": "low",
            "source_command": "cron_jobs",
        }
    ]

    client.exec_command.side_effect = [
        _command_result("@daily curl https://example.invalid/health"),
        _command_result("custom.service enabled from /tmp/custom.service"),
        _command_result(""),
    ]

    two_matches = autoruns_check("192.0.2.10", "analyst", str(key_file))

    assert two_matches["suspicious"] is True
    assert two_matches["suspicious_findings"] == [
        {
            "keyword": "curl",
            "confidence": "low",
            "source_command": "cron_jobs",
        },
        {
            "keyword": "/tmp/",
            "confidence": "low",
            "source_command": "systemd_enabled",
        },
    ]


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_autoruns_check_rejects_host_not_in_allowlist(
    mock_ssh_client,
    monkeypatch,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    monkeypatch.setattr(
        "src.mcp_servers.remote_tools._load_allowed_hosts",
        lambda: [],
    )

    result = autoruns_check("198.51.100.20", "analyst", str(key_file))

    assert result == {
        "status": "error",
        "error": "Host is not in the approved allowlist",
        "data": None,
    }
    mock_ssh_client.assert_not_called()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_autoruns_check_authentication_error(mock_ssh_client, tmp_path):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    client.connect.side_effect = paramiko.AuthenticationException("denied")

    result = autoruns_check("192.0.2.10", "analyst", str(key_file))

    assert result == {
        "status": "error",
        "error": "SSH authentication failed",
        "data": None,
    }
    client.close.assert_called_once()


@patch("src.mcp_servers.remote_tools.paramiko.SSHClient")
def test_autoruns_check_tolerates_individual_command_failure(
    mock_ssh_client,
    tmp_path,
):
    key_file = tmp_path / "id_test"
    key_file.write_text("mock-private-key-content", encoding="utf-8")
    client = mock_ssh_client.return_value
    failed_crontab = _command_result("")
    failed_crontab[2].read.return_value = b"no crontab for analyst"
    failed_crontab[1].channel.recv_exit_status.return_value = 1
    client.exec_command.side_effect = [
        failed_crontab,
        _command_result("sshd.service enabled"),
        _command_result(""),
    ]

    result = autoruns_check("192.0.2.10", "analyst", str(key_file))

    assert result["status"] == "success"
    cron_jobs = result["data"]["persistence_check"]["cron_jobs"]
    assert cron_jobs == {
        "stdout": "",
        "stderr": "no crontab for analyst",
        "exit_status": 1,
    }
    assert result["data"]["persistence_check"]["systemd_enabled"]["stdout"] == (
        "sshd.service enabled"
    )
