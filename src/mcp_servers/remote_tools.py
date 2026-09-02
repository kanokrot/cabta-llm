"""Read-only SSH collection tools with allowlist and host-key enforcement.

Every connection must match ``remote_hosts`` in ``config.yaml`` and pass
verification against the entry's dedicated ``known_hosts`` file.
"""

import ipaddress
import os
import socket
from pathlib import Path
from typing import Any

import paramiko
import yaml
from mcp.server.fastmcp import FastMCP


mcp = FastMCP("remote-tools")

_CONNECT_TIMEOUT_SECONDS = 10
_SYSTEM_INFO_COMMANDS = {
    "uname": "uname -a",
    "hostname": "hostname",
    "uptime": "uptime",
}
_PERSISTENCE_COMMANDS = {
    "cron_jobs": "crontab -l",
    "systemd_enabled": "systemctl list-unit-files --state=enabled",
    "rc_local": "cat /etc/rc.local",
}
_HIGH_CONFIDENCE_PERSISTENCE_KEYWORDS = (
    "nc -e",
    "/dev/tcp/",
    "bash -i",
    "mkfifo",
    "xmrig",
    "mimikatz",
)
_LOW_CONFIDENCE_PERSISTENCE_KEYWORDS = (
    "curl",
    "wget",
    "| sh",
    "| bash",
    "base64 -d",
    "base64 --decode",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
)
_TIME_RANGE_SINCE = {
    "last_1h": "1 hour ago",
    "last_24h": "24 hours ago",
    "last_7d": "7 days ago",
}


def _resolve_config_path() -> Path:
    """Return the configured YAML path, falling back to the project config."""
    project_root = Path(__file__).resolve().parent.parent.parent
    return Path(os.environ.get("BTA_CONFIG") or project_root / "config.yaml")


def _load_allowed_hosts() -> list[dict[str, Any]]:
    """Load remote-host allowlist entries from the project configuration."""
    try:
        with _resolve_config_path().open("r", encoding="utf-8") as config_file:
            config = yaml.safe_load(config_file) or {}
    except (OSError, yaml.YAMLError):
        return []

    remote_hosts = config.get("remote_hosts", [])
    if not isinstance(remote_hosts, list):
        return []
    return [entry for entry in remote_hosts if isinstance(entry, dict)]


def _error(message: str) -> dict[str, Any]:
    """Build a credential-safe error response."""
    return {"status": "error", "error": message, "data": None}


def _extract_ips_from_ss_output(raw_output: str) -> list[str]:
    """Extract unique, non-local peer IP addresses from ``ss`` output."""
    remote_ips: list[str] = []
    seen: set[str] = set()

    for line in raw_output.splitlines():
        columns = line.split()
        if len(columns) < 6 or columns[0].lower() == "netid":
            continue
        if columns[1].casefold() != "estab":
            continue

        peer_endpoint = columns[5]
        if peer_endpoint.startswith("[") and "]:" in peer_endpoint:
            address = peer_endpoint[1 : peer_endpoint.rfind("]:")]
        elif ":" in peer_endpoint:
            address = peer_endpoint.rsplit(":", 1)[0]
        else:
            continue

        address = address.split("%", 1)[0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue

        if parsed.is_unspecified or parsed.is_loopback:
            continue

        normalized = str(parsed)
        if normalized not in seen:
            seen.add(normalized)
            remote_ips.append(normalized)

    return remote_ips


def _detect_suspicious_persistence(
    commands_output: dict[str, dict],
) -> tuple[bool, list[dict]]:
    """Detect suspicious persistence indicators in collected command output."""
    findings = []
    seen: set[tuple[str, str]] = set()
    high_confidence_match = False
    low_confidence_matches = 0

    for source_command, command_result in commands_output.items():
        stdout = str(command_result.get("stdout", "")).casefold()
        for confidence, keywords in (
            ("high", _HIGH_CONFIDENCE_PERSISTENCE_KEYWORDS),
            ("low", _LOW_CONFIDENCE_PERSISTENCE_KEYWORDS),
        ):
            for keyword in keywords:
                match_count = stdout.count(keyword.casefold())
                if not match_count:
                    continue
                if confidence == "high":
                    high_confidence_match = True
                else:
                    low_confidence_matches += match_count

                dedupe_key = (keyword, source_command)
                if dedupe_key not in seen:
                    seen.add(dedupe_key)
                    findings.append({
                        "keyword": keyword,
                        "confidence": confidence,
                        "source_command": source_command,
                    })

    suspicious = high_confidence_match or low_confidence_matches >= 2
    return suspicious, findings


def _collect_remote_commands(
    host: str,
    username: str,
    key_path: str,
    port: int,
    commands: dict[str, str],
) -> dict[str, Any]:
    """Run read-only commands through the shared secured SSH workflow."""
    allowed_host = next(
        (
            entry
            for entry in _load_allowed_hosts()
            if entry.get("host") == host and entry.get("username") == username
        ),
        None,
    )
    if allowed_host is None:
        return _error("Host is not in the approved allowlist")

    client = paramiko.SSHClient()
    try:
        private_key = Path(key_path).expanduser()
        if not private_key.is_file():
            return _error("SSH private key file was not found")

        known_hosts = Path(str(allowed_host.get("known_hosts_path", ""))).expanduser()
        if not known_hosts.is_file():
            return _error("SSH known_hosts file was not found")

        client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            hostname=host,
            port=port,
            username=username,
            key_filename=str(private_key),
            look_for_keys=False,
            allow_agent=False,
            timeout=_CONNECT_TIMEOUT_SECONDS,
            auth_timeout=_CONNECT_TIMEOUT_SECONDS,
            banner_timeout=_CONNECT_TIMEOUT_SECONDS,
        )

        collected = {}
        for name, command in commands.items():
            _stdin, stdout, stderr = client.exec_command(
                command,
                timeout=_CONNECT_TIMEOUT_SECONDS,
            )
            collected[name] = {
                "stdout": stdout.read().decode("utf-8", errors="replace").strip(),
                "stderr": stderr.read().decode("utf-8", errors="replace").strip(),
                "exit_status": stdout.channel.recv_exit_status(),
            }
        return {"status": "success", "error": None, "data": collected}
    except paramiko.BadHostKeyException:
        return _error("Host key verification failed")
    except paramiko.AuthenticationException:
        return _error("SSH authentication failed")
    except socket.timeout:
        return _error("SSH connection timed out")
    except FileNotFoundError:
        return _error("SSH private key file was not found")
    except paramiko.SSHException:
        return _error("SSH connection failed")
    finally:
        client.close()


@mcp.tool()
def system_info_collect(
    host: str,
    username: str,
    key_path: str,
    port: int = 22,
) -> dict[str, Any]:
    """Collect system information from an allowlisted, host-key-pinned target.

    Args:
        host: Hostname or IP address, which must be on the allowlist.
        username: Remote SSH account name, which must match the allowlist.
        key_path: Local path to the SSH private key. Key contents are never
            logged or returned.
        port: SSH service port (default 22).
    """
    result = _collect_remote_commands(
        host, username, key_path, port, _SYSTEM_INFO_COMMANDS
    )
    if result["status"] == "error":
        return result
    return {
        "status": "success",
        "error": None,
        "data": {"host": host, "port": port, "system_info": result["data"]},
    }


@mcp.tool()
def process_list_collect(
    host: str,
    username: str,
    key_path: str,
    port: int = 22,
) -> dict[str, Any]:
    """Collect the process list from an allowlisted, host-key-pinned target.

    Args:
        host: Hostname or IP address, which must be on the allowlist.
        username: Remote SSH account name, which must match the allowlist.
        key_path: Local path to the SSH private key. Key contents are never
            logged or returned.
        port: SSH service port (default 22).
    """
    result = _collect_remote_commands(
        host, username, key_path, port, {"process_list": "ps aux"}
    )
    if result["status"] == "error":
        return result
    return {
        "status": "success",
        "error": None,
        "data": {"host": host, "port": port, "process_list": result["data"]["process_list"]},
    }


@mcp.tool()
def netstat_collect(
    host: str,
    username: str,
    key_path: str,
    port: int = 22,
) -> dict[str, Any]:
    """Collect network connections from an allowlisted, pinned target.

    Args:
        host: Hostname or IP address, which must be on the allowlist.
        username: Remote SSH account name, which must match the allowlist.
        key_path: Local path to the SSH private key. Key contents are never
            logged or returned.
        port: SSH service port (default 22).
    """
    result = _collect_remote_commands(
        host, username, key_path, port, {"network_connections": "ss -tanp"}
    )
    if result["status"] == "error":
        return result
    network_connections = result["data"]["network_connections"]
    remote_ips = _extract_ips_from_ss_output(network_connections["stdout"])
    network_connections["remote_ips"] = remote_ips
    return {
        "status": "success",
        "error": None,
        "remote_ips": remote_ips,
        "data": {
            "host": host,
            "port": port,
            "network_connections": network_connections,
        },
    }


@mcp.tool()
def event_log_collect(
    host: str,
    username: str,
    key_path: str,
    port: int = 22,
    time_range: str = "last_24h",
) -> dict[str, Any]:
    """Collect journal events from an allowlisted, host-key-pinned target.

    Args:
        host: Hostname or IP address, which must be on the allowlist.
        username: Remote SSH account name, which must match the allowlist.
        key_path: Local path to the SSH private key. Key contents are never
            logged or returned.
        port: SSH service port (default 22).
        time_range: Simple named range; unknown values default to 24 hours.
    """
    since = _TIME_RANGE_SINCE.get(time_range, "24 hours ago")
    command = f'journalctl --since "{since}" --no-pager'
    result = _collect_remote_commands(
        host, username, key_path, port, {"event_logs": command}
    )
    if result["status"] == "error":
        return result
    event_logs = result["data"]["event_logs"]
    raw_text = event_logs["stdout"]
    event_logs["raw_text"] = raw_text
    return {
        "status": "success",
        "error": None,
        "raw_text": raw_text,
        "data": {
            "host": host,
            "port": port,
            "event_logs": event_logs,
            "time_range": time_range,
        },
    }


@mcp.tool()
def autoruns_check(
    host: str,
    username: str,
    key_path: str,
    port: int = 22,
) -> dict[str, Any]:
    """Collect persistence mechanisms from an allowlisted, pinned target.

    Args:
        host: Hostname or IP address, which must be on the allowlist.
        username: Remote SSH account name, which must match the allowlist.
        key_path: Local path to the SSH private key. Key contents are never
            logged or returned.
        port: SSH service port (default 22).
    """
    result = _collect_remote_commands(
        host, username, key_path, port, _PERSISTENCE_COMMANDS
    )
    if result["status"] == "error":
        return result
    persistence_check = result["data"]
    suspicious, suspicious_findings = _detect_suspicious_persistence(
        persistence_check
    )
    persistence_check["suspicious"] = suspicious
    persistence_check["suspicious_findings"] = suspicious_findings
    return {
        "status": "success",
        "error": None,
        "suspicious": suspicious,
        "suspicious_findings": suspicious_findings,
        "data": {
            "host": host,
            "port": port,
            "persistence_check": persistence_check,
        },
    }


def main() -> None:
    """Run the remote tools MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
