"""
OSINT Tools MCP Server - Open-source intelligence gathering via MCP.

Tools: WHOIS, DNS, GeoIP, reverse DNS, domain age, email validation,
       subdomain enumeration, HTTP header analysis, SSL certificate info.

No API keys required - uses free public services and Python stdlib.

Usage:
    python -m src.mcp_servers.osint_tools
"""

import json
import subprocess
import logging
import re
import socket
import ssl
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import _dns_helper

logger = logging.getLogger(__name__)

mcp = FastMCP("osint-tools")


def _safe_request(url: str, timeout: int = 10) -> str:
    """Make a safe HTTP GET request."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BlueTeamAssistant/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def whois_lookup(target: str) -> str:
    """Perform WHOIS lookup for a domain or IP address.

    Args:
        target: Domain name or IP address to look up
    """
    target = target.strip().lower()

    # Determine WHOIS server
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        whois_server = "whois.arin.net"
    else:
        # Try to get WHOIS server from IANA
        tld = target.rsplit(".", 1)[-1] if "." in target else target
        whois_server_map = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "info": "whois.afilias.net",
            "io": "whois.nic.io",
            "dev": "whois.nic.google",
            "app": "whois.nic.google",
            "xyz": "whois.nic.xyz",
            "me": "whois.nic.me",
            "co": "whois.nic.co",
            "uk": "whois.nic.uk",
            "de": "whois.denic.de",
            "ru": "whois.tcinet.ru",
            "cn": "whois.cnnic.cn",
            "tr": "whois.nic.tr",
        }
        whois_server = whois_server_map.get(tld, f"whois.nic.{tld}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((whois_server, 43))
        sock.sendall((target + "\r\n").encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        text = response.decode("utf-8", errors="replace")

        # Parse key fields
        result = {
            "target": target,
            "whois_server": whois_server,
            "raw": text[:5000],
        }

        # Extract common fields
        for field_name, patterns in {
            "registrar": [r"Registrar:\s*(.+)", r"registrar:\s*(.+)"],
            "creation_date": [r"Creation Date:\s*(.+)", r"created:\s*(.+)", r"Registered on:\s*(.+)"],
            "expiry_date": [r"Registry Expiry Date:\s*(.+)", r"Expiry Date:\s*(.+)", r"expires:\s*(.+)"],
            "name_servers": [r"Name Server:\s*(.+)"],
            "status": [r"Status:\s*(.+)", r"Domain Status:\s*(.+)"],
            "registrant_org": [r"Registrant Organization:\s*(.+)"],
            "registrant_country": [r"Registrant Country:\s*(.+)"],
        }.items():
            values = []
            for pattern in patterns:
                values.extend(re.findall(pattern, text, re.IGNORECASE))
            if values:
                result[field_name] = values if len(values) > 1 else values[0]

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": f"WHOIS lookup failed: {e}", "target": target})


@mcp.tool()
def dns_resolve(domain: str, record_types: str = "A,AAAA,MX,NS,TXT,CNAME") -> str:
    """Resolve DNS records for a domain.

    Args:
        domain: Domain name to resolve
        record_types: Comma-separated DNS record types to query
    """
    domain = domain.strip().lower()
    results = {"domain": domain, "records": {}}
    requested = [rtype.strip().upper() for rtype in record_types.split(",") if rtype.strip()]
    resolver_labels = []

    if _dns_helper.dns_available():
        queried = _dns_helper.resolve_many(domain, requested)
        for rtype, query in queried:
            resolver_labels.append(query.resolver)
            if query.answers:
                results["records"][rtype] = query.answers
            elif query.status == "error":
                results["records"][rtype] = {"error": query.error or "DNS query failed"}
    else:
        # Preserve the original socket/nslookup path when dnspython is absent.
        try:
            ips = socket.getaddrinfo(domain, None)
            ipv4 = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET))
            ipv6 = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET6))
            if ipv4 and "A" in requested:
                results["records"]["A"] = ipv4
            if ipv6 and "AAAA" in requested:
                results["records"]["AAAA"] = ipv6
        except socket.gaierror as e:
            if "A" in requested:
                results["records"]["A"] = {"error": str(e)}

        for rtype in requested:
            if rtype in ("A", "AAAA"):
                continue
            try:
                result = subprocess.run(
                    ["nslookup", "-type=" + rtype, domain],
                    capture_output=True, text=True, timeout=10
                )
                output = result.stdout
                records = []
                for line in output.split("\n"):
                    line = line.strip()
                    if rtype == "MX" and "mail exchanger" in line.lower():
                        records.append(line.split("=")[-1].strip() if "=" in line else line)
                    elif rtype == "NS" and "nameserver" in line.lower():
                        records.append(line.split("=")[-1].strip() if "=" in line else line)
                    elif rtype == "TXT" and ('"' in line or "text" in line.lower()):
                        records.append(line.strip('"').strip())
                    elif rtype == "CNAME" and "canonical name" in line.lower():
                        records.append(line.split("=")[-1].strip() if "=" in line else line)
                if records:
                    results["records"][rtype] = records
            except Exception as e:
                results["records"][rtype] = {"error": str(e)}
        resolver_labels.append("nslookup")

    results["resolver"] = _dns_helper.combine_resolvers(resolver_labels)
    return json.dumps(results, indent=2)


@mcp.tool()
def geoip_lookup(ip: str) -> str:
    """Look up geographic location and ASN information for an IP address.
    Uses free ip-api.com service (no API key needed, 45 req/min limit).

    Args:
        ip: IPv4 or IPv6 address to look up
    """
    ip = ip.strip()
    try:
        data = _safe_request(f"http://ip-api.com/json/{ip}?fields=66846719")
        result = json.loads(data)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"GeoIP lookup failed: {e}", "ip": ip})


@mcp.tool()
def reverse_dns(ip: str) -> str:
    """Perform reverse DNS lookup for an IP address.

    Args:
        ip: IP address to reverse-resolve
    """
    ip = ip.strip()
    if _dns_helper.dns_available():
        query = _dns_helper.resolve_ptr(ip)
        if query.answers:
            return json.dumps({
                "ip": ip,
                "hostname": query.answers[0],
                "aliases": [],
                "addresses": [ip],
                "resolver": query.resolver,
            }, indent=2)
        if query.status in ("nxdomain", "noanswer"):
            return json.dumps({
                "ip": ip,
                "hostname": None,
                "error": query.error or "No PTR record found",
                "resolver": query.resolver,
            }, indent=2)
        return json.dumps({
            "ip": ip,
            "error": query.error or "PTR lookup failed",
            "resolver": query.resolver,
        }, indent=2)

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)
        return json.dumps({
            "ip": ip,
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses,
            "resolver": "system",
        }, indent=2)
    except socket.herror as e:
        return json.dumps({"ip": ip, "hostname": None, "error": str(e), "resolver": "system"})
    except Exception as e:
        return json.dumps({"ip": ip, "error": str(e), "resolver": "system"})


@mcp.tool()
def ssl_certificate_info(host: str, port: int = 443) -> str:
    """Retrieve and analyze SSL/TLS certificate for a host.

    Args:
        host: Hostname to check
        port: Port number (default 443)
    """
    host = host.strip().lower()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        result = {
            "host": host,
            "port": port,
            "tls_version": version,
            "cipher_suite": cipher[0] if cipher else None,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [
                entry[1] for entry in cert.get("subjectAltName", [])
            ],
        }

        # Check expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                from email.utils import parsedate_to_datetime
                expiry = parsedate_to_datetime(not_after)
                now = datetime.now(timezone.utc)
                days_left = (expiry - now).days
                result["days_until_expiry"] = days_left
                result["expired"] = days_left < 0
            except Exception:
                pass

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": f"SSL check failed: {e}", "host": host})


@mcp.tool()
def http_headers(url: str) -> str:
    """Retrieve and analyze HTTP response headers for security assessment.

    Checks for: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    CORS, server info disclosure, cookie security flags.

    Args:
        url: URL to check (http:// or https://)
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "BlueTeamAssistant/2.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = dict(resp.headers)
            status = resp.status

        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "X-XSS-Protection": headers.get("X-XSS-Protection"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy"),
        }

        # Assess security posture
        issues = []
        if not security_headers["Strict-Transport-Security"]:
            issues.append("Missing HSTS header")
        if not security_headers["Content-Security-Policy"]:
            issues.append("Missing CSP header")
        if not security_headers["X-Frame-Options"]:
            issues.append("Missing X-Frame-Options (clickjacking risk)")
        if not security_headers["X-Content-Type-Options"]:
            issues.append("Missing X-Content-Type-Options")
        if headers.get("Server"):
            issues.append(f"Server header discloses: {headers['Server']}")

        return json.dumps({
            "url": url,
            "status": status,
            "all_headers": headers,
            "security_headers": {k: v for k, v in security_headers.items() if v},
            "missing_security_headers": [k for k, v in security_headers.items() if not v],
            "security_issues": issues,
            "score": f"{sum(1 for v in security_headers.values() if v)}/7",
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"HTTP header check failed: {e}", "url": url})


@mcp.tool()
def subdomain_enumerate(domain: str) -> str:
    """Enumerate subdomains using certificate transparency logs (crt.sh).
    Free service, no API key needed.
    Args:
        domain: Base domain to enumerate subdomains for
    """
    domain = domain.strip().lower()
    try:
        data = _safe_request(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        entries = json.loads(data)
        if not isinstance(entries, list):
            if isinstance(entries, dict):
                time.sleep(2)
                retry_data = _safe_request(
                    f"https://crt.sh/?q=%.{domain}&output=json", timeout=20
                )
                try:
                    retry_entries = json.loads(retry_data)
                except json.JSONDecodeError:
                    return json.dumps({
                        "error": (
                            "Unexpected response format from crt.sh after one retry "
                            f"(non-JSON; keys={list(entries)[:20]}; "
                            f"response={retry_data[:200]})"
                        ),
                        "domain": domain,
                    })
                if isinstance(retry_entries, list):
                    entries = retry_entries
                else:
                    return json.dumps({
                        "error": (
                            "Unexpected response format from crt.sh after one retry "
                            f"(expected list, got {type(retry_entries).__name__}; "
                            f"keys={list(retry_entries)[:20] if isinstance(retry_entries, dict) else []}; "
                            f"response={retry_data[:200]})"
                        ),
                        "domain": domain,
                    })
            else:
                return json.dumps({
                    "error": f"Unexpected response format from crt.sh (expected list, got {type(entries).__name__})",
                    "domain": domain,
                })
        subdomains = set()
        skipped_malformed = 0
        for entry in entries:
            if not isinstance(entry, dict):
                skipped_malformed += 1
                continue
            name = entry.get("name_value", "")
            for sub in name.split(chr(10)):
                sub = sub.strip().lower()
                if sub and sub.endswith(domain) and "*" not in sub:
                    subdomains.add(sub)
        sorted_subs = sorted(subdomains)
        result_payload = {
            "domain": domain,
            "subdomain_count": len(sorted_subs),
            "subdomains": sorted_subs[:500],
            "source": "crt.sh (Certificate Transparency)",
        }
        if skipped_malformed:
            result_payload["warning"] = f"Skipped {skipped_malformed} malformed entries from crt.sh response"
        return json.dumps(result_payload, indent=2)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"crt.sh returned a non-JSON response, likely a service outage: {e}", "domain": domain})
    except Exception as e:
        return json.dumps({"error": f"Subdomain enumeration failed: {e}", "domain": domain})


def _legacy_dns_query_txt(name: str, timeout: int = 10) -> tuple[list[str], bool, str]:
    """Original nslookup TXT path used when dnspython is unavailable."""
    try:
        r = subprocess.run(
            ["nslookup", "-type=TXT", name],
            capture_output=True, text=True, timeout=timeout
        )
        stdout_lower = r.stdout.lower()
        failure_markers = ("timed out", "timed-out", "server failed", "can" + chr(39) + "t find")
        if r.returncode != 0 or any(marker in stdout_lower for marker in failure_markers):
            return [], False, "nslookup"
        return r.stdout.split(chr(10)), True, "nslookup"
    except Exception:
        return [], False, "nslookup"


def _dns_query_txt_result(name: str, timeout: int = 3) -> tuple[list[str], bool, str]:
    """Return TXT lines, whether the query completed, and resolver label."""
    if not _dns_helper.dns_available():
        return _legacy_dns_query_txt(name, timeout=timeout)
    query = _dns_helper.resolve_record(name, "TXT", timeout=timeout)
    if query.status in ("ok", "nxdomain", "noanswer"):
        return query.answers, True, query.resolver
    return [], False, query.resolver


def _dns_query_txt(name: str, timeout: int = 10) -> tuple[list[str], bool]:
    """Compatibility wrapper for callers that only need lines and success."""
    lines, ok, _resolver = _dns_query_txt_result(name, timeout=timeout)
    return lines, ok


@mcp.tool()
def email_security_check(domain: str) -> str:
    """Check email security configuration for a domain.
    Checks SPF, DKIM, DMARC records.
    Args:
        domain: Domain to check email security for
    """
    domain = domain.strip().lower()
    result = {"domain": domain, "checks": {}}

    query_names = {
        "SPF": domain,
        "DMARC": f"_dmarc.{domain}",
    }
    dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]
    for selector in dkim_selectors:
        query_names[f"DKIM:{selector}"] = f"{selector}._domainkey.{domain}"

    query_results = {}
    resolver_labels = []
    executor = ThreadPoolExecutor(max_workers=8)
    futures = {
        key: executor.submit(_dns_query_txt_result, name, 5 if key.startswith("DKIM:") else 3)
        for key, name in query_names.items()
    }
    deadline = time.monotonic() + 15.0
    try:
        for key in query_names:
            future = futures[key]
            remaining = max(0.0, deadline - time.monotonic())
            try:
                query_results[key] = future.result(timeout=remaining)
            except Exception:
                query_results[key] = ([], False, "system")
            resolver_labels.append(query_results[key][2])
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    lines, ok, _resolver = query_results["SPF"]
    if not ok:
        result["checks"]["SPF"] = {"found": None, "records": [], "error": "DNS query failed or timed out"}
    else:
        spf_records = [line.strip().strip(chr(34)) for line in lines if "v=spf1" in line.lower()]
        result["checks"]["SPF"] = {"found": bool(spf_records), "records": spf_records}

    lines, ok, _resolver = query_results["DMARC"]
    if not ok:
        result["checks"]["DMARC"] = {"found": None, "records": [], "error": "DNS query failed or timed out"}
    else:
        dmarc_records = [line.strip().strip(chr(34)) for line in lines if "v=dmarc1" in line.lower()]
        result["checks"]["DMARC"] = {"found": bool(dmarc_records), "records": dmarc_records}

    dkim_found = []
    dkim_query_failures = 0
    for selector in dkim_selectors:
        lines, ok, _resolver = query_results[f"DKIM:{selector}"]
        if not ok:
            dkim_query_failures += 1
            continue
        stdout_joined = chr(10).join(lines)
        if "v=dkim1" in stdout_joined.lower() or "p=" in stdout_joined:
            dkim_found.append(selector)
    if dkim_query_failures == len(dkim_selectors):
        result["checks"]["DKIM"] = {"found": None, "selectors_found": [], "error": "All DKIM selector queries failed or timed out"}
    else:
        result["checks"]["DKIM"] = {"found": bool(dkim_found), "selectors_found": dkim_found}

    issues = []
    if result["checks"]["SPF"].get("found") is False:
        issues.append("No SPF record found - email spoofing possible")
    elif result["checks"]["SPF"].get("found") is None:
        issues.append("SPF check inconclusive - DNS query failed")
    if result["checks"]["DMARC"].get("found") is False:
        issues.append("No DMARC record found - no email authentication policy")
    elif result["checks"]["DMARC"].get("found") is None:
        issues.append("DMARC check inconclusive - DNS query failed")
    if result["checks"]["DKIM"].get("found") is False:
        issues.append("No DKIM record found (checked common selectors)")
    elif result["checks"]["DKIM"].get("found") is None:
        issues.append("DKIM check inconclusive - DNS query failed")

    result["security_issues"] = issues
    checks_confirmed_found = sum(1 for c in result["checks"].values() if c.get("found") is True)
    checks_inconclusive = sum(1 for c in result["checks"].values() if c.get("found") is None)
    result["score"] = f"{checks_confirmed_found}/3"
    if checks_inconclusive:
        result["score_note"] = f"{checks_inconclusive}/3 checks inconclusive due to DNS query failures"

    result["resolver"] = _dns_helper.combine_resolvers(resolver_labels)
    return json.dumps(result, indent=2)


def main():
    """Run the OSINT tools MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
