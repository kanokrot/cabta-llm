"""Small, best-effort IP country lookup helper."""

import ipaddress
import json
import logging
import re
from functools import lru_cache
from typing import Optional
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


def _is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return False
    return parsed.is_global and not any((
        parsed.is_private,
        parsed.is_loopback,
        parsed.is_link_local,
        parsed.is_reserved,
        parsed.is_multicast,
        parsed.is_unspecified,
    ))


@lru_cache(maxsize=1024)
def _lookup_public_ip_country(ip: str):
    # ip-api.com free tier is HTTP-only, limited to about 45 requests/minute,
    # and intended for non-commercial use.
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode"
    try:
        request = Request(url, headers={"User-Agent": "BlueTeamAssistant/1.0"})
        with urlopen(request, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("status") != "success":
            return None
        code = payload.get("countryCode")
        if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z]{2}", code):
            return None
        return code.upper()
    except Exception:
        logger.debug("IP country lookup failed for %s", ip, exc_info=True)
        return None


def lookup_ip_country(ip: str) -> Optional[str]:
    """Return an uppercase ISO-style two-letter country code, or ``None``.

    Non-public addresses are rejected before any network call.
    """
    if not isinstance(ip, str) or not _is_public_ip(ip):
        return None
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
        return _lookup_public_ip_country(normalized_ip)
    except Exception:
        logger.debug("IP country lookup failed for invalid input", exc_info=True)
        return None
