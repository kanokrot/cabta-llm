"""
Author: Ugur Ates
Free threat feed integrations with caching.

Sources:
- USOM (Turkish national CERT) - JSON API with cached lookups, text-list fallback
- SSL Blacklist (abuse.ch) - CSV parsed into sets with TTL cache
- Smet NRD and HaGeZi NRD - domain lists with TTL cache
- MalwareBazaar recent SHA256 - text list with TTL cache

Notes:
- All outbound requests explicitly use certifi's CA bundle. On some Windows
  Python installs, aiohttp/asyncio's default SSL context does not pick up
  certifi automatically, which causes SSLCertVerificationError even after
  `pip install --upgrade certifi`. Passing an explicit ssl.SSLContext built
  from certifi.where() avoids that class of failure entirely.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import ssl
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import aiohttp
import certifi

logger = logging.getLogger(__name__)

# Build the SSL context once at import time and reuse it for every request.
_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


@dataclass
class FeedResult:
    """Normalized result shape returned by every feed check."""

    status: str  # '✓' found, '✗' not found, '⚠' error
    source: str
    found: bool
    score: int = 0
    message: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        d = {
            "status": self.status,
            "source": self.source,
            "found": self.found,
            "score": self.score,
            "message": self.message,
        }
        if self.error is not None:
            d["error"] = self.error
        return d


@dataclass
class _FeedCache:
    """Simple TTL cache holder for a set of indicators."""

    ttl_seconds: int
    last_update: float = 0.0
    data: Set[str] = field(default_factory=set)

    def is_stale(self) -> bool:
        return not self.data or (time.time() - self.last_update) >= self.ttl_seconds

    def mark_fresh(self) -> None:
        self.last_update = time.time()


def _is_ipv4(value: str) -> bool:
    octets = value.split(".")
    if len(octets) != 4:
        return False
    try:
        return all(0 <= int(o) <= 255 for o in octets)
    except ValueError:
        return False


class ThreatFeeds:
    """
    Free threat feed aggregator with in-memory caching.

    Feeds are downloaded once and cached for ``cache_ttl_seconds`` (default 1h).
    Subsequent lookups use the cached sets for fast O(1) membership testing.
    """

    DEFAULT_CACHE_TTL = 3600  # 1 hour

    USOM_API_URL = "https://siberguvenlik.gov.tr/api/address/index"
    USOM_URL_LIST = "https://www.usom.gov.tr/url-list.txt"
    USOM_IP_LIST = "https://www.usom.gov.tr/ip-list.txt"

    SSLBL_CERT_CSV = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
    SSLBL_IP_CSV = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"

    SMET_NRD_URL = "https://smet.cz/nrd/data/today.txt"
    HAGEZI_NRD_URL = "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt"
    MB_RECENT_SHA256_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"

    def __init__(self, config: Dict):
        self.config = config
        self.timeout = aiohttp.ClientTimeout(total=30)
        self._cache_ttl = config.get("timeouts", {}).get(
            "feed_cache_ttl", self.DEFAULT_CACHE_TTL
        )

        # USOM caches (URLs / IPs / domains kept separate since USOM tags them)
        self._usom_urls = _FeedCache(self._cache_ttl)
        self._usom_ips = _FeedCache(self._cache_ttl)
        self._usom_domains = _FeedCache(self._cache_ttl)

        # SSL Blacklist caches
        self._sslbl_sha1 = _FeedCache(self._cache_ttl)
        self._sslbl_ips = _FeedCache(self._cache_ttl)
        self._sslbl_ip_feed_deprecated = False

        # Static-list caches
        self._smet_nrd = _FeedCache(self._cache_ttl)
        self._hagezi_nrd = _FeedCache(self._cache_ttl)
        self._mb_recent_sha256 = _FeedCache(self._cache_ttl)

    # ------------------------------------------------------------------
    # Shared HTTP helpers
    # ------------------------------------------------------------------

    def _session(self) -> aiohttp.ClientSession:
        """Create a session that always verifies against the certifi CA bundle."""
        connector = aiohttp.TCPConnector(ssl=_SSL_CONTEXT)
        return aiohttp.ClientSession(timeout=self.timeout, connector=connector)

    async def _fetch_text(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.text()
                logger.warning(f"[fetch] {url} returned HTTP {resp.status}")
        except Exception as e:
            logger.warning(f"[fetch] {url} failed: {e}")
        return None

    async def _fetch_json(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict]:
        try:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    return await resp.json()
                logger.warning(f"[fetch] {url} returned HTTP {resp.status}")
        except Exception as e:
            logger.warning(f"[fetch] {url} failed: {e}")
        return None

    # ------------------------------------------------------------------
    # USOM
    # ------------------------------------------------------------------

    async def _refresh_usom_cache(self) -> None:
        """Download and parse USOM feed lists into sets (JSON API, then text-list fallback)."""
        if not self._usom_ips.is_stale():
            return

        logger.info("[USOM] Refreshing threat feed cache")
        async with self._session() as session:
            data = await self._fetch_json(session, self.USOM_API_URL)
            if data:
                self._parse_usom_json(data)
            else:
                logger.info("[USOM] JSON API unavailable, falling back to text lists")

            # Fallback / supplement: plain text lists
            for list_url, cache in (
                (self.USOM_URL_LIST, self._usom_urls),
                (self.USOM_IP_LIST, self._usom_ips),
            ):
                text = await self._fetch_text(session, list_url)
                if text:
                    for line in text.splitlines():
                        line = line.strip().lower()
                        if line and not line.startswith("#"):
                            cache.data.add(line)

        for cache in (self._usom_urls, self._usom_ips, self._usom_domains):
            cache.mark_fresh()

        total = len(self._usom_urls.data) + len(self._usom_ips.data) + len(self._usom_domains.data)
        logger.info(f"[USOM] Cache refreshed: {total} indicators loaded")

    def _parse_usom_json(self, data: Dict) -> None:
        models = data.get("models", []) if isinstance(data, dict) else []
        for entry in models:
            value = (entry.get("url") or entry.get("value") or "").strip().lower()
            if not value:
                continue
            ioc_type = entry.get("type", "")

            if ioc_type == "url" or "://" in value:
                self._usom_urls.data.add(value)
            elif ioc_type == "ip":
                self._usom_ips.data.add(value)
            elif ioc_type == "domain":
                self._usom_domains.data.add(value)
            else:
                # Unknown type: index under both IP and domain to be safe.
                self._usom_ips.data.add(value)
                self._usom_domains.data.add(value)

    async def check_usom(self, ioc: str) -> Dict:
        """Check one IOC through USOM's queryable API."""
        try:
            ioc_lower = ioc.strip().lower()
            if not ioc_lower:
                raise ValueError("empty IOC")

            if _is_ipv4(ioc_lower):
                ioc_type = "ip"
            elif "://" in ioc_lower:
                ioc_type = "url"
            else:
                ioc_type = "domain"

            async with self._session() as session:
                data = await self._fetch_json(
                    session,
                    self.USOM_API_URL,
                    params={"q": ioc_lower, "type": ioc_type, "per-page": "10"},
                )

            if not isinstance(data, dict) or not isinstance(data.get("models"), list):
                raise RuntimeError("USOM API returned an invalid response shape")

            found = any(
                isinstance(entry, dict)
                and str(entry.get("url") or entry.get("value") or "").strip().lower()
                == ioc_lower
                for entry in data["models"]
            )

            if found:
                return FeedResult(
                    status="✓",
                    source="USOM",
                    found=True,
                    score=85,
                    message="Found in USOM API",
                ).to_dict()

            return FeedResult(
                status="✗",
                source="USOM",
                found=False,
                message="Not found in USOM API",
            ).to_dict()

        except Exception as e:
            logger.error(f"[USOM] Error: {e}")
            return FeedResult(status="⚠", source="USOM", found=False, error=str(e)).to_dict()

    # ------------------------------------------------------------------
    # SSL Blacklist (abuse.ch)
    # ------------------------------------------------------------------

    async def _refresh_sslbl_cache(self) -> None:
        """Download and parse SSLBL CSVs into sets of SHA1 fingerprints and IPs."""
        if not self._sslbl_sha1.is_stale():
            return

        logger.info("[SSLBL] Refreshing SSL Blacklist cache")
        self._sslbl_sha1.data.clear()
        self._sslbl_ips.data.clear()
        self._sslbl_ip_feed_deprecated = False
        async with self._session() as session:
            cert_csv = await self._fetch_text(session, self.SSLBL_CERT_CSV)
            if cert_csv:
                self._parse_sslbl_cert_csv(cert_csv)

            ip_csv = await self._fetch_text(session, self.SSLBL_IP_CSV)
            if ip_csv:
                self._parse_sslbl_ip_csv(ip_csv)
                self._sslbl_ip_feed_deprecated = "deprecated" in ip_csv.lower()

        self._sslbl_sha1.mark_fresh()
        self._sslbl_ips.mark_fresh()
        logger.info(
            f"[SSLBL] Cache refreshed: {len(self._sslbl_sha1.data)} SHA1, "
            f"{len(self._sslbl_ips.data)} IPs"
        )

    def _parse_sslbl_cert_csv(self, text: str) -> None:
        # Format: Listingdate,SHA1,Listingreason
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                sha1 = parts[1].strip().lower()
                if len(sha1) == 40:
                    self._sslbl_sha1.data.add(sha1)
            if parts and _is_ipv4(parts[0].strip()):
                self._sslbl_ips.data.add(parts[0].strip())

    def _parse_sslbl_ip_csv(self, text: str) -> None:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for value in line.split(",")[:2]:
                ip = value.strip()
                if _is_ipv4(ip):
                    self._sslbl_ips.data.add(ip)

    async def check_ssl_blacklist(self, ioc: str) -> Dict:
        """
        Check IOC against SSL Blacklist (abuse.ch).

        Supports both SHA1 certificate fingerprints and IP addresses.
        """
        try:
            await self._refresh_sslbl_cache()
            ioc_lower = ioc.strip().lower()

            is_sha1 = len(ioc_lower) == 40 and all(c in "0123456789abcdef" for c in ioc_lower)
            if is_sha1 and not self._sslbl_sha1.data:
                return FeedResult(
                    status=chr(0x26A0),
                    source="SSL Blacklist",
                    found=False,
                    error="SSLBL certificate feed returned no usable SHA1 entries",
                ).to_dict()

            if is_sha1 and ioc_lower in self._sslbl_sha1.data:
                return FeedResult(
                    status="✓",
                    source="SSL Blacklist",
                    found=True,
                    score=90,
                    message="Certificate SHA1 found in SSLBL",
                ).to_dict()

            if _is_ipv4(ioc_lower) and self._sslbl_ip_feed_deprecated:
                return FeedResult(
                    status=chr(0x26A0),
                    source="SSL Blacklist",
                    found=False,
                    error="SSLBL IP feed is deprecated; certificate SHA1 feed remains available",
                ).to_dict()

            if _is_ipv4(ioc_lower) and not self._sslbl_ips.data:
                return FeedResult(
                    status=chr(0x26A0),
                    source="SSL Blacklist",
                    found=False,
                    error="SSLBL IP feed returned no usable IPv4 entries",
                ).to_dict()

            if ioc_lower in self._sslbl_ips.data:
                return FeedResult(
                    status="✓",
                    source="SSL Blacklist",
                    found=True,
                    score=85,
                    message="IP found in SSLBL C2 blacklist",
                ).to_dict()

            return FeedResult(
                status="✗",
                source="SSL Blacklist",
                found=False,
                message="Not found in SSL Blacklist",
            ).to_dict()

        except Exception as e:
            logger.error(f"[SSLBlacklist] Error: {e}")
            return FeedResult(
                status="⚠", source="SSL Blacklist", found=False, error=str(e)
            ).to_dict()

    # ------------------------------------------------------------------
    # Smet NRD
    # ------------------------------------------------------------------

    async def _refresh_smet_cache(self) -> None:
        """Download and cache the current Smet newly registered domains list."""
        if not self._smet_nrd.is_stale():
            return

        logger.info("[Smet NRD] Refreshing domain-list cache")
        async with self._session() as session:
            text = await self._fetch_text(session, self.SMET_NRD_URL)
            if text:
                self._smet_nrd.data = {
                    line.strip().lower().lstrip("\ufeff")
                    for line in text.splitlines()
                    if line.strip() and not line.strip().startswith(("#", "!"))
                }

        self._smet_nrd.mark_fresh()
        logger.info("[Smet NRD] Cache refreshed: %d domains", len(self._smet_nrd.data))

    async def check_smet_nrd(self, domain: str) -> Dict:
        """Check a domain against Smet newly registered domains."""
        try:
            await self._refresh_smet_cache()
            domain_lower = domain.strip().lower()
            found = domain_lower in self._smet_nrd.data
            return FeedResult(
                status="\u2713" if found else "\u2717",
                source="Smet NRD",
                found=found,
                score=85 if found else 0,
                message="Domain found in Smet NRD" if found else "Not found in Smet NRD",
            ).to_dict()
        except Exception as e:
            logger.error(f"[Smet NRD] Error: {e}")
            return FeedResult(
                status="\u26a0", source="Smet NRD", found=False, error=str(e)
            ).to_dict()

    # ------------------------------------------------------------------
    # HaGeZi NRD
    # ------------------------------------------------------------------

    async def _refresh_hagezi_cache(self) -> None:
        """Download and cache the current HaGeZi newly registered domains list."""
        if not self._hagezi_nrd.is_stale():
            return

        logger.info("[HaGeZi NRD] Refreshing domain-list cache")
        async with self._session() as session:
            text = await self._fetch_text(session, self.HAGEZI_NRD_URL)
            if text:
                self._hagezi_nrd.data = {
                    line.strip().lower().lstrip("\ufeff")
                    for line in text.splitlines()
                    if line.strip() and not line.strip().startswith(("#", "!"))
                }

        self._hagezi_nrd.mark_fresh()
        logger.info("[HaGeZi NRD] Cache refreshed: %d domains", len(self._hagezi_nrd.data))

    async def check_hagezi_nrd(self, domain: str) -> Dict:
        """Check a domain against HaGeZi newly registered domains."""
        try:
            await self._refresh_hagezi_cache()
            domain_lower = domain.strip().lower()
            found = domain_lower in self._hagezi_nrd.data
            return FeedResult(
                status="\u2713" if found else "\u2717",
                source="HaGeZi NRD",
                found=found,
                score=85 if found else 0,
                message="Domain found in HaGeZi NRD" if found else "Not found in HaGeZi NRD",
            ).to_dict()
        except Exception as e:
            logger.error(f"[HaGeZi NRD] Error: {e}")
            return FeedResult(
                status="\u26a0", source="HaGeZi NRD", found=False, error=str(e)
            ).to_dict()

    # ------------------------------------------------------------------
    # MalwareBazaar recent SHA256
    # ------------------------------------------------------------------

    async def _refresh_mb_recent_cache(self) -> None:
        """Download and cache MalwareBazaar's recent SHA256 export."""
        if not self._mb_recent_sha256.is_stale():
            return

        logger.info("[MalwareBazaar recent SHA256] Refreshing hash-list cache")
        async with self._session() as session:
            text = await self._fetch_text(session, self.MB_RECENT_SHA256_URL)
            if text:
                self._mb_recent_sha256.data = {
                    line.strip().lower().lstrip("\ufeff")
                    for line in text.splitlines()
                    if (
                        len(line.strip()) == 64
                        and all(c in "0123456789abcdefABCDEF" for c in line.strip())
                    )
                }

        self._mb_recent_sha256.mark_fresh()
        logger.info(
            "[MalwareBazaar recent SHA256] Cache refreshed: %d hashes",
            len(self._mb_recent_sha256.data),
        )

    async def check_mb_recent(self, hash_value: str) -> Dict:
        """Check a hash against MalwareBazaar's recent SHA256 export."""
        try:
            await self._refresh_mb_recent_cache()
            hash_lower = hash_value.strip().lower()
            found = hash_lower in self._mb_recent_sha256.data
            return FeedResult(
                status="\u2713" if found else "\u2717",
                source="MalwareBazaar recent SHA256",
                found=found,
                score=95 if found else 0,
                message=(
                    "SHA256 found in MalwareBazaar recent export"
                    if found else "Not found in MalwareBazaar recent export"
                ),
            ).to_dict()
        except Exception as e:
            logger.error(f"[MalwareBazaar recent SHA256] Error: {e}")
            return FeedResult(
                status="\u26a0",
                source="MalwareBazaar recent SHA256",
                found=False,
                error=str(e),
            ).to_dict()
