"""Single source registry for the administrator settings page."""

from __future__ import annotations

from ..scoring.intelligent_scoring import NON_API_SCORING_SOURCES
from ..utils.api_key_validator import get_valid_key


_ENTRIES = (
    {
        "id": "threatfox",
        "label": "abuse.ch Auth-Key",
        "config_keys": ("threatfox", "abusech"),
        "tier": "scoring",
        "note": "Free Auth-Key required; scoring lookup uses a 15-second deadline.",
    },
    {
        "id": "virustotal",
        "label": "VirusTotal",
        "config_keys": ("virustotal",),
        "tier": "report",
        "note": "Listed free tier: 500 requests/day; local limit: 4 requests/minute.",
    },
    {"id": "abuseipdb", "label": "AbuseIPDB", "config_keys": ("abuseipdb",), "tier": "report", "note": "Free tier: 1,000 requests/day."},
    {"id": "shodan", "label": "Shodan", "config_keys": ("shodan",), "tier": "report", "note": "Free tier: 100 queries/month."},
    {"id": "alienvault", "label": "AlienVault OTX", "config_keys": ("alienvault",), "tier": "report", "note": "Free tier: unlimited."},
    {"id": "censys", "label": "Censys", "config_keys": ("censys",), "tier": "report", "note": "Single bearer token; enter one value."},
    {"id": "criminalip", "label": "Criminal IP", "config_keys": ("criminalip",), "tier": "report", "note": ""},
    {"id": "ipqualityscore", "label": "IPQualityScore", "config_keys": ("ipqualityscore",), "tier": "report", "note": "Free tier: 5,000 requests/month."},
    {"id": "phishtank", "label": "PhishTank", "config_keys": ("phishtank",), "tier": "report", "note": ""},
    {"id": "ip2proxy", "label": "IP2Proxy", "config_keys": ("ip2proxy",), "tier": "report", "note": ""},
    {"id": "greynoise", "label": "GreyNoise", "config_keys": ("greynoise",), "tier": "report", "note": "Free tier: 50 queries/day."},
    {"id": "pulsedive", "label": "Pulsedive", "config_keys": ("pulsedive",), "tier": "report", "note": ""},
    {"id": "threatzone", "label": "ThreatZone", "config_keys": ("threatzone",), "tier": "report", "note": ""},
    {"id": "triage", "label": "Triage", "config_keys": ("triage",), "tier": "sandbox", "note": "Free access is limited."},
    {"id": "hybrid_analysis", "label": "Hybrid Analysis", "config_keys": ("hybrid_analysis", "hybridanalysis"), "tier": "sandbox", "note": "Free tier: 100 searches/month."},
    {"id": "anyrun", "label": "ANY.RUN", "config_keys": ("anyrun",), "tier": "sandbox", "note": ""},
    {"id": "joe_sandbox", "label": "Joe Sandbox", "config_keys": ("joe_sandbox", "joesandbox"), "tier": "sandbox", "note": ""},
)


def settings_sources(api_keys: dict | None = None) -> list[dict]:
    """Return registry entries and status derived from valid configured keys."""
    api_keys = api_keys if isinstance(api_keys, dict) else {}
    validation_keys = {
        name: value if isinstance(value, str) else None
        for name, value in api_keys.items()
    }
    result = []
    for entry in _ENTRIES:
        item = dict(entry)
        item["config_keys"] = list(entry["config_keys"])
        if item["id"] in NON_API_SCORING_SOURCES:
            item["tier"] = "scoring"
        valid_keys = [get_valid_key(validation_keys, name) for name in item["config_keys"]]
        valid_key = next((key for key in valid_keys if key), None)
        item["configured"] = valid_key is not None
        item["masked_preview"] = (
            valid_key[:4] + ("•" * max(0, len(valid_key) - 4))
            if valid_key else ""
        )
        result.append(item)
    return result


def registered_config_keys() -> set[str]:
    return {key for entry in _ENTRIES for key in entry["config_keys"]}


def primary_config_key(config_key: str) -> str:
    """Resolve a registered primary or alias name to its write key."""
    for entry in _ENTRIES:
        if config_key in entry["config_keys"]:
            return entry["config_keys"][0]
    raise KeyError(config_key)
