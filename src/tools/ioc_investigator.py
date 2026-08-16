"""
Blue Team Assistant - IOC Investigation Tool

Multi-source threat intelligence lookup for IPs, domains, URLs, and hashes.

ioc_investigator.py
"""

import asyncio
from typing import Dict
import logging
from ..integrations.threat_intel import ThreatIntelligence
from ..integrations.llm_analyzer import LLMAnalyzer
from ..integrations.ticketing import create_incident_ticket
from ..utils.ioc_extractor import IOCExtractor
from ..utils.helpers import determine_verdict, extract_domain_from_url
from ..utils.domain_age_checker import check_domain_age
from ..utils.dga_detector import detect_dga
from ..scoring.intelligent_scoring import IntelligentScoring
from ..detection.rule_generator import RuleGenerator
from ..reporting.html_report_generator import HTMLReportGenerator
from ..rag.rag_knowledge_base import RAGKnowledgeBase, load_playbooks_from_yaml

logger = logging.getLogger(__name__)

# Trusted infrastructure - NEVER flag as malicious
TRUSTED_DOMAINS = {
    # Certificate Authorities
    'digicert.com', 'verisign.com', 'letsencrypt.org', 'comodo.com',
    'godaddy.com', 'globalsign.com', 'entrust.com', 'thawte.com',
    'geotrust.com', 'rapidssl.com', 'sectigo.com', 'comodoca.com',
    'usertrust.com', 'trustwave.com', 'symantec.com', 'pki.goog',
    # Microsoft
    'microsoft.com', 'windows.com', 'windowsupdate.com', 'azure.com',
    'msft.net', 'msn.com', 'live.com', 'office.com', 'office365.com',
    # Google
    'google.com', 'googleapis.com', 'gstatic.com', 'google-analytics.com',
    # CDNs
    'akamai.net', 'akamaiedge.net', 'cloudflare.com', 'fastly.net',
    'cloudfront.net', 'azureedge.net', 'edgecastcdn.net',
    # Other trusted
    'apple.com', 'mozilla.org', 'adobe.com',
}

class IOCInvestigator:
    """
    IOC Investigation Tool.
    
    Investigates IPs, domains, URLs, and hashes using 20+ threat intelligence sources.
    """
    
    def __init__(self, config: Dict):
        """Initialize IOC investigator."""
        self.config = config
        self.threat_intel = ThreatIntelligence(config)
        self.llm_analyzer = LLMAnalyzer(config)

        self.rag_kb = None
        if config.get('analysis', {}).get('enable_rag', True):
            try:
                self.rag_kb = RAGKnowledgeBase()
                self.rag_kb.seed(load_playbooks_from_yaml())
            except Exception as exc:
                logger.warning(f"[IOC] RAG knowledge base unavailable (non-fatal): {exc}")
                self.rag_kb = None
    
    def _is_trusted_infrastructure(self, ioc: str, ioc_type: str) -> bool:
        """Check if IOC belongs to trusted infrastructure."""
        ioc_lower = ioc.lower()
        
        if ioc_type == 'domain':
            for trusted in TRUSTED_DOMAINS:
                if ioc_lower == trusted or ioc_lower.endswith('.' + trusted):
                    return True
        elif ioc_type == 'url':
            for trusted in TRUSTED_DOMAINS:
                if trusted in ioc_lower:
                    return True
        
        return False
    
    async def _enrich_domain(self, domain: str) -> Dict:
        """
        Enrich domain IOC with age and DGA analysis.

        Args:
            domain: Domain name to analyze

        Returns:
            Enrichment dict with domain_age and dga_analysis keys
        """
        enrichment = {}

        # Domain age check
        try:
            age_result = await asyncio.to_thread(check_domain_age, domain)
            enrichment['domain_age'] = age_result
        except Exception as exc:
            logger.warning(f"[IOC] Domain age check failed (non-fatal): {exc}")
            enrichment['domain_age'] = {'error': str(exc)}

        # DGA detection
        try:
            dga_result = detect_dga(domain)
            enrichment['dga_analysis'] = dga_result
        except Exception as exc:
            logger.warning(f"[IOC] DGA detection failed (non-fatal): {exc}")
            enrichment['dga_analysis'] = {'error': str(exc)}

        return enrichment

    def _calculate_domain_score_bonus(self, enrichment: Dict) -> int:
        """
        Calculate threat score bonus from domain enrichment.

        Scoring rules:
        - Newly registered domain (< 30 days): +20
        - DGA detected (confidence >= 50): +30

        Args:
            enrichment: Domain enrichment results

        Returns:
            Score bonus (0-50)
        """
        bonus = 0

        # Domain age bonus
        domain_age = enrichment.get('domain_age', {})
        if domain_age.get('is_newly_registered'):
            bonus += 20
            logger.info("[IOC] +20 score: newly registered domain")

        # DGA detection bonus
        dga = enrichment.get('dga_analysis', {})
        if dga.get('is_dga'):
            bonus += 30
            logger.info(f"[IOC] +30 score: DGA detected (confidence={dga.get('confidence', 0)})")

        return bonus

    def _aggregate_seen_dates(self, sources: Dict) -> tuple:
        """Aggregate first_seen/last_seen across sources that report them.
        VirusTotal's last_analysis reflects VT's scan cadence, not confirmed
        IOC activity, so it's only used as a last-resort fallback for
        last_seen when no other source has activity data.
        Falls back to the first non-empty value found if date parsing fails.
        """
        from datetime import datetime
        import re

        FIRST_SEEN_SOURCES = ('feodotracker', 'threatfox', 'c2_trackers')
        LAST_SEEN_SOURCES = ('feodotracker', 'c2_trackers', 'greynoise')

        def _try_parse(s):
            if not s or not isinstance(s, str):
                return None
            s_clean = re.sub(r'\s*UTC\s*$', '', s.strip())
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    return datetime.strptime(s_clean, fmt)
                except ValueError:
                    continue
            return None

        def _pick(source_names, field):
            candidates = []
            for name in source_names:
                val = sources.get(name, {}).get(field)
                if val and val not in ('N/A', ''):
                    candidates.append(val)
            if not candidates:
                return None
            parsed = [(v, _try_parse(v)) for v in candidates]
            parsed_ok = [p for p in parsed if p[1] is not None]
            if not parsed_ok:
                return candidates[0]
            return (min if field == 'first_seen' else max)(parsed_ok, key=lambda p: p[1])[0]

        first_seen = _pick(FIRST_SEEN_SOURCES, 'first_seen')
        last_seen = _pick(LAST_SEEN_SOURCES, 'last_seen')

        if last_seen is None:
            vt_date = sources.get('virustotal', {}).get('last_analysis')
            if vt_date and vt_date not in ('N/A', ''):
                last_seen = vt_date

        return first_seen, last_seen

    async def investigate(self, ioc: str, analysis_id: str = None) -> Dict:
        """
        Investigate IOC.

        Args:
            ioc: Indicator to investigate

        Returns:
            Investigation results
        """
        logger.info(f"[IOC] Starting investigation: {ioc}")

        # Detect IOC type
        ioc_type = IOCExtractor.categorize_ioc(ioc)

        if ioc_type == 'unknown':
            return {'error': f'Unable to categorize IOC: {ioc}'}

        # Check if trusted infrastructure - skip heavy investigation
        if self._is_trusted_infrastructure(ioc, ioc_type):
            logger.info(f"[IOC] Skipping trusted infrastructure: {ioc}")
            return {
                'ioc': ioc,
                'ioc_type': ioc_type,
                'threat_score': 0,
                'verdict': 'CLEAN',
                'sources': {},
                'sources_checked': 0,
                'sources_flagged': 0,
                'note': 'Trusted infrastructure (Certificate Authority / CDN / Major vendor)',
                'recommendations': ['No action required - legitimate infrastructure'],
            }

        # Run threat intelligence checks
        intel_results = await self.threat_intel.investigate_ioc_comprehensive(ioc, ioc_type)

        # Calculate base threat score
        threat_score = IntelligentScoring.calculate_ioc_score(intel_results)

        # Domain enrichment (age + DGA) for domain and URL IOCs
        domain_enrichment = {}
        if ioc_type in ('domain', 'url'):
            target_domain = ioc if ioc_type == 'domain' else extract_domain_from_url(ioc)
            if target_domain:
                domain_enrichment = await self._enrich_domain(target_domain)
                # Apply domain-based score bonus
                domain_bonus = self._calculate_domain_score_bonus(domain_enrichment)
                if domain_bonus > 0:
                    threat_score = min(100, threat_score + domain_bonus)
                    logger.info(
                        f"[IOC] Domain enrichment bonus +{domain_bonus} "
                        f"-> adjusted score {threat_score}"
                    )

        verdict = determine_verdict(threat_score)

        # Sync updated threat_score to intel_results before LLM analysis
        intel_results["threat_score"] = threat_score
        first_seen, last_seen = self._aggregate_seen_dates(intel_results.get('sources', {}))

        # Retrieve relevant knowledge base entries (non-fatal, never affects verdict)
        rag_hits = []
        if self.rag_kb:
            try:
                rag_query_parts = [ioc_type, verdict, f"threat score {threat_score}"]
                dga = domain_enrichment.get('dga_analysis', {}) if domain_enrichment else {}
                domain_age = domain_enrichment.get('domain_age', {}) if domain_enrichment else {}
                if dga.get('is_dga'):
                    rag_query_parts.append('dga')
                if domain_age.get('is_newly_registered'):
                    rag_query_parts.append('newly_registered')
                rag_query = ' '.join(rag_query_parts)
                rag_hits = self.rag_kb.query(rag_query)
            except Exception as exc:
                logger.warning(f"[IOC] RAG query failed (non-fatal): {exc}")
                rag_hits = []

        # Get LLM analysis if enabled (non-blocking: failure is OK)
        llm_analysis = {}
        if self.config.get('analysis', {}).get('enable_llm', True):
            try:
                llm_analysis = await self.llm_analyzer.analyze_ioc_results(
                    ioc, ioc_type, intel_results, rag_context=rag_hits
                )
                if llm_analysis is None:
                    llm_analysis = {'note': 'LLM unavailable - results based on threat intelligence only'}
            except Exception as llm_err:
                logger.warning(f"[IOC] LLM analysis failed (non-fatal): {llm_err}")
                llm_analysis = {'note': f'LLM analysis failed: {llm_err}'}

        # Generate detection rules
        detection_rules = RuleGenerator.generate_ioc_rules(ioc, ioc_type, {'verdict': verdict})

        # Generate recommendations
        # Prioritize LLM-generated recommendations if they exist and are valid
        if llm_analysis and isinstance(llm_analysis.get('recommendations'), list) and llm_analysis['recommendations']:
            recommendations = llm_analysis['recommendations']
            logger.info("[IOC] Using dynamic LLM-generated recommendations.")
        else:
            # Fallback to the static, verdict-based list if LLM fails
            recommendations = self._generate_recommendations(verdict, intel_results)
            logger.info("[IOC] LLM recommendations unavailable, using static fallback list.")

        # Add domain-specific recommendations
        if domain_enrichment:
            domain_age = domain_enrichment.get('domain_age', {})
            dga = domain_enrichment.get('dga_analysis', {})
            if domain_age.get('is_newly_registered'):
                recommendations.insert(0, '🆕 Domain is newly registered (<30 days) - high risk indicator')
            if dga.get('is_dga'):
                family = dga.get('dga_family_guess', 'unknown')
                recommendations.insert(0, f'🤖 Domain appears algorithmically generated (DGA, family: {family})')

        result = {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'threat_score': threat_score,
            'verdict': verdict,
            # Standardized keys
            'sources': intel_results.get('sources', {}),  # Direct 'sources' key for consistency
            'sources_checked': intel_results.get('sources_checked', 0),
            'sources_flagged': intel_results.get('sources_flagged', 0),
            'first_seen': first_seen,
            'last_seen': last_seen,
            # Legacy compatibility aliases
            'threat_intel_results': intel_results.get('sources', {}),  # Backward compat
            'threat_intelligence': {
                'sources': intel_results.get('sources', {}),
                'sources_checked': intel_results.get('sources_checked', 0),
                'sources_flagged': intel_results.get('sources_flagged', 0)
            },
            # Domain enrichment (domain_age + DGA analysis)
            'domain_enrichment': domain_enrichment if domain_enrichment else None,
            'llm_analysis': llm_analysis,
            'detection_rules': detection_rules,
            'recommendations': recommendations,
            'rag_references': rag_hits
        }

        logger.info(f"[IOC] Investigation complete: {ioc} → {verdict} ({threat_score}/100)")

        # Create an incident ticket if the verdict is malicious or suspicious
        ticket_verdicts = self.config.get("ticketing", {}).get("create_on_verdict", ["MALICIOUS", "SUSPICIOUS"])
        if verdict in ticket_verdicts and analysis_id:
            try:
                create_incident_ticket(result, analysis_id)
            except Exception as e:
                logger.error(f"[IOC] Failed to create incident ticket: {e}")

        return result
    
    def _generate_recommendations(self, verdict: str, intel_results: Dict) -> list:
        """Generate action recommendations based on verdict."""
        if verdict == 'MALICIOUS':
            return [
                '🚨 Block IOC at firewall/proxy immediately',
                '🔍 Hunt for connections to this IOC in logs (last 30 days)',
                '💻 Isolate any affected hosts from network',
                '📋 Create incident ticket for IR team',
                '🔐 Reset credentials on affected systems'
            ]
        elif verdict == 'SUSPICIOUS':
            return [
                '⚠️ Add IOC to monitoring watchlist',
                '🔍 Review logs for any connections',
                '📊 Correlate with other suspicious activity',
                '👀 Monitor for additional indicators'
            ]
        elif verdict == 'CLEAN':
            return [
                '📝 Document finding',
                '👁️ Passive monitoring recommended',
                '✅ No immediate action required'
            ]
        else:  # UNKNOWN
            return [
                '❓ Insufficient data to determine risk',
                '📋 Document for reference'
            ]
    
    def generate_html_report(self, investigation_result: Dict, ioc: str, output_path: str):
        """Generate HTML report."""
        generator = HTMLReportGenerator()
        return generator.generate_ioc_report(investigation_result, ioc, output_path)
