"""
intelligent_scoring.py
Author: Ugur AtesIntelligent threat scoring system."""

from typing import Dict
import logging
from ..integrations.threat_intel import GROUP_B_EXCLUDE

logger = logging.getLogger(__name__)

# Production IOC scoring admits only the six sources below.  The numeric
# values are derived from the seven-source AHP analysis documented in
# docs/source_weight_ahp_derivation_2026-09-16.md.  VirusTotal remains
# report-only because it has not passed the separate availability/evidence
# admission gate.
SOURCE_SCORING_MULTIPLIERS = {
    "feodotracker": 1.500000,
    "c2_trackers": 0.442818,
    "spamhaus": 0.695930,
    "tor_exit_nodes": 0.542480,
    "sslblacklist": 0.878018,
    "threatfox": 0.339610,
}
NON_API_SCORING_SOURCES = frozenset(SOURCE_SCORING_MULTIPLIERS)

class IntelligentScoring:
    """
    Context-aware threat scoring.
    
    Combines multiple factors:
    - Threat intel sources (40%)
    - File analysis (30%)
    - Behavioral indicators (20%)
    - Context (10%)
    """
    
    @staticmethod
    def _get_source_score(source_data: Dict) -> int:
        """
        Extract score from various response formats.
        Different APIs return scores in different formats.
        """
        if not isinstance(source_data, dict):
            return 0
        
        status = source_data.get('status', '')
        
        # Not flagged = 0 score
        if status not in ['✓', '✓ FLAGGED', 'FLAGGED', 'flagged']:
            return 0
        
        # Direct score field
        if 'score' in source_data:
            score = source_data['score']
            if isinstance(score, (int, float)):
                return int(score)
        
        # IPQualityScore format
        if 'fraud_score' in source_data:
            return int(source_data['fraud_score'])
        
        # AbuseIPDB format
        if 'confidence' in source_data:
            return int(source_data['confidence'])
        
        # VirusTotal - detections format
        if 'detections' in source_data:
            detections = source_data['detections']
            if isinstance(detections, str) and '/' in detections:
                try:
                    malicious, total = detections.split('/')
                    ratio = int(malicious) / int(total) if int(total) > 0 else 0
                    return int(ratio * 100)
                except:
                    pass
        
        # GreyNoise classification
        if 'classification' in source_data:
            classification = source_data['classification'].lower()
            if 'malicious' in classification:
                return 90
            elif 'suspicious' in classification:
                return 60
            elif 'unknown' in classification:
                return 30
        
        # Shodan - calculate from findings
        if 'ports' in source_data or 'vulns' in source_data:
            score = 20  # Base score for "found"
            vulns = source_data.get('vulns', [])
            if isinstance(vulns, list) and len(vulns) > 0:
                score += min(40, len(vulns) * 10)
            tags = source_data.get('tags', [])
            if isinstance(tags, list):
                if any(tag in ['malware', 'botnet', 'tor', 'c2'] for tag in tags):
                    score += 50
            return min(100, score)
        
        # FeodoTracker - botnet info
        if 'botnet' in source_data:
            return 85  # Known botnet C2
        
        # Spamhaus - listed
        if 'listed' in source_data:
            if source_data['listed']:
                return 80
        
        # Default for flagged sources without explicit score
        if status in ['✓', '✓ FLAGGED', 'FLAGGED']:
            return 50  # Default score for flagged
        
        return 0
    
    @staticmethod
    def calculate_ioc_score(intel_results: Dict) -> int:
        """
        Calculate IOC threat score.

        Combines threat intelligence source scores.

        Args:
            intel_results: Results from threat intelligence sources

        Returns:
            Threat score (0-100)
        """
        sources = intel_results.get('sources', {})

        if not sources:
            return 0

        # Weight different sources.
        # รายชื่อ source ในแต่ละ tier ต้อง sync กับ investigate_ioc_comprehensive()
        # ใน threat_intel.py เสมอ — เพิ่ม/ลบ source ใหม่ต้องอัปเดตทั้งสองที่พร้อมกัน
        # (พบ mismatch 9 รายการเมื่อ 2026-09-13 ดู CABTA_scope_ledger.md)
        weighted_scores = []

        # These lists preserve the operational source group inventory used by
        # accounting/tests.  Arithmetic uses SOURCE_SCORING_MULTIPLIERS so
        # AHP-derived source-specific values are not collapsed into legacy
        # 1.5/1.0/0.5 tier constants.
        high_confidence_sources = [
            'feodotracker'
        ]

        medium_confidence_sources = [
            'c2_trackers', 'spamhaus', 'tor_exit_nodes', 'sslblacklist'
        ]

        low_confidence_sources = [
            'threatfox'
        ]

        tier_sources = (
            set(high_confidence_sources)
            | set(medium_confidence_sources)
            | set(low_confidence_sources)
        )
        if tier_sources != NON_API_SCORING_SOURCES:
            raise RuntimeError(
                "IOC scoring tier definitions are out of sync with the non-API policy"
            )

        group_a_sources_flagged = 0
        for source_name, source_data in sources.items():
            source_name_lower = source_name.lower()
            # API/API-key/query sources, VirusTotal, CIRCL, untiered feeds,
            # and unknown sources are report-only under the current design.
            if source_name_lower not in NON_API_SCORING_SOURCES:
                continue

            # An unavailable source is not a clean result and must not enter
            # this round's score.  In particular, ThreatFox timeout handling
            # marks the source unavailable instead of falling back to stale
            # cache data.
            if not isinstance(source_data, dict) or source_data.get('unavailable') is True:
                continue

            if isinstance(source_data, dict) and source_data.get('status') in [
                '✓', '✓ FLAGGED', 'FLAGGED', 'flagged'
            ]:
                group_a_sources_flagged += 1

            score = IntelligentScoring._get_source_score(source_data)

            if score > 0:
                weighted_scores.append(
                    score * SOURCE_SCORING_MULTIPLIERS[source_name_lower]
                )

        if not weighted_scores:
            base_score = 0
        else:
            # Calculate weighted average
            base_score = sum(weighted_scores) / len(weighted_scores)

            # Boost score if multiple sources flagged
            if group_a_sources_flagged >= 3:
                base_score = min(100, base_score * 1.3)  # 30% boost for 3+ flagged
            elif group_a_sources_flagged >= 2:
                base_score = min(100, base_score * 1.15)  # 15% boost for 2 flagged

        return max(0, min(100, int(base_score)))

    @staticmethod
    def calculate_source_coverage(intel_results: Dict) -> Dict:
        """Classify source availability independently from threat scoring."""
        coverage = {
            "sources_flagged": 0,
            "sources_clean": 0,
            "sources_unavailable": 0,
            "sources_stale": 0,
            "total_sources_attempted": 0,
            "sources_skipped_not_applicable": 0,
            "group_a": {
                "sources_flagged": 0,
                "sources_clean": 0,
                "sources_unavailable": 0,
                "sources_stale": 0,
                "total_sources_attempted": 0,
                "sources_skipped_not_applicable": 0,
            },
            "group_b": {
                "sources_flagged": 0,
                "sources_clean": 0,
                "sources_unavailable": 0,
                "sources_stale": 0,
                "total_sources_attempted": 0,
                "sources_skipped_not_applicable": 0,
            },
        }

        sources = intel_results.get('sources', {})
        if not isinstance(sources, dict):
            return coverage

        for source_name, source_data in sources.items():
            if not isinstance(source_data, dict):
                continue

            group = (
                coverage["group_b"]
                if source_name.lower() in GROUP_B_EXCLUDE
                else coverage["group_a"]
            )

            status = str(source_data.get('status', '')).strip()
            reason = str(
                source_data.get('error') or source_data.get('message') or ''
            ).strip().lower()
            if (
                source_data.get('not_applicable') is True
                or status == '➖'
                or reason == 'not applicable'
            ):
                group["sources_skipped_not_applicable"] += 1
                continue

            group["total_sources_attempted"] += 1
            is_cached = source_data.get('cached') is True

            if source_data.get('status') == '⚠' and not is_cached:
                group["sources_unavailable"] += 1
                continue

            if is_cached:
                group["sources_stale"] += 1

            score = IntelligentScoring._get_source_score(source_data)
            if score > 0:
                group["sources_flagged"] += 1
            else:
                group["sources_clean"] += 1

        # Keep Group A/B coverage visible separately for transparent, auditable CTI
        # reporting. Admiralty/MISP distinguishes source reliability from the
        # credibility of the information, so Group B is not deleted as evidence;
        # it is retained as supplemental context outside the verdict denominator.
        for metric in coverage["group_a"]:
            coverage[metric] = coverage["group_a"][metric]

        return coverage
    
    @staticmethod
    def calculate_file_score(file_data: Dict = None, hash_score: int = 0, ioc_results: list = None, file_analysis: Dict = None, intel_score: int = None) -> int:
        """
        Calculate composite file threat score.
        
        Scoring breakdown:
        - Hash reputation: 40%
        - Static analysis: 40%
        - Embedded IOC analysis: 20%
        
        Args:
            file_data: File analysis data (new signature)
            hash_score: Score from hash reputation checking (new signature)
            ioc_results: List of IOC investigation results from file (new signature)
            file_analysis: Legacy parameter for backward compatibility
            intel_score: Legacy parameter for backward compatibility
        
        Returns:
            Composite threat score (0-100)
        """
        # Handle legacy signature
        if file_analysis is not None and intel_score is not None:
            file_data = file_analysis
            hash_score = intel_score
        
        if file_data is None:
            file_data = {}
        
        # Hash reputation (40% weight)
        score = hash_score * 0.4
        
        # Static analysis factors (40% weight)
        file_factors = 0
        
        # logger.info(f"[SCORING] file_data keys: {list(file_data.keys())}")
        
        # ==================== SCRIPT-SPECIFIC SCORING ====================
        # Check for suspicious string categories (PowerShell, VBS, etc.)
        string_categories = file_data.get('suspicious_string_categories', [])
        # logger.info(f"[SCORING] string_categories: {string_categories}")
        if string_categories:
            # Convert to uppercase for comparison
            string_categories_upper = [cat.upper() if isinstance(cat, str) else str(cat).upper() for cat in string_categories]
            
            # logger.info(f"[SCORING] string_categories_upper: {string_categories_upper}")
            
            # Critical categories - ANY of these = high risk
            critical_cats = ['CRYPTO', 'PERSISTENCE', 'NETWORK', 'OBFUSCATION', 'EXECUTION', 'EVASION', 'DISABLE_SECURITY']
            medium_cats = ['REGISTRY', 'FILE_OPS', 'PROCESS', 'CREDENTIAL', 'DOWNLOAD']
            
            critical_count = sum(1 for cat in string_categories_upper if cat in critical_cats)
            medium_count = sum(1 for cat in string_categories_upper if cat in medium_cats)
            
            # logger.info(f"[SCORING] critical_count: {critical_count}, medium_count: {medium_count}")
            
            # More aggressive scoring for scripts
            if critical_count >= 3:
                file_factors += 50  # Max score for highly malicious scripts
            elif critical_count >= 2:
                file_factors += 40  # Multiple critical indicators
            elif critical_count >= 1:
                file_factors += 30  # At least one critical indicator
            elif medium_count >= 3:
                file_factors += 25
            elif medium_count >= 1:
                file_factors += 15
            
            # logger.info(f"[SCORING] After string categories, file_factors: {file_factors}")
        
        # Check for suspicious indicators
        indicators = file_data.get('suspicious_indicators', [])
        if indicators:
            file_factors += min(40, len(indicators) * 8)
        
        # Check for unsigned files (PE only)
        signature = file_data.get('signature', {})
        if signature and not signature.get('signed'):
            file_factors += 15
        
        # Check for high entropy (packing)
        sections = file_data.get('sections', [])
        for section in sections:
            if section.get('suspicious'):
                file_factors += 20
                break
        
        # Check for suspicious APIs/imports
        imports = file_data.get('imports', [])
        suspicious_dlls = ['ws2_32.dll', 'wininet.dll', 'urlmon.dll']
        for imp in imports:
            if imp.get('dll', '').lower() in suspicious_dlls:
                file_factors += 15
                break
        
        # Check obfuscation
        obfuscation = file_data.get('obfuscation', {})
        if obfuscation.get('likely_obfuscated'):
            file_factors += 20
        
        # Check YARA severity (already boosted in main analyzer, but check here too)
        yara_severity = file_data.get('yara_severity', 'NONE')
        if yara_severity == 'CRITICAL':
            file_factors += 40
        elif yara_severity == 'MEDIUM':
            file_factors += 20
        
        # ==================== SCRIPT-SPECIFIC BOOST ====================
        # Add script analysis boost if available
        script_boost = file_data.get('script_score_boost', 0)
        if script_boost > 0:
            # logger.info(f"[SCORING] Adding script_score_boost: {script_boost}")
            file_factors += script_boost
        
        # Check suspicious_apis directly (from ScriptAnalyzer)
        suspicious_apis = file_data.get('suspicious_apis', [])
        if suspicious_apis and script_boost == 0:  # Only if not already boosted
            # logger.info(f"[SCORING] suspicious_apis found: {suspicious_apis}")
            file_factors += min(30, len(suspicious_apis) * 10)
        
        score += min(100, file_factors) * 0.4  # Increased cap from 40 to 100
        
        # logger.info(f"[SCORING] After file_factors, total score: {score}")
        
        # Embedded IOC analysis (20% weight)
        if ioc_results:
            ioc_score = 0
            malicious_count = sum(1 for r in ioc_results if r.get('verdict') == 'MALICIOUS')
            suspicious_count = sum(1 for r in ioc_results if r.get('verdict') == 'SUSPICIOUS')
            
            if malicious_count > 0:
                ioc_score = 100  # Any malicious IOC = max score
            elif suspicious_count > 0:
                ioc_score = 70  # Suspicious IOCs
            else:
                # Check average threat score
                if ioc_results:
                    avg_threat_score = sum(r.get('threat_score', 0) for r in ioc_results) / len(ioc_results)
                    ioc_score = avg_threat_score
            
            score += ioc_score * 0.2
        
        return max(0, min(100, int(score)))
    
    @staticmethod
    def calculate_email_score(base_score: int, ioc_results: list, attachment_results: list) -> int:
        """
        Calculate composite email phishing score.
        
        v1.0.0: Base score weight increased because email-specific indicators
        (auth failures, SPAM flags, forensics) are already strong signals.
        
        Scoring breakdown:
        - Base email analysis: 70% (increased from 60%)
        - IOC analysis: 20% (decreased from 25%)
        - Attachment analysis: 10% (decreased from 15%)
        
        Args:
            base_score: Base email phishing score (0-100)
            ioc_results: List of IOC investigation results
            attachment_results: List of attachment analysis results
        
        Returns:
            Composite phishing score (0-100)
        """
        # Base email score (70% weight) - v1.0.0: increased
        score = base_score * 0.70
        
        # IOC analysis (20% weight)
        if ioc_results:
            ioc_score = 0
            malicious_count = sum(1 for r in ioc_results if r.get('verdict') == 'MALICIOUS')
            suspicious_count = sum(1 for r in ioc_results if r.get('verdict') == 'SUSPICIOUS')
            
            if malicious_count > 0:
                ioc_score = 100
            elif suspicious_count >= 2:
                ioc_score = 80
            elif suspicious_count == 1:
                ioc_score = 60
            else:
                avg_threat_score = sum(r.get('threat_score', 0) for r in ioc_results) / len(ioc_results) if ioc_results else 0
                ioc_score = avg_threat_score
            
            score += ioc_score * 0.20
        
        # Attachment analysis (10% weight)
        if attachment_results:
            attachment_score = 0
            malicious_count = sum(1 for r in attachment_results if r.get('verdict') == 'MALICIOUS')
            suspicious_count = sum(1 for r in attachment_results if r.get('verdict') == 'SUSPICIOUS')
            
            if malicious_count > 0:
                attachment_score = 100
            elif suspicious_count > 0:
                attachment_score = 75
            else:
                avg_threat_score = sum(r.get('threat_score', 0) for r in attachment_results) / len(attachment_results) if attachment_results else 0
                attachment_score = avg_threat_score
            
            score += attachment_score * 0.10
        
      
        # If the base score is high (for example, [SPAM] subject or DKIM FAIL),
        # the composite score should also remain high.
        if base_score >= 80:
            score = max(score, base_score * 0.85)  # En az %85'ini koru
        elif base_score >= 60:
            score = max(score, base_score * 0.75)  # En az %75'ini koru
        elif base_score >= 40:
            score = max(score, base_score * 0.65)  # En az %65'ini koru
        
        return max(0, min(100, int(score)))
