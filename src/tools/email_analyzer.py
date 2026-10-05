"""
Author: Ugur AtesEmail Analysis Tool - SOC-GRADE with Advanced Features."""

import email
from email import policy
from email.utils import parseaddr
from html import unescape
from pathlib import Path
import asyncio
import re
import threading
import tempfile
import time
from typing import Dict, List
from urllib.parse import urlparse
import logging
from ..utils.ioc_extractor import IOCExtractor
from ..integrations.llm_analyzer import LLMAnalyzer
from ..scoring.intelligent_scoring import IntelligentScoring
from ..analyzers.advanced_email_analyzer import AdvancedEmailAnalyzer
from ..analyzers.email_forensics import EmailForensics  # NEW: DFIR-grade forensics
from ..analyzers.email_threat_indicators import EmailThreatIndicators  # Enhanced threat checks
from ..analyzers.bec_detector import BECDetector  # BEC detection
from ..detection.rule_generator import RuleGenerator
from ..reporting.raw_output_collector import RawOutputCollector
from ..integrations.ticketing import create_incident_ticket
from ..rag.rag_knowledge_base import RAGKnowledgeBase, load_playbooks_from_yaml

logger = logging.getLogger(__name__)

_CROSS_TOOL_LOCK = threading.Lock()
_CROSS_TOOL_LOCK_WAIT_SECONDS = 120.0
_IOC_STAGE_TIMEOUT_SECONDS = 60.0
_ATTACHMENT_STAGE_TIMEOUT_SECONDS = 120.0
_ATTACHMENT_SUFFIX_RE = re.compile(r'^\.[A-Za-z0-9]{1,10}$')

_EMAIL_INDICATOR_LABELS = {
    'spf_fail': 'SPF failure',
    'dkim_fail': 'DKIM failure',
    'dmarc_fail': 'DMARC failure',
    'header_anomaly': 'Header anomaly',
    'link_mismatch': 'Link mismatch',
    'lookalike_domain': 'Lookalike domain',
    'html_obfuscation': 'HTML obfuscation',
    'qr_code': 'QR code',
    'brand_impersonation': 'Brand impersonation',
    'mixed_script': 'Mixed-script text',
    'phishing_keyword': 'Phishing keyword',
    'return_path_mismatch': 'Return-Path mismatch',
    'suspicious_tld': 'Suspicious TLD',
    'threat_indicator_finding': 'Threat indicator finding',
    'bec_finding': 'BEC finding',
    'spam_header': 'Spam header',
    'forensics': 'Forensics finding',
}

_SUSPICIOUS_EMAIL_TLDS = (
    '.bid', '.xyz', '.top', '.win', '.click', '.loan',
    '.work', '.gq', '.tk', '.ml', '.ga', '.cf',
)


def _is_allowlisted_email_url(url: str) -> bool:
    """Return whether a URL host matches the shared IOC domain allowlist."""
    try:
        hostname = (urlparse(url).hostname or '').lower().rstrip('.')
    except ValueError:
        return False
    return any(
        hostname == allowed_domain
        or hostname.endswith(f'.{allowed_domain}')
        for allowed_domain in IOCExtractor.WHITELIST_DOMAINS
    )


def _append_capability_error(
    capability_errors: List[Dict],
    capability: str,
    status: str,
    message: str,
) -> None:
    """Add one safe, user-facing stage error without exposing internals."""
    if any(
        error.get('capability') == capability and error.get('status') == status
        for error in capability_errors
    ):
        return
    capability_errors.append({
        'capability': capability,
        'status': status,
        'message': message,
    })


def _dedupe_preserve_order(values: List[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        marker = str(value)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(value)
    return result


async def _acquire_cross_tool_lock() -> bool:
    """Wait asynchronously for the email cross-tool stage lock."""
    deadline = time.monotonic() + _CROSS_TOOL_LOCK_WAIT_SECONDS
    while True:
        if _CROSS_TOOL_LOCK.acquire(blocking=False):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        await asyncio.sleep(min(0.05, remaining))
class EmailAnalyzer:
    """
    SOC-GRADE Email Security Analysis Tool.
    
    Features:
    - Basic parsing & authentication (SPF/DKIM/DMARC)
    - **Advanced header analysis** (Received chain, Return-Path mismatch, Message-ID validation)
    - **Link-text mismatch detection** (phishing)
    - **Lookalike domain detection** (homograph, typosquatting)
    - **HTML obfuscation analysis** (hidden text, zero-size fonts, suspicious CSS)
    - **QR code detection** (modern phishing trend)
    - **Brand impersonation detection** (PayPal, Microsoft, Apple, Amazon, etc.)
    - **Email template fingerprinting** (campaign detection)
    - IOC extraction → Cross-tool integration
    - Attachment extraction → File analyzer integration
    - **Equal-weight indicator scoring** (IOC/attachment results remain supplemental)
    """
    
    def __init__(self, config: Dict):
        """Initialize email analyzer."""
        self.config = config
        self.llm_analyzer = LLMAnalyzer(config)
        self.advanced_analyzer = AdvancedEmailAnalyzer()
        self.bec_detector = BECDetector()

        self.rag_kb = None
        if config.get('analysis', {}).get('enable_rag', True):
            try:
                self.rag_kb = RAGKnowledgeBase()
                self.rag_kb.seed(load_playbooks_from_yaml())
            except Exception as exc:
                logger.warning(f"[EMAIL] RAG knowledge base unavailable (non-fatal): {exc}")
                self.rag_kb = None

        # Cross-tool integration (set by parent)
        self.ioc_investigator = None
        self.file_analyzer = None
    
    async def analyze(
        self, email_path: str, analysis_id: str = None, user_id: int = None,
    ) -> Dict:
        """
        Comprehensive email analysis with SOC-grade techniques.
        
        Args:
            email_path: Path to .eml file
        
        Returns:
            Comprehensive analysis results
        """
        logger.info(f"[EMAIL] Analyzing: {Path(email_path).name}")
        
        # Initialize Raw Output Collector
        raw_collector = RawOutputCollector()
        raw_collector.record_pipeline_step('init', 'email_analysis_start', 'started')
        capability_errors = []
        
        try:
            # Parse email
            with open(email_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            
            # ==================== BASIC EXTRACTION ====================
            email_data = await self._extract_email_data(msg)
            raw_collector.record_pipeline_step('parsing', 'basic_extraction', 'completed')
            
            # ==================== ADVANCED ANALYSIS ====================
            
            # 1. Advanced Header Analysis
            logger.info("[EMAIL] Performing advanced header analysis...")
            header_analysis = self.advanced_analyzer.analyze_headers(msg)
            
            # Capture headers for raw output
            raw_collector.capture_email_headers({
                'from': email_data.get('from', ''),
                'to': [email_data.get('to', '')],
                'subject': email_data.get('subject', ''),
                'date': email_data.get('date', ''),
                'message_id': email_data.get('message_id', ''),
                'reply_to': email_data.get('reply_to', ''),
                'return_path': email_data.get('return_path', ''),
                'received': header_analysis.get('received_chain', []),
                'x_headers': header_analysis.get('x_headers', {}),
                'raw': str(msg)[:5000]
            })
            raw_collector.record_pipeline_step('headers', 'header_analysis', 'completed')
            
            # 2. DFIR-Grade Email Forensics (NEW!)
            logger.info("[EMAIL] Performing DFIR-grade forensics...")
            forensics = EmailForensics.perform_full_forensics(
                msg, 
                email_data['from'],
                email_data.get('from_domain', '')
            )
            raw_collector.capture_forensics_results(forensics)
            raw_collector.record_pipeline_step('forensics', 'dfir_forensics', 'completed')
            
            # 3. Authentication Check
            email_data['spf'] = self._check_spf(msg)
            email_data['dkim'] = self._check_dkim(msg)
            email_data['dmarc'] = self._check_dmarc(msg)
            auth_presence = self._authentication_header_presence(msg)
            
            # Capture authentication results
            raw_collector.capture_authentication_results({
                'spf': {'result': email_data['spf']},
                'dkim': {'result': email_data['dkim']},
                'dmarc': {'result': email_data['dmarc']},
                'overall_pass': all(r.lower() == 'pass' for r in [email_data['spf'], email_data['dkim'], email_data['dmarc']] if r)
            })
            raw_collector.record_pipeline_step('auth', 'authentication_check', 'completed')
            
            # 3. Link-Text Mismatch Detection
            logger.info("[EMAIL] Detecting link-text mismatches...")
            link_mismatches = self.advanced_analyzer.detect_link_text_mismatch(email_data['body_html'])
            
            # 4. Lookalike Domain Detection
            logger.info("[EMAIL] Detecting lookalike domains...")
            all_domains = email_data['domains'] + [
                url.split('/')[2] if '//' in url else url 
                for url in email_data['urls']
            ]
            lookalike_domains = self.advanced_analyzer.detect_lookalike_domains(list(set(all_domains)))
            
            # 5. HTML Obfuscation Analysis
            logger.info("[EMAIL] Analyzing HTML obfuscation...")
            html_obfuscation = self.advanced_analyzer.analyze_html_obfuscation(email_data['body_html'])
            
            # 6. QR Code Detection
            logger.info("[EMAIL] Detecting QR codes...")
            qr_detection = self.advanced_analyzer.detect_qr_codes(
                email_data['body_html'], 
                email_data['attachments']
            )
            
            # 7. Brand Impersonation Detection
            logger.info("[EMAIL] Detecting brand impersonation...")
            brand_impersonation = self.advanced_analyzer.detect_brand_impersonation(
                email_data['from'],
                email_data['subject'],
                email_data['body_html'] + email_data['body_text'],
                all_domains
            )

            mixed_script = self.advanced_analyzer.detect_mixed_script(
                email_data.get('subject'),
                email_data.get('from'),
            )
            if not isinstance(mixed_script, dict):
                mixed_script = {
                    'found': False,
                    'fields': {'subject': [], 'display_name': []},
                    'count': 0,
                }
            
            # 8. Email Template Fingerprinting
            logger.info("[EMAIL] Fingerprinting email template...")
            template_fingerprint = self.advanced_analyzer.fingerprint_email_template(
                email_data['body_html'],
                email_data['subject']
            )
            
            # 9. Transfer forensics score to email_data for base scoring
            email_data['forensics_score'] = forensics.get('forensics_score', 0)
            logger.info(f"[EMAIL] Forensics risk score: {email_data['forensics_score']}/100")

            # 10. Enhanced Threat Indicator Checks (10 new checks)
            logger.info("[EMAIL] Running enhanced threat indicator checks...")
            threat_indicators = EmailThreatIndicators.run_all_checks(
                msg=msg,
                html_body=email_data['body_html'],
                body_text=email_data['body_text'],
                subject=email_data['subject'],
                from_address=email_data['from'],
                urls=email_data['urls'],
                attachments=email_data['attachments'],
                from_domain=email_data.get('from_domain', ''),
            )
            logger.info(
                f"[EMAIL] Threat indicators: {threat_indicators['checks_run']} checks, "
                f"severity={threat_indicators['overall_severity']}, "
                f"score_impact=+{threat_indicators['total_score_impact']}"
            )
            raw_collector.record_pipeline_step('threat_indicators', 'enhanced_checks', 'completed')

            # 11. BEC (Business Email Compromise) Detection
            logger.info("[EMAIL] Running BEC detection...")
            from_name, from_email_addr = parseaddr(email_data['from'])
            auth_results_header = msg.get('Authentication-Results', '')
            bec_email_data = {
                'from': email_data['from'],
                'reply_to': email_data.get('reply_to', ''),
                'subject': email_data['subject'],
                'body': email_data['body_text'],
                'display_name': from_name,
                'auth_results': auth_results_header,
            }
            bec_results = self.bec_detector.analyze(bec_email_data)
            logger.info(
                f"[EMAIL] BEC detection: score={bec_results['bec_score']}, "
                f"verdict={bec_results['verdict']}, "
                f"indicators={bec_results['indicator_count']}"
            )
            raw_collector.record_pipeline_step('bec_detection', 'bec_analysis', 'completed')

            # ==================== INDICATOR SCORING ====================
            indicator_summary = self._build_indicator_summary(
                email_data,
                header_analysis,
                link_mismatches,
                lookalike_domains,
                html_obfuscation,
                qr_detection,
                brand_impersonation,
                threat_indicators,
                bec_results,
                mixed_script,
                forensics=forensics,
                auth_presence=auth_presence,
            )
            base_score = self._calculate_base_phishing_score(
                email_data,
                header_analysis,
                link_mismatches,
                lookalike_domains,
                html_obfuscation,
                qr_detection,
                brand_impersonation,
                threat_indicators,
                bec_results,
                mixed_script,
                forensics=forensics,
                auth_presence=auth_presence,
                indicator_summary=indicator_summary,
            )
            
            # ==================== CROSS-TOOL INTEGRATION ====================
            
            # Investigate IOCs
            ioc_results = []
            if self.ioc_investigator:
                ioc_results = await self._investigate_iocs(email_data, capability_errors)
            else:
                _append_capability_error(
                    capability_errors,
                    'ioc_investigator',
                    'not_connected',
                    'IOC investigation is not connected for this email.',
                )
            
            # Analyze attachments
            attachment_results = []
            if self.file_analyzer:
                attachment_results = await self._analyze_attachments(
                    msg, email_data, capability_errors
                )
            else:
                _append_capability_error(
                    capability_errors,
                    'file_analyzer',
                    'not_connected',
                    'Attachment scanning is not connected for this email.',
                )
            
            # The IOC and attachment stages remain visible as supplemental
            # evidence, but do not participate in the email indicator score.
            composite_score = base_score

            # Determine verdict from indicator states, not score thresholds.
            verdict = self._determine_indicator_verdict(indicator_summary)
            
            # ==================== LLM ANALYSIS ====================
            llm_analysis = {}
            rag_context = []
            if self.config.get('analysis', {}).get('enable_llm', True):
                if self.rag_kb:
                    try:
                        rag_query = (
                            f"phishing email {verdict} "
                            f"threat score {composite_score}"
                        )
                        rag_context = self.rag_kb.query(
                            rag_query,
                            category_filter='playbook',
                            max_distance=0.60,
                        )
                    except Exception as exc:
                        logger.warning(f"[EMAIL] RAG query failed (non-fatal): {exc}")
                        rag_context = []

                email_context = {
                    **email_data,
                    'header_anomalies': header_analysis.get('anomalies', []),
                    'link_mismatches': len(link_mismatches),
                    'lookalike_domains': lookalike_domains,
                    'html_obfuscation_score': html_obfuscation.get('risk_score', 0),
                    'qr_codes_found': qr_detection.get('qr_codes_found', 0),
                    'brand_impersonation': len(brand_impersonation),
                    'mixed_script_found': mixed_script.get('found', False),
                    'ioc_count': len(ioc_results),
                    'malicious_iocs': sum(1 for r in ioc_results if r.get('verdict') in ['MALICIOUS', 'SUSPICIOUS']),
                    'attachment_count': len(attachment_results),
                    'malicious_attachments': sum(1 for r in attachment_results if r.get('verdict') in ['MALICIOUS', 'SUSPICIOUS']),
                    'threat_indicator_severity': threat_indicators.get('overall_severity', 'NONE'),
                    'threat_indicator_score': threat_indicators.get('total_score_impact', 0),
                    'threat_indicator_active_checks': threat_indicators.get('active_checks', []),
                    'bec_score': bec_results.get('bec_score', 0),
                    'bec_verdict': bec_results.get('verdict', 'LOW'),
                    'bec_has_financial': bec_results.get('has_financial_indicators', False),
                    'bec_has_impersonation': bec_results.get('has_impersonation_indicators', False),
                    'base_score': base_score,
                    'composite_score': composite_score,
                    'forensics_score': forensics.get('forensics_score', 0),
                    'capability_errors': capability_errors,
                }
                llm_analysis = await self.llm_analyzer.analyze_email(
                    email_context,
                    rag_context=rag_context,
                )
            
            # ==================== FINAL RESULT ====================
            result = {
                'email_data': email_data,
                'advanced_analysis': {
                    'header_analysis': header_analysis,
                    'link_mismatches': link_mismatches,
                    'lookalike_domains': lookalike_domains,
                    'html_obfuscation': html_obfuscation,
                    'qr_detection': qr_detection,
                    'brand_impersonation': brand_impersonation,
                    'mixed_script': mixed_script,
                    'template_fingerprint': template_fingerprint,
                    'threat_indicators': threat_indicators,
                    'bec_analysis': bec_results,
                },
                'forensics': forensics,  # NEW: DFIR-grade forensics
                'indicator_summary': indicator_summary,
                'base_phishing_score': base_score,
                'composite_score': composite_score,
                'verdict': verdict,
                'ioc_analysis': {
                    'total_iocs': len(ioc_results),
                    'malicious_iocs': sum(1 for r in ioc_results if r.get('verdict') == 'MALICIOUS'),
                    'suspicious_iocs': sum(1 for r in ioc_results if r.get('verdict') == 'SUSPICIOUS'),
                    'results': ioc_results
                },
                'attachment_analysis': {
                    'total_attachments': len(attachment_results),
                    'malicious_attachments': sum(1 for r in attachment_results if r.get('verdict') == 'MALICIOUS'),
                    'suspicious_attachments': sum(1 for r in attachment_results if r.get('verdict') == 'SUSPICIOUS'),
                    'results': attachment_results
                },
                'capability_errors': capability_errors,
                'llm_analysis': llm_analysis,
                'rag_references': rag_context,
                'iocs_found': {
                    'urls': len(email_data['urls']),
                    'ips': len(email_data['ips']),
                    'domains': len(email_data['domains'])
                },
                'detection_rules': RuleGenerator.generate_email_rules({
                    'from': email_data.get('from', ''),
                    'subject': email_data.get('subject', ''),
                    'sender_domain': email_data.get('from', '').split('@')[-1].split('>')[0] if '@' in email_data.get('from', '') else '',
                    'urls': [
                        url for url in email_data.get('urls', [])
                        if not _is_allowlisted_email_url(url)
                    ][:5],
                    'malicious_iocs': [r.get('ioc') for r in ioc_results if r.get('verdict') == 'MALICIOUS'][:10]
                })
            }

            if 'ioc' not in result:
                result['ioc'] = email_data.get('from', 'unknown')
            
            # ==================== RAW OUTPUT CAPTURE ====================
            # Capture content
            raw_collector.capture_email_content({
                'text': email_data.get('body_text', '')[:5000],
                'html': email_data.get('body_html', '')[:10000],
                'urls': email_data.get('urls', []),
                'suspicious_keywords': [],
                'urgency': []
            })
            
            # Capture attachments
            raw_collector.capture_email_attachments(email_data.get('attachments', []))
            
            # Capture advanced analysis
            raw_collector.capture_advanced_analysis({
                'link_mismatches': link_mismatches,
                'lookalike_domains': lookalike_domains,
                'html_obfuscation': html_obfuscation,
                'qr_detection': qr_detection,
                'brand_impersonation': brand_impersonation,
                'mixed_script': mixed_script,
                'template_fingerprint': template_fingerprint,
                'threat_indicators': threat_indicators,
                'bec_analysis': bec_results,
            })

            # Capture IOC results
            raw_collector.capture_ioc_results(ioc_results)
            
            # Capture scoring
            raw_collector.capture_scoring_details({
                'composite': composite_score,
                'base_phishing': base_score,
                'indicator_summary': indicator_summary,
                'verdict': verdict
            })
            
            # Capture detection rules
            raw_collector.capture_detection_rules(result.get('detection_rules', {}))
            
            # Finalize
            raw_collector.finalize()
            
            # Add raw output to result
            result['raw_output'] = raw_collector.get_all_raw_data()
            
            logger.info(f"[EMAIL] Analysis complete: {verdict} (base: {base_score}, composite: {composite_score}/100)")

            ticket_verdicts = self.config.get("ticketing", {}).get("create_on_verdict_email", ["PHISHING", "SUSPICIOUS"])
            if verdict in ticket_verdicts and analysis_id:
                try:
                    create_incident_ticket(result, analysis_id, owner_id=user_id)
                except Exception as e:
                    logger.error(f"[EMAIL] Failed to create incident ticket: {e}")

            return result
        
        except Exception as e:
            logger.error(f"[EMAIL] Analysis failed: {e}", exc_info=True)
            return {'error': str(e)}
    
    async def _extract_email_data(self, msg: email.message.Message) -> Dict:
        """Extract basic email data."""
        from_email = parseaddr(msg.get('From', ''))[1]
        from_domain = from_email.split('@')[-1] if '@' in from_email else ''
        email_data = {
            'from': msg.get('From', ''),
            'from_domain': from_domain,
            'to': msg.get('To', ''),
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'reply_to': msg.get('Reply-To', ''),
            'return_path': msg.get('Return-Path', ''),
            'body_text': '',
            'body_html': '',
            'attachments': [],
            'urls': [],
            'ips': [],
            'domains': []
        }
        
        # Extract body
        body_parts = []
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                filename = part.get_filename()
                is_attachment = (
                    part.get_content_disposition() == 'attachment'
                    or (filename and content_type not in ('text/plain', 'text/html'))
                )
                if is_attachment:
                    email_data['attachments'].append({
                        'filename': filename or 'unnamed',
                        'content_type': content_type,
                        'size': len(part.get_payload(decode=True) or b'')
                    })
                elif content_type == 'text/plain':
                    try:
                        body_parts.append(part.get_payload(decode=True).decode('utf-8', errors='ignore'))
                    except:
                        pass
                elif content_type == 'text/html':
                    try:
                        email_data['body_html'] += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                body_parts.append(msg.get_payload(decode=True).decode('utf-8', errors='ignore'))
            except:
                pass
        
        email_data['body_text'] = '\n'.join(body_parts)
        
        # Extract IOCs
        all_text = f"{email_data['from']} {email_data['subject']} {email_data['body_text']} {email_data['body_html']}"
        iocs = IOCExtractor.extract_all(all_text)
        email_data['urls'] = [unescape(url) for url in iocs['urls']]
        email_data['ips'] = iocs['ipv4']
        email_data['domains'] = iocs['domains']

        spam_headers = self._extract_spam_headers(msg)
        if spam_headers:
            email_data['spam_headers'] = spam_headers
        
        return email_data
    
    @staticmethod
    def _authentication_header_presence(msg: email.message.Message) -> Dict[str, bool]:
        """Identify whether each authentication result was actually supplied."""
        auth_results = ' '.join(msg.get_all('Authentication-Results', []))
        return {
            'spf': bool(msg.get('Received-SPF', '').strip()),
            'dkim': bool(re.search(r'\bdkim\s*=\s*\w+', auth_results, re.IGNORECASE)),
            'dmarc': bool(re.search(r'\bdmarc\s*=\s*\w+', auth_results, re.IGNORECASE)),
        }

    @staticmethod
    def _extract_spam_headers(msg: email.message.Message) -> Dict:
        """Extract explicit spam headers without turning a missing header into clear."""
        headers = {
            name.lower(): value
            for name, value in msg.items()
            if name.lower().startswith('x-spam-')
        }
        if not headers:
            return {}

        result = {'headers': headers}
        flag = msg.get('X-Spam-Flag', '') or msg.get('X-Spam-Status', '')
        if flag:
            result['x_spam_flag'] = flag.split(',', 1)[0].strip().upper()
        return result

    @staticmethod
    def _find_phishing_keywords(email_data: Dict) -> List[str]:
        keywords = (
            'urgent', 'verify', 'suspend', 'click here', 'account', 'password',
            'confirm', 'security alert', 'unusual activity', 'update payment',
            'suspended', 'locked', 'expire', 'act now', 'limited time',
        )
        combined_text = ' '.join(
            str(email_data.get(field, '')).lower()
            for field in ('body_text', 'subject')
        )
        return [keyword for keyword in keywords if keyword in combined_text]

    @staticmethod
    def _independent_forensics_findings(forensics: Dict):
        """Return findings not duplicated by auth or advanced header checks."""
        if not isinstance(forensics, dict):
            return None

        findings = []
        available = False
        reputation = forensics.get('sender_reputation')
        if isinstance(reputation, dict) and 'suspicious_patterns' in reputation:
            available = True
            findings.extend(reputation.get('suspicious_patterns') or [])

        relay = forensics.get('relay_analysis')
        if isinstance(relay, dict):
            for key in ('suspicious_hops', 'time_anomalies', 'geo_anomalies'):
                if key in relay:
                    available = True
                    findings.extend(relay.get(key) or [])

        return findings if available else None

    def _build_indicator_summary(
        self,
        email_data: Dict,
        header_analysis: Dict,
        link_mismatches: List,
        lookalike_domains: List,
        html_obfuscation: Dict,
        qr_detection: Dict,
        brand_impersonation: List,
        threat_indicators: Dict = None,
        bec_results: Dict = None,
        mixed_script: Dict = None,
        *,
        forensics: Dict = None,
        auth_presence: Dict[str, bool] = None,
    ) -> Dict:
        """Build equal-weight found/clear/unavailable indicator states."""
        if auth_presence is None:
            auth_presence = {
                name: name in email_data
                for name in ('spf', 'dkim', 'dmarc')
            }

        factors = []

        def add_factor(key, available, found):
            if not available:
                state = 'unavailable'
            else:
                state = 'found' if found else 'clear'
            factors.append({
                'key': key,
                'label': _EMAIL_INDICATOR_LABELS[key],
                'state': state,
            })

        add_factor('spf_fail', auth_presence.get('spf', False),
                   str(email_data.get('spf', '')).lower() == 'fail')
        add_factor('dkim_fail', auth_presence.get('dkim', False),
                   str(email_data.get('dkim', '')).lower() == 'fail')
        add_factor('dmarc_fail', auth_presence.get('dmarc', False),
                   str(email_data.get('dmarc', '')).lower() == 'fail')

        header_available = isinstance(header_analysis, dict) and 'anomalies' in header_analysis
        add_factor('header_anomaly', header_available,
                   bool(header_analysis.get('anomalies')) if header_available else False)

        html_available = bool(email_data.get('body_html'))
        add_factor('link_mismatch', html_available and link_mismatches is not None,
                   bool(link_mismatches))
        add_factor('lookalike_domain', lookalike_domains is not None,
                   bool(lookalike_domains))

        html_keys = ('zero_size_fonts', 'hidden_elements', 'white_on_white', 'suspicious_css')
        html_findings_available = (
            html_available
            and isinstance(html_obfuscation, dict)
            and any(key in html_obfuscation for key in html_keys)
        )
        html_found = any(
            html_obfuscation.get(key) for key in html_keys
        ) if html_findings_available else False
        add_factor('html_obfuscation', html_findings_available, html_found)

        qr_available = (
            (html_available or bool(email_data.get('attachments')))
            and isinstance(qr_detection, dict)
            and 'qr_codes_found' in qr_detection
        )
        add_factor('qr_code', qr_available,
                   bool(qr_detection.get('qr_codes_found')) if qr_available else False)
        add_factor('brand_impersonation', brand_impersonation is not None,
                   bool(brand_impersonation))
        add_factor('mixed_script', isinstance(mixed_script, dict) and 'found' in mixed_script,
                   bool(mixed_script.get('found')) if isinstance(mixed_script, dict) else False)

        keyword_available = 'body_text' in email_data and 'subject' in email_data
        add_factor('phishing_keyword', keyword_available,
                   bool(self._find_phishing_keywords(email_data)))

        from_value = email_data.get('from', '')
        return_path = email_data.get('return_path')
        if return_path is None and isinstance(header_analysis, dict):
            return_path = header_analysis.get('return_path')
        from_email = parseaddr(from_value)[1]
        return_email = parseaddr(return_path or '')[1]
        return_available = bool(from_email and return_email)
        from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
        return_domain = return_email.split('@')[-1].lower() if '@' in return_email else ''
        add_factor('return_path_mismatch', return_available,
                   return_domain != from_domain if return_available else False)

        sender_domain = email_data.get('from_domain', '') or from_domain
        add_factor('suspicious_tld', bool(sender_domain), any(
            sender_domain.lower().endswith(tld) for tld in _SUSPICIOUS_EMAIL_TLDS
        ))

        threat_available = (
            isinstance(threat_indicators, dict)
            and 'active_checks' in threat_indicators
        )
        add_factor('threat_indicator_finding', threat_available,
                   bool(threat_indicators.get('active_checks')) if threat_available else False)

        bec_available = isinstance(bec_results, dict) and 'indicator_count' in bec_results
        add_factor('bec_finding', bec_available,
                   bool(bec_results.get('indicator_count')) if bec_available else False)

        spam_available = 'spam_headers' in email_data
        spam_headers = email_data.get('spam_headers') or {}
        spam_flag = str(spam_headers.get('x_spam_flag', '')).strip().lower()
        add_factor('spam_header', spam_available, spam_flag in {'yes', 'true', 'on'})

        independent_forensics = self._independent_forensics_findings(forensics)
        add_factor('forensics', independent_forensics is not None,
                   bool(independent_forensics))

        found = sum(item['state'] == 'found' for item in factors)
        checkable = sum(item['state'] != 'unavailable' for item in factors)
        return {
            'found': found,
            'checkable': checkable,
            'factors': factors,
        }

    @staticmethod
    def _determine_indicator_verdict(indicator_summary: Dict) -> str:
        factor_states = {
            item['key']: item['state']
            for item in indicator_summary.get('factors', [])
        }
        if indicator_summary.get('checkable', 0) == 0:
            return 'UNKNOWN'
        if any(
            factor_states.get(key) == 'found'
            for key in (
                'brand_impersonation',
                'lookalike_domain',
                'mixed_script',
            )
        ):
            return 'PHISHING'
        if indicator_summary.get('found', 0) > 0:
            return 'SUSPICIOUS'
        return 'CLEAN'

    def _calculate_base_phishing_score(
        self,
        email_data: Dict,
        header_analysis: Dict,
        link_mismatches: List,
        lookalike_domains: List,
        html_obfuscation: Dict,
        qr_detection: Dict,
        brand_impersonation: List,
        threat_indicators: Dict = None,
        bec_results: Dict = None,
        mixed_script: Dict = None,
        *,
        forensics: Dict = None,
        auth_presence: Dict[str, bool] = None,
        indicator_summary: Dict = None,
    ) -> int:
        """Return the equal-weight indicator score; legacy name retained for consumers."""
        summary = indicator_summary or self._build_indicator_summary(
            email_data,
            header_analysis,
            link_mismatches,
            lookalike_domains,
            html_obfuscation,
            qr_detection,
            brand_impersonation,
            threat_indicators,
            bec_results,
            mixed_script,
            forensics=forensics,
            auth_presence=auth_presence,
        )
        return IntelligentScoring.calculate_email_score(summary)
    
    async def _investigate_iocs(
        self,
        email_data: Dict,
        capability_errors: List[Dict] = None,
    ) -> List[Dict]:
        """Investigate extracted IOCs with bounded, partial-result processing."""
        ioc_results = []
        capability_errors = capability_errors if capability_errors is not None else []

        if not self.ioc_investigator:
            _append_capability_error(
                capability_errors,
                'ioc_investigator',
                'not_connected',
                'IOC investigation is not connected for this email.',
            )
            return ioc_results

        if not await _acquire_cross_tool_lock():
            _append_capability_error(
                capability_errors,
                'ioc_investigator',
                'busy',
                'IOC investigation is busy; this stage was skipped.',
            )
            return ioc_results

        deadline = time.monotonic() + _IOC_STAGE_TIMEOUT_SECONDS
        logger.info(
            f"[EMAIL] Found {len(email_data['urls'])} URLs, "
            f"{len(email_data['ips'])} IPs, {len(email_data['domains'])} domains"
        )
        try:
            groups = (
                ('URL', _dedupe_preserve_order(email_data['urls'])[:5]),
                ('IP', _dedupe_preserve_order(email_data['ips'])[:3]),
                ('domain', _dedupe_preserve_order(email_data['domains'])[:3]),
            )
            for label, values in groups:
                for value in values:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        _append_capability_error(
                            capability_errors,
                            'ioc_investigator',
                            'timeout',
                            'IOC investigation timed out; partial results were kept.',
                        )
                        return ioc_results
                    try:
                        logger.info(f"[EMAIL] Investigating {label}: {value}")
                        result = await asyncio.wait_for(
                            self.ioc_investigator.investigate(value),
                            timeout=remaining,
                        )
                        ioc_results.append(result)
                    except asyncio.TimeoutError:
                        _append_capability_error(
                            capability_errors,
                            'ioc_investigator',
                            'timeout',
                            'IOC investigation timed out; partial results were kept.',
                        )
                        return ioc_results
                    except Exception:
                        logger.exception("[EMAIL] IOC investigation failed")
                        _append_capability_error(
                            capability_errors,
                            'ioc_investigator',
                            'error',
                            'IOC investigation failed; partial results were kept.',
                        )
            return ioc_results
        finally:
            _CROSS_TOOL_LOCK.release()

    async def _analyze_attachments(
        self,
        msg: email.message.Message,
        email_data: Dict,
        capability_errors: List[Dict] = None,
    ) -> List[Dict]:
        """Analyze email attachments with bounded, partial-result processing."""
        attachment_results = []
        capability_errors = capability_errors if capability_errors is not None else []

        if not self.file_analyzer:
            _append_capability_error(
                capability_errors,
                'file_analyzer',
                'not_connected',
                'Attachment scanning is not connected for this email.',
            )
            return attachment_results

        if not await _acquire_cross_tool_lock():
            _append_capability_error(
                capability_errors,
                'file_analyzer',
                'busy',
                'Attachment scanning is busy; this stage was skipped.',
            )
            return attachment_results

        deadline = time.monotonic() + _ATTACHMENT_STAGE_TIMEOUT_SECONDS
        logger.info(f"[EMAIL] Found {len(email_data['attachments'])} attachments")
        try:
            for attachment_info in email_data['attachments'][:3]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _append_capability_error(
                        capability_errors,
                        'file_analyzer',
                        'timeout',
                        'Attachment scanning timed out; partial results were kept.',
                    )
                    break

                tmp_path = None
                try:
                    filename = attachment_info['filename']
                    suffix = Path(filename).suffix
                    if not _ATTACHMENT_SUFFIX_RE.fullmatch(suffix):
                        suffix = ''
                    for part in msg.walk():
                        if part.get_filename() != filename:
                            continue
                        payload = part.get_payload(decode=True)
                        if payload is None:
                            raise ValueError('attachment payload unavailable')
                        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                            tmp.write(payload)
                            tmp_path = tmp.name

                        logger.info(f"[EMAIL] Analyzing attachment: {filename}")
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            _append_capability_error(
                                capability_errors,
                                'file_analyzer',
                                'timeout',
                                'Attachment scanning timed out; partial results were kept.',
                            )
                            return attachment_results
                        result = await asyncio.wait_for(
                            self.file_analyzer.analyze(tmp_path),
                            timeout=remaining,
                        )
                        result['filename'] = filename
                        attachment_results.append(result)
                        break
                except asyncio.TimeoutError:
                    _append_capability_error(
                        capability_errors,
                        'file_analyzer',
                        'timeout',
                        'Attachment scanning timed out; partial results were kept.',
                    )
                    break
                except Exception:
                    logger.exception("[EMAIL] Attachment analysis failed")
                    _append_capability_error(
                        capability_errors,
                        'file_analyzer',
                        'error',
                        'Attachment scanning failed; partial results were kept.',
                    )
                finally:
                    if tmp_path:
                        try:
                            Path(tmp_path).unlink()
                        except OSError:
                            pass
            return attachment_results
        finally:
            _CROSS_TOOL_LOCK.release()
    
    def _check_spf(self, msg: email.message.Message) -> str:
        """Check SPF status from headers."""
        received_spf = msg.get('Received-SPF', '').lower()
        if 'pass' in received_spf:
            return 'pass'
        elif 'fail' in received_spf:
            return 'fail'
        elif 'softfail' in received_spf:
            return 'softfail'
        else:
            return 'none'
    
    def _check_dkim(self, msg: email.message.Message) -> str:
        """Check DKIM status from headers."""
        auth_results = msg.get('Authentication-Results', '').lower()
        if 'dkim=pass' in auth_results:
            return 'pass'
        elif 'dkim=fail' in auth_results:
            return 'fail'
        else:
            return 'none'
    
    def _check_dmarc(self, msg: email.message.Message) -> str:
        """Check DMARC status from headers."""
        auth_results = msg.get('Authentication-Results', '').lower()
        if 'dmarc=pass' in auth_results:
            return 'pass'
        elif 'dmarc=fail' in auth_results:
            return 'fail'
        else:
            return 'none'
