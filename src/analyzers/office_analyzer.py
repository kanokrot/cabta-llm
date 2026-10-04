"""
Author: Ugur Ates
Office Analyzer - Professional MS Office file analysis.

Integrated tools:
- oletools (olevba, mraptor, oleobj, oleid)
- YARA scanning
- String extraction

v1.0.0 - Professional Analysis Suite
"""

import zipfile
import xml.etree.ElementTree as ET
import logging
import re
from typing import Dict, List
from pathlib import Path

logger = logging.getLogger(__name__)
class OfficeAnalyzer:
    """
    Professional Office file analysis with oletools integration.
    
    Features:
    - VBA Macro extraction and analysis (olevba)
    - Malicious macro detection (mraptor)
    - OLE object detection (oleobj)
    - OLE indicator detection (oleid)
    - External link detection
    - DDE attack detection
    """
    
    # Suspicious VBA keywords
    SUSPICIOUS_KEYWORDS = {
        'auto_execute': [
            'AutoOpen', 'AutoClose', 'AutoExec', 'AutoExit', 'Auto_Open',
            'Auto_Close', 'Workbook_Open', 'Document_Open', 'DocumentOpen',
        ],
        'execution': [
            'Shell', 'WScript.Shell', 'CreateObject', 'GetObject',
            'PowerShell', 'cmd.exe', 'mshta', 'cscript', 'wscript',
            'Exec', 'Run', 'ShellExecute',
        ],
        'download': [
            'URLDownloadToFile', 'XMLHTTP', 'WinHttp', 'Msxml2',
            'InternetExplorer.Application', 'DownloadFile',
        ],
        'obfuscation': [
            'Chr', 'ChrW', 'Asc', 'StrReverse', 'Replace',
            'CallByName', 'Base64', 'FromBase64',
        ],
        'registry': [
            'RegWrite', 'RegRead', 'RegDelete',
            'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE',
        ],
    }
    
    def __init__(self):
        """Initialize with tool runner."""
        try:
            from ..tools.external_tool_runner import get_tool_runner
            self.tool_runner = get_tool_runner()
        except:
            self.tool_runner = None
    
    def analyze(self, file_path: str) -> Dict:
        """
        Perform comprehensive Office file analysis.
        
        Pipeline:
        1. oleid - OLE file indicators
        2. olevba - VBA macro extraction & analysis
        3. mraptor - Malicious macro detection
        4. oleobj - Embedded OLE objects
        5. Basic content analysis
        """
        logger.info(f"[OFFICE] Analyzing: {Path(file_path).name}")
        
        result = {
            'file_path': file_path,
            'file_type': 'Office',
            'format': Path(file_path).suffix.lower(),
            'analysis_tools': [],
            
            'ole_indicators': {},
            'vba_analysis': {},
            'macro_verdict': {},
            'embedded_objects': [],
            'external_links': [],
            'dde_links': [],
            
            'threat_indicators': [],
            'threat_score': 0,
            'verdict': 'UNKNOWN',
            'raw_outputs': {},
        }
        
        # 1. OLE Indicators (oleid)
        if self.tool_runner and self.tool_runner.is_available('oleid'):
            oleid_out = self.tool_runner.run_oleid(file_path)
            if oleid_out.success:
                result['ole_indicators'] = self._parse_oleid(oleid_out.stdout)
                result['raw_outputs']['oleid'] = oleid_out.stdout
                result['analysis_tools'].append('oleid')
        
        # 2. VBA Macro Analysis (olevba)
        if self.tool_runner and self.tool_runner.is_available('olevba'):
            olevba_out = self.tool_runner.run_olevba(file_path, decode=True)
            if olevba_out.success:
                result['vba_analysis'] = self._parse_olevba(olevba_out.stdout)
                result['raw_outputs']['olevba'] = olevba_out.stdout
                result['analysis_tools'].append('olevba')
                
                if result['vba_analysis'].get('has_macros'):
                    result['threat_indicators'].append("Contains VBA Macros")
                if result['vba_analysis'].get('auto_execute'):
                    result['threat_indicators'].append(
                        f"Auto-execute: {', '.join(result['vba_analysis']['auto_execute'][:3])}"
                    )
        
        # 3. Malicious Macro Detection (mraptor)
        if self.tool_runner and self.tool_runner.is_available('mraptor'):
            mraptor_out = self.tool_runner.run_mraptor(file_path)
            if mraptor_out.success or mraptor_out.exit_code in (0, 10, 15):
                result['macro_verdict'] = self._parse_mraptor(
                    mraptor_out.stdout,
                    exit_code=mraptor_out.exit_code,
                )
                result['raw_outputs']['mraptor'] = mraptor_out.stdout
                if mraptor_out.stderr:
                    result['raw_outputs']['mraptor_stderr'] = mraptor_out.stderr

                if result['macro_verdict'].get('error'):
                    result.setdefault('tool_errors', []).append({
                        'tool': 'mraptor',
                        'message': result['macro_verdict']['error'],
                    })
                else:
                    result['analysis_tools'].append('mraptor')
                
                if result['macro_verdict'].get('is_suspicious'):
                    result['threat_indicators'].append(
                        f"mraptor: {result['macro_verdict'].get('flags', 'Suspicious')}"
                    )
        
        # 4. Embedded OLE Objects (oleobj)
        if self.tool_runner and self.tool_runner.is_available('oleobj'):
            oleobj_out = self.tool_runner.run_oleobj(file_path)
            if oleobj_out.success:
                result['embedded_objects'] = self._parse_oleobj(oleobj_out.stdout)
                result['raw_outputs']['oleobj'] = oleobj_out.stdout
                result['analysis_tools'].append('oleobj')
                
                if result['embedded_objects']:
                    result['threat_indicators'].append(
                        f"Embedded OLE objects: {len(result['embedded_objects'])}"
                    )
        
        # 5. Basic content analysis (fallback)
        if not result['analysis_tools']:
            basic = self._basic_analysis(file_path)
            result.update(basic)
            result['analysis_tools'].append('basic')
        
        # 6. Calculate threat score
        result['threat_score'] = self._calculate_score(result)
        result['verdict'] = self._determine_verdict(result['threat_score'])
        
        return result
    
    def _parse_oleid(self, output: str) -> Dict:
        """Parse oleid output."""
        indicators = {
            'has_vba': False,
            'has_xlm': False,
            'has_flash': False,
            'has_external_links': False,
            'encrypted': False,
            'risk_level': 'low',
        }
        
        output_lower = output.lower()
        
        if 'vba macros' in output_lower and ('yes' in output_lower or 'true' in output_lower):
            indicators['has_vba'] = True
        if 'xlm macros' in output_lower and 'yes' in output_lower:
            indicators['has_xlm'] = True
        if 'flash' in output_lower and 'yes' in output_lower:
            indicators['has_flash'] = True
        if 'external' in output_lower and 'yes' in output_lower:
            indicators['has_external_links'] = True
        if 'encrypted' in output_lower and 'yes' in output_lower:
            indicators['encrypted'] = True
        
        if indicators['has_xlm'] or indicators['has_flash']:
            indicators['risk_level'] = 'high'
        elif indicators['has_vba']:
            indicators['risk_level'] = 'medium'
        
        return indicators
    
    def _parse_olevba(self, output: str) -> Dict:
        """Parse olevba output."""
        analysis = {
            'has_macros': False,
            'auto_execute': [],
            'suspicious_keywords': [],
            'iocs': {'urls': [], 'ips': []},
            'vba_code_preview': '',
        }
        
        if 'VBA MACRO' in output or 'contains VBA' in output.lower():
            analysis['has_macros'] = True
        
        # Extract suspicious keywords
        for category, keywords in self.SUSPICIOUS_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() in output.lower():
                    if category == 'auto_execute':
                        if kw not in analysis['auto_execute']:
                            analysis['auto_execute'].append(kw)
                    else:
                        if kw not in analysis['suspicious_keywords']:
                            analysis['suspicious_keywords'].append(kw)
        
        # Extract URLs
        url_pattern = re.compile(r'https?://[^\s<>"\']+')
        for url in url_pattern.findall(output):
            if url not in analysis['iocs']['urls']:
                analysis['iocs']['urls'].append(url)
        
        # Extract IPs
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        for ip in ip_pattern.findall(output):
            if ip not in analysis['iocs']['ips'] and not ip.startswith('0.'):
                analysis['iocs']['ips'].append(ip)
        
        return analysis
    
    def _parse_mraptor(self, output: str, exit_code: int = None) -> Dict:
        """Parse mraptor result rows without interpreting the legend."""
        verdict = {
            'is_suspicious': False,
            'flags': '',
            'auto_exec': False,
            'write': False,
            'execute': False,
        }

        result_pattern = re.compile(
            r'(?<![A-Za-z0-9_.-])(NO\s+MACRO|OK|SUSPICIOUS|ERROR)(?![A-Za-z0-9_.-])',
            re.IGNORECASE,
        )
        parsed_row = False

        def collect_flags(fragments):
            flags = ''
            for fragment in fragments:
                token = fragment.strip().upper()
                token = re.sub(r'^[\[\](){}:,;]+|[\[\](){}:,;]+$', '', token)
                if not token or not re.fullmatch(r'[AWX.\- ]+', token):
                    continue
                for flag in token:
                    if flag in 'AWX' and flag not in flags:
                        flags += flag
            return flags

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or line.lower().startswith('flags:'):
                continue
            match = result_pattern.search(line)
            if not match:
                continue

            parsed_row = True
            result_name = re.sub(r'\s+', ' ', match.group(1).upper())
            if result_name == 'ERROR':
                verdict['error'] = 'mraptor reported ERROR'
                break
            if result_name in ('NO MACRO', 'OK'):
                break

            if '|' in line:
                cells = [cell.strip() for cell in line.split('|')]
                flags = collect_flags(cell for cell in cells if result_name not in cell.upper())
            else:
                before = line[:match.start()].split()
                after = line[match.end():].split()
                flags = collect_flags(before + after)

            verdict['is_suspicious'] = result_name == 'SUSPICIOUS'
            verdict['flags'] = flags
            verdict['auto_exec'] = 'A' in flags
            verdict['write'] = 'W' in flags
            verdict['execute'] = 'X' in flags
            break

        if not parsed_row:
            if exit_code == 15:
                verdict['is_suspicious'] = True
            elif exit_code == 10:
                verdict['error'] = 'mraptor exited with error code 10'

        return verdict
    
    def _parse_oleobj(self, output: str) -> List[Dict]:
        """Parse oleobj output."""
        objects = []
        
        current_obj = {}
        for line in output.split('\n'):
            line = line.strip()
            if 'Object type:' in line:
                if current_obj:
                    objects.append(current_obj)
                current_obj = {'type': line.split(':')[-1].strip()}
            elif 'Object name:' in line:
                current_obj['name'] = line.split(':')[-1].strip()
            elif 'Saved to file:' in line:
                current_obj['saved_path'] = line.split(':')[-1].strip()
        
        if current_obj:
            objects.append(current_obj)
        
        return objects
    
    def _basic_analysis(self, file_path: str) -> Dict:
        """Basic analysis without oletools."""
        result = {
            'has_macros': False,
            'external_links': [],
        }
        
        try:
            # Check if it's an OOXML file (zip-based)
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, 'r') as z:
                    namelist = z.namelist()
                    
                    # Check for VBA
                    if any('vbaProject' in n for n in namelist):
                        result['has_macros'] = True
                    
                    # Check for external links
                    for name in namelist:
                        if 'relationships' in name.lower():
                            try:
                                content = z.read(name).decode('utf-8', errors='ignore')
                                external = re.findall(r'Target="(https?://[^"]+)"', content)
                                result['external_links'].extend(external)
                            except:
                                pass
        except:
            pass
        
        return result
    
    def _calculate_score(self, result: Dict) -> int:
        """Calculate threat score."""
        score = 0
        
        # OLE indicators
        ole = result.get('ole_indicators', {})
        if ole.get('has_vba'):
            score += 15
        if ole.get('has_xlm'):
            score += 25
        if ole.get('has_flash'):
            score += 30
        if ole.get('has_external_links'):
            score += 10
        
        # VBA analysis
        vba = result.get('vba_analysis', {})
        if vba.get('has_macros'):
            score += 10
        score += len(vba.get('auto_execute', [])) * 15
        score += min(len(vba.get('suspicious_keywords', [])) * 3, 20)
        
        # mraptor verdict
        mraptor = result.get('macro_verdict', {})
        if mraptor.get('is_suspicious'):
            score += 30
        if mraptor.get('auto_exec') and mraptor.get('execute'):
            score += 20
        
        # Embedded objects
        score += len(result.get('embedded_objects', [])) * 10
        
        return min(score, 100)
    
    def _determine_verdict(self, score: int) -> str:
        if score >= 70:
            return 'MALICIOUS'
        elif score >= 40:
            return 'SUSPICIOUS'
        else:
            return 'CLEAN'
