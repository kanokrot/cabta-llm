"""
Author: Ugur AtesMITRE ATT&CK Framework Mapper for Blue Team Assistant."""

from typing import Dict, List
import re
import logging

from src.utils.mitre_keyword_patterns import (
    KEYWORD_TECHNIQUE_MAP,
    MITRE_MAPPER_KEYWORD_ORDER,
)
from src.utils.mitre_technique_names import get_technique_name

logger = logging.getLogger(__name__)
# Comprehensive MITRE ATT&CK Mapping
_MITRE_MAPPING_CONFLICTS = {
    "base64": {"technique": "T1027", "tactic": "Defense Evasion", "name": "Obfuscated Files"},
    "macro": {"technique": "T1566.001", "tactic": "Initial Access", "name": "Spearphishing Attachment"},
}
_MITRE_MAPPING_METADATA_OVERRIDES = {
    "invoke-wmimethod": {"name": "WMI"},
}

MITRE_MAPPING = {}
for _keyword in MITRE_MAPPER_KEYWORD_ORDER:
    if _keyword in _MITRE_MAPPING_CONFLICTS:
        MITRE_MAPPING[_keyword] = dict(_MITRE_MAPPING_CONFLICTS[_keyword])
        continue

    _technique_id = KEYWORD_TECHNIQUE_MAP[_keyword]
    _metadata = get_technique_name(_technique_id)
    MITRE_MAPPING[_keyword] = {
        "technique": _technique_id,
        "tactic": _metadata["tactic"],
        "name": _metadata["name"],
    }
    MITRE_MAPPING[_keyword].update(_MITRE_MAPPING_METADATA_OVERRIDES.get(_keyword, {}))

del _keyword, _technique_id, _metadata
class MITREMapper:
    """Map indicators to MITRE ATT&CK techniques."""
    
    @staticmethod
    def map_indicators(content: str) -> List[Dict]:
        """
        Map content to MITRE ATT&CK techniques.
        
        Args:
            content: String content to analyze (file content, command lines, etc.)
        
        Returns:
            List of detected MITRE techniques
        """
        if not content:
            return []
        
        content_lower = content.lower()
        techniques = []
        seen = set()
        
        for indicator, mapping in MITRE_MAPPING.items():
            if indicator in content_lower and mapping['technique'] not in seen:
                techniques.append({
                    'technique_id': mapping['technique'],
                    'technique_name': mapping['name'],
                    'tactic': mapping['tactic'],
                    'indicator': indicator
                })
                seen.add(mapping['technique'])
        
        # Sort by tactic order (roughly following kill chain)
        tactic_order = [
            'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Command and Control', 'Exfiltration', 'Impact'
        ]
        
        techniques.sort(key=lambda x: tactic_order.index(x['tactic']) if x['tactic'] in tactic_order else 99)
        
        logger.info(f"[MITRE] Mapped {len(techniques)} ATT&CK techniques")
        return techniques
    
    @staticmethod
    def map_from_categories(categories: List[str]) -> List[Dict]:
        """
        Map string categories to MITRE techniques.
        
        Args:
            categories: List of malware behavior categories
        
        Returns:
            List of MITRE techniques
        """
        techniques = []
        seen = set()
        
        category_mapping = {
            'network': {'technique': 'T1071', 'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
            'persistence': {'technique': 'T1547', 'tactic': 'Persistence', 'name': 'Boot or Logon Autostart Execution'},
            'evasion': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files or Information'},
            'obfuscation': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files or Information'},
            'crypto': {'technique': 'T1486', 'tactic': 'Impact', 'name': 'Data Encrypted for Impact'},
            'execution': {'technique': 'T1059', 'tactic': 'Execution', 'name': 'Command and Scripting Interpreter'},
            'disable_security': {'technique': 'T1562', 'tactic': 'Defense Evasion', 'name': 'Impair Defenses'},
            'credential': {'technique': 'T1003', 'tactic': 'Credential Access', 'name': 'OS Credential Dumping'},
            'discovery': {'technique': 'T1082', 'tactic': 'Discovery', 'name': 'System Information Discovery'},
            'lateral': {'technique': 'T1021', 'tactic': 'Lateral Movement', 'name': 'Remote Services'},
            'exfiltration': {'technique': 'T1041', 'tactic': 'Exfiltration', 'name': 'Exfiltration Over C2 Channel'},
            'keylogger': {'technique': 'T1056', 'tactic': 'Collection', 'name': 'Input Capture'},
            'screenshot': {'technique': 'T1113', 'tactic': 'Collection', 'name': 'Screen Capture'},
        }
        
        for category in categories:
            cat_lower = category.lower()
            if cat_lower in category_mapping and category_mapping[cat_lower]['technique'] not in seen:
                mapping = category_mapping[cat_lower]
                techniques.append({
                    'technique_id': mapping['technique'],
                    'technique_name': mapping['name'],
                    'tactic': mapping['tactic'],
                    'indicator': category
                })
                seen.add(mapping['technique'])
        
        return techniques
    
    @staticmethod
    def render_mitre_table(techniques: List[Dict]) -> str:
        """
        Render MITRE techniques as formatted ASCII table.
        
        Args:
            techniques: List of MITRE technique dicts
        
        Returns:
            Formatted table string
        """
        if not techniques:
            return "No MITRE ATT&CK techniques detected."
        
        lines = []
        lines.append("┌─ MITRE ATT&CK MAPPING")
        lines.append("│")
        lines.append("│  ┌────────────┬─────────────────────────────┬──────────────────────┐")
        lines.append("│  │ Technique  │ Name                        │ Tactic               │")
        lines.append("│  ├────────────┼─────────────────────────────┼──────────────────────┤")
        
        for tech in techniques[:10]:
            tid = tech['technique_id'][:10].ljust(10)
            name = tech['technique_name'][:27].ljust(27)
            tactic = tech['tactic'][:20].ljust(20)
            lines.append(f"│  │ {tid} │ {name} │ {tactic} │")
        
        lines.append("│  └────────────┴─────────────────────────────┴──────────────────────┘")
        lines.append("│")
        lines.append(f"│  Total: {len(techniques)} techniques detected")
        lines.append("│  Reference: https://attack.mitre.org/")
        lines.append("└" + "─" * 77)
        
        return '\n'.join(lines)
    
    @staticmethod
    def render_mitre_html(techniques: List[Dict]) -> str:
        """
        Render MITRE techniques as HTML table.
        
        Args:
            techniques: List of MITRE technique dicts
        
        Returns:
            HTML table string
        """
        if not techniques:
            return "<p>No MITRE ATT&CK techniques detected.</p>"
        
        html = """
        <div class="card mb-4">
            <div class="card-header bg-dark text-white">
                <h5>🎯 MITRE ATT&CK Techniques</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped table-bordered">
                        <thead class="thead-dark">
                            <tr>
                                <th>Technique ID</th>
                                <th>Name</th>
                                <th>Tactic</th>
                                <th>Indicator</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        for tech in techniques[:15]:
            tactic_class = 'text-danger' if tech['tactic'] in ['Execution', 'Impact', 'Credential Access'] else 'text-warning' if tech['tactic'] in ['Defense Evasion', 'Persistence'] else ''
            html += f"""
                            <tr>
                                <td><a href="https://attack.mitre.org/techniques/{tech['technique_id']}/" target="_blank">{tech['technique_id']}</a></td>
                                <td>{tech['technique_name']}</td>
                                <td class="{tactic_class}">{tech['tactic']}</td>
                                <td><code>{tech['indicator'][:30]}</code></td>
                            </tr>
            """
        
        html += f"""
                        </tbody>
                    </table>
                </div>
                <p class="text-muted">
                    <small>Total: {len(techniques)} techniques detected | 
                    <a href="https://attack.mitre.org/" target="_blank">MITRE ATT&CK Reference</a></small>
                </p>
            </div>
        </div>
        """
        
        return html
