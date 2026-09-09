"""Basic syntax validation for generated detection-rule artifacts."""

import re
from typing import List

import yaml


def validate_rule(rule_type: str, rule_content: str) -> dict:
    """Perform basic, offline syntax sanity checks for a detection rule.

    YARA is compiled with ``yara-python``. Sigma is parsed as YAML with
    PyYAML and checked for its core document fields; the project does not
    include a dedicated Sigma semantic validator. KQL, SPL, XQL, and DQL do
    not have offline parsers in this project, so they receive only non-empty,
    balanced-delimiter, and balanced-quote checks. Suricata, Snort, and
    firewall rules receive those same checks plus basic format checks.

    This function does not establish semantic or behavioral correctness for
    any rule type.
    """
    normalized_type = str(rule_type or '').strip().lower()
    errors: List[str] = []
    supported_types = {
        'kql', 'spl', 'xql', 'dql', 'sigma', 'yara',
        'suricata', 'snort', 'firewall',
    }

    if normalized_type not in supported_types:
        errors.append(f"Unsupported rule type: {normalized_type or '<empty>'}")
        return {
            'valid': False,
            'errors': errors,
            'rule_type': normalized_type,
        }

    if not isinstance(rule_content, str) or not rule_content.strip():
        errors.append('Rule content must be a non-empty string')
        return {
            'valid': False,
            'errors': errors,
            'rule_type': normalized_type,
        }

    content = rule_content.strip()

    if normalized_type == 'yara':
        try:
            import yara

            yara.compile(source=content)
        except ImportError:
            errors.append('YARA validation unavailable: yara-python is not installed')
        except Exception as exc:
            errors.append(f'YARA syntax error: {exc}')

    elif normalized_type == 'sigma':
        try:
            document = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            errors.append(f'Sigma YAML syntax error: {exc}')
        else:
            if not isinstance(document, dict):
                errors.append('Sigma rule must be a YAML mapping')
            else:
                for required_field in ('title', 'logsource', 'detection'):
                    if required_field not in document:
                        errors.append(
                            f"Sigma rule is missing required field: {required_field}"
                        )
                detection = document.get('detection')
                if isinstance(detection, dict) and 'condition' not in detection:
                    errors.append('Sigma detection is missing required field: condition')

    else:
        pairs = {')': '(', ']': '[', '}': '{'}
        opening = set(pairs.values())
        stack: List[str] = []
        quote = None
        escaped = False

        for char in content:
            if escaped:
                escaped = False
                continue
            if char == '\\':
                escaped = True
                continue
            if quote:
                if char == quote:
                    quote = None
                continue
            if char in ('"', "'"):
                quote = char
            elif char in opening:
                stack.append(char)
            elif char in pairs:
                if not stack or stack.pop() != pairs[char]:
                    errors.append(f'Unmatched closing delimiter: {char}')
                    break

        if quote:
            errors.append(f'Unterminated {quote} quote')
        if stack:
            errors.append(f'Unclosed delimiter: {stack[-1]}')

        if normalized_type in ('suricata', 'snort') and not errors:
            rule_lines = [
                line.strip() for line in content.splitlines()
                if line.strip() and not line.lstrip().startswith('#')
            ]
            rule_pattern = re.compile(
                r'^(alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth)\s+'
                r'\S+\s+\S+\s+\S+\s+(?:->|<>|<-)\s+\S+\s+\S+\s*'
                r'\(.+;\s*\)$',
                re.IGNORECASE,
            )
            if not rule_lines:
                errors.append(f'{normalized_type.title()} content has no active rule')
            else:
                for line_number, line in enumerate(rule_lines, start=1):
                    if not rule_pattern.match(line):
                        errors.append(
                            f'{normalized_type.title()} rule line {line_number} '
                            'must contain an action, header, direction, and options'
                        )

        if normalized_type == 'firewall' and not errors:
            active_lines = [
                line.strip() for line in content.splitlines()
                if line.strip() and not line.lstrip().startswith('#')
            ]
            structural_prefixes = (
                'action=', 'allow ', 'block ', 'deny ', 'permit ',
                'config ', 'edit ', 'set ', 'unset ', 'next', 'end',
            )
            if not active_lines:
                errors.append('Firewall content has no active rule')
            elif not all(
                '=' in line or line.lower().startswith(structural_prefixes)
                for line in active_lines
            ):
                errors.append(
                    'Firewall rule must use key/value entries or a recognized '
                    'allow, deny, block, permit, or configuration command'
                )

    return {
        'valid': not errors,
        'errors': errors,
        'rule_type': normalized_type,
    }
