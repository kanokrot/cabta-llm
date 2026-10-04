from src.analyzers.office_analyzer import OfficeAnalyzer


def _analyzer() -> OfficeAnalyzer:
    return OfficeAnalyzer.__new__(OfficeAnalyzer)


def test_no_macro_row_ignores_flags_legend():
    output = """mraptor output
Flags: A=AutoExec, W=Write, X=Execute
| File | Flags | Result |
| clean.docx |  | No Macro |
"""

    verdict = _analyzer()._parse_mraptor(output)

    assert verdict['is_suspicious'] is False
    assert verdict['flags'] == ''
    assert verdict['auto_exec'] is False
    assert verdict['write'] is False
    assert verdict['execute'] is False


def test_suspicious_row_uses_flags_column_only():
    output = """Flags: A=AutoExec, W=Write, X=Execute
| File | Flags | Result |
| suspicious.docm | AX | SUSPICIOUS |
"""

    verdict = _analyzer()._parse_mraptor(output)

    assert verdict['is_suspicious'] is True
    assert verdict['flags'] == 'AX'
    assert verdict['auto_exec'] is True
    assert verdict['write'] is False
    assert verdict['execute'] is True


def test_error_row_is_not_suspicious():
    output = """Flags: A=AutoExec, W=Write, X=Execute
| File | Flags | Result |
| broken.docm | AX | ERROR |
"""

    verdict = _analyzer()._parse_mraptor(output)

    assert verdict['is_suspicious'] is False
    assert verdict['flags'] == ''
    assert verdict['error'] == 'mraptor reported ERROR'


def test_exit_code_fallback_is_used_when_result_row_is_missing():
    suspicious = _analyzer()._parse_mraptor('', exit_code=15)
    error = _analyzer()._parse_mraptor('', exit_code=10)

    assert suspicious['is_suspicious'] is True
    assert error['is_suspicious'] is False
    assert error['error'] == 'mraptor exited with error code 10'
