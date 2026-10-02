"""Test harness for the generator's Sigma subset, not a full Sigma engine.

The evaluator intentionally supports only the field operations emitted by
``RuleGenerator``. Unsupported Sigma syntax raises ``NotImplementedError``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


_TOKEN_RE = re.compile(r"\s*(\(|\)|\b(?:and|or|not)\b|[A-Za-z_][A-Za-z0-9_]*)")


def _event_values(value: Any) -> list[Any]:
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, Sequence):
        return list(value)
    return [value]


def _value_matches(operator: str, expected: Any, actual: Any) -> bool:
    if isinstance(expected, list):
        return any(_value_matches(operator, item, actual) for item in expected)
    if not isinstance(expected, (str, int, float, bool)) or expected is None:
        raise NotImplementedError(f"Unsupported Sigma value: {expected!r}")

    actual_values = _event_values(actual)
    for actual_value in actual_values:
        if not isinstance(actual_value, (str, int, float, bool)):
            raise NotImplementedError(
                f"Unsupported event value: {actual_value!r}"
            )
        if operator == "eq" and actual_value == expected:
            return True
        if operator == "contains" and str(expected) in str(actual_value):
            return True
        if operator == "endswith" and str(actual_value).endswith(str(expected)):
            return True
    return False


def _field_match(field: str, expected: Any, event: Mapping[str, Any]) -> bool:
    if "|" in field:
        field_name, modifier = field.split("|", 1)
        if modifier == "contains":
            operator = "contains"
        elif modifier == "endswith":
            operator = "endswith"
        else:
            raise NotImplementedError(f"Unsupported Sigma modifier: {modifier}")
    else:
        field_name = field
        operator = "eq"

    if field_name not in event:
        return False
    return _value_matches(operator, expected, event[field_name])


def _selection_match(selection: Any, event: Mapping[str, Any]) -> bool:
    if isinstance(selection, Mapping):
        return all(
            _field_match(str(field), expected, event)
            for field, expected in selection.items()
        )
    if isinstance(selection, list):
        return any(_selection_match(item, event) for item in selection)
    raise NotImplementedError(f"Unsupported Sigma selection: {selection!r}")


class _ConditionParser:
    def __init__(self, condition: str, selections: Mapping[str, bool]):
        self.condition = condition
        self.selections = selections
        self.tokens = self._tokenize(condition)
        self.index = 0

    @staticmethod
    def _tokenize(condition: str) -> list[str]:
        tokens: list[str] = []
        position = 0
        while position < len(condition):
            match = _TOKEN_RE.match(condition, position)
            if not match:
                raise NotImplementedError(
                    f"Unsupported Sigma condition syntax: {condition!r}"
                )
            tokens.append(match.group(1))
            position = match.end()
        return tokens

    def parse(self) -> bool:
        if not self.tokens:
            raise NotImplementedError("Empty Sigma condition")
        result = self._parse_or()
        if self.index != len(self.tokens):
            raise NotImplementedError(
                f"Unsupported Sigma condition syntax: {self.condition!r}"
            )
        return result

    def _parse_or(self) -> bool:
        result = self._parse_and()
        while self._accept("or"):
            right = self._parse_and()
            result = result or right
        return result

    def _parse_and(self) -> bool:
        result = self._parse_not()
        while self._accept("and"):
            right = self._parse_not()
            result = result and right
        return result

    def _parse_not(self) -> bool:
        if self._accept("not"):
            return not self._parse_not()
        return self._parse_primary()

    def _parse_primary(self) -> bool:
        if self._accept("("):
            result = self._parse_or()
            if not self._accept(")"):
                raise NotImplementedError(
                    f"Unsupported Sigma condition syntax: {self.condition!r}"
                )
            return result
        if self.index >= len(self.tokens):
            raise NotImplementedError(
                f"Unsupported Sigma condition syntax: {self.condition!r}"
            )
        token = self.tokens[self.index]
        self.index += 1
        if token in {"and", "or", "not", "(", ")"}:
            raise NotImplementedError(
                f"Unsupported Sigma condition syntax: {self.condition!r}"
            )
        return bool(self.selections.get(token, False))

    def _accept(self, token: str) -> bool:
        if self.index < len(self.tokens) and self.tokens[self.index] == token:
            self.index += 1
            return True
        return False


def match_sigma_document(
    document: Mapping[str, Any], event: Mapping[str, Any]
) -> bool:
    """Evaluate one parsed generated rule against one event dictionary."""
    if not isinstance(document, Mapping):
        raise NotImplementedError("Sigma document must be a mapping")
    detection = document.get("detection")
    if not isinstance(detection, Mapping):
        raise NotImplementedError("Sigma detection must be a mapping")
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise NotImplementedError("Sigma condition must be a string")

    selections = {
        str(name): _selection_match(selection, event)
        for name, selection in detection.items()
        if name != "condition"
    }
    return _ConditionParser(condition, selections).parse()
