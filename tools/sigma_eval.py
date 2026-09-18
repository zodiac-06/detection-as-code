"""Evaluate Sigma rules against in-memory log events.

pySigma parses and converts rules but does not ship a matcher, so there is no
stock way to answer the question a detection engineer actually cares about:
*does this rule fire on this event, and stay silent on that one?*

This module walks the condition tree pySigma produces and evaluates it against
a plain Python dictionary, which is what makes rule unit tests possible in CI
without standing up a SIEM.

Supported value types: strings with ``*``/``?`` wildcards, numbers, booleans,
null, regular expressions, CIDR expressions, numeric comparisons and
field-to-field references. Field names may be dotted paths (``userIdentity.arn``)
which are resolved into nested dictionaries, with a flat-key fallback so that
already-flattened events work too.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

_MISSING = object()


class UnsupportedRuleError(RuntimeError):
    """Raised when a rule uses a construct this evaluator cannot model."""


# --------------------------------------------------------------------------- #
# field resolution
# --------------------------------------------------------------------------- #


def resolve_field(event: dict, field: str) -> Any:
    """Look up ``field`` in ``event``, treating dots as nesting.

    ``properties.message`` finds ``event["properties"]["message"]`` but falls
    back to the literal key ``"properties.message"`` so that flattened events
    from a SIEM forwarder also work. Lists encountered along the path are
    searched element-wise, which is how CloudTrail and Entra ID audit records
    nest their interesting values.
    """
    if field in event:
        return event[field]

    current: Any = event
    for part in field.split("."):
        current = _descend(current, part)
        if current is _MISSING:
            return _MISSING
    return current


def _descend(node: Any, key: str) -> Any:
    if isinstance(node, dict):
        return node.get(key, _MISSING)
    if isinstance(node, list):
        found = [_descend(item, key) for item in node]
        found = [value for value in found if value is not _MISSING]
        if not found:
            return _MISSING
        return _flatten(found)
    return _MISSING


def _flatten(values: list) -> list:
    out: list = []
    for value in values:
        if isinstance(value, list):
            out.extend(value)
        else:
            out.append(value)
    return out


def _as_iterable(value: Any) -> Iterable[Any]:
    if isinstance(value, list):
        return value
    return [value]


# --------------------------------------------------------------------------- #
# value matching
# --------------------------------------------------------------------------- #


def sigma_string_to_regex(value: SigmaString) -> re.Pattern:
    """Translate a SigmaString into an anchored, case-insensitive regex."""
    pattern = []
    for part in value.iter_parts():
        if part is SpecialChars.WILDCARD_MULTI:
            pattern.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            pattern.append(".")
        else:
            pattern.append(re.escape(str(part)))
    return re.compile("^" + "".join(pattern) + "$", re.IGNORECASE | re.DOTALL)


def match_value(expected: Any, actual: Any, event: dict) -> bool:
    """Return True if a single observed ``actual`` satisfies ``expected``."""
    if isinstance(expected, SigmaNull):
        return actual is _MISSING or actual is None

    if isinstance(expected, SigmaExists):
        present = actual is not _MISSING and actual is not None
        return present is bool(expected.exists)

    if actual is _MISSING:
        return False

    if isinstance(expected, SigmaExpansion):
        return any(match_value(inner, actual, event) for inner in expected.values)

    if isinstance(expected, SigmaString):
        if actual is None:
            return False
        return bool(sigma_string_to_regex(expected).match(str(actual)))

    if isinstance(expected, SigmaRegularExpression):
        flags = re.IGNORECASE if "i" in str(getattr(expected, "flags", "")) else 0
        return bool(re.search(str(expected.regexp), str(actual), flags))

    if isinstance(expected, SigmaNumber):
        try:
            return float(actual) == float(expected.number)
        except (TypeError, ValueError):
            return False

    if isinstance(expected, SigmaBool):
        return bool(actual) is bool(expected.boolean)

    if isinstance(expected, SigmaCIDRExpression):
        try:
            network = ipaddress.ip_network(str(expected.cidr), strict=False)
            return ipaddress.ip_address(str(actual)) in network
        except ValueError:
            return False

    if isinstance(expected, SigmaCompareExpression):
        return _compare(expected, actual)

    if isinstance(expected, SigmaFieldReference):
        other = resolve_field(event, str(expected.field))
        return other is not _MISSING and str(other) == str(actual)

    raise UnsupportedRuleError(f"unsupported value type: {type(expected).__name__}")


def _compare(expected: SigmaCompareExpression, actual: Any) -> bool:
    try:
        left = float(actual)
        right = float(expected.number)
    except (TypeError, ValueError):
        return False
    op = expected.op.value if hasattr(expected.op, "value") else str(expected.op)
    return {
        "<": left < right,
        "<=": left <= right,
        ">": left > right,
        ">=": left >= right,
    }[op]


# --------------------------------------------------------------------------- #
# condition tree evaluation
# --------------------------------------------------------------------------- #


def evaluate_node(node: Any, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(evaluate_node(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(evaluate_node(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not evaluate_node(node.args[0], event)

    if isinstance(node, ConditionFieldEqualsValueExpression):
        observed = resolve_field(event, node.field)
        if isinstance(node.value, (SigmaNull, SigmaExists)):
            return match_value(node.value, observed, event)
        if observed is _MISSING:
            return False
        return any(match_value(node.value, item, event) for item in _as_iterable(observed))

    if isinstance(node, ConditionValueExpression):
        # Keyword search: the value may appear in any field of the event.
        return any(
            match_value(node.value, item, event)
            for item in _all_scalars(event)
        )

    raise UnsupportedRuleError(f"unsupported condition node: {type(node).__name__}")


def _all_scalars(node: Any) -> Iterable[Any]:
    if isinstance(node, dict):
        for value in node.values():
            yield from _all_scalars(value)
    elif isinstance(node, list):
        for value in node:
            yield from _all_scalars(value)
    else:
        yield node


# --------------------------------------------------------------------------- #
# public entry points
# --------------------------------------------------------------------------- #


def rule_matches(rule: SigmaRule, event: dict) -> bool:
    """True if any of the rule's conditions match ``event``."""
    for condition in rule.detection.parsed_condition:
        if evaluate_node(condition.parse(), event):
            return True
    return False


def logsource_matches(rule: SigmaRule, event: dict) -> bool:
    """Loose check that an event was tagged for the rule's log source.

    Test fixtures carry an optional ``_logsource`` key so that a typo in a
    fixture does not silently produce a passing negative test.
    """
    declared = event.get("_logsource")
    if not declared:
        return True
    source = rule.logsource
    for key in ("product", "service", "category"):
        expected = getattr(source, key, None)
        if expected and declared.get(key) and declared[key] != expected:
            return False
    return True
