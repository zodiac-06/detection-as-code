"""Pytest entry point for the rule test suite.

The evaluation logic lives in ``tools/`` so that it can also be run as a plain
script (``make test``) on a machine without pytest installed. This module only
adapts it to pytest so that CI, IDEs and coverage tooling see individual test
cases rather than one opaque pass/fail.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from rule_tests import Case, iter_cases, run_case, untested_rules  # noqa: E402

CASES = list(iter_cases())


@pytest.mark.parametrize("case", CASES, ids=[str(case) for case in CASES])
def test_rule_case(case: Case) -> None:
    passed, message = run_case(case)
    assert passed, f"{case}: {message}"


def test_every_rule_has_a_fixture() -> None:
    missing = untested_rules()
    assert not missing, "rules without a test fixture: " + ", ".join(str(p) for p in missing)


def test_suite_is_not_empty() -> None:
    assert CASES, "no test fixtures were discovered"


def test_each_rule_has_both_polarities() -> None:
    """A rule with only true positives has not been shown to be selective."""
    kinds: dict[str, set[str]] = {}
    for case in CASES:
        kinds.setdefault(case.rule_path.name, set()).add(case.kind)
    incomplete = [name for name, seen in kinds.items() if len(seen) < 2]
    assert not incomplete, (
        "these rules need both true_positive and false_positive cases: " + ", ".join(incomplete)
    )
