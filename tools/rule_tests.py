"""Load rule test fixtures and evaluate them.

A fixture lives in ``tests/data/<rule-stem>.yml`` and looks like this::

    rule: rules/windows/process_creation/example.yml
    true_positive:
        - name: what the attacker did
          event: {...}
    false_positive:
        - name: the benign activity that must not alert
          event: {...}

Running the fixtures is what turns a rule from an untested YAML file into
something you can change with confidence: a tightened filter that silently
kills the detection fails the build instead of quietly failing in production.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sigma_eval import logsource_matches, rule_matches  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "tests" / "data"
RULES_DIR = REPO_ROOT / "rules"


@dataclass
class Case:
    fixture: Path
    rule_path: Path
    rule: SigmaRule
    kind: str  # "true_positive" or "false_positive"
    name: str
    event: dict

    @property
    def should_match(self) -> bool:
        return self.kind == "true_positive"

    def __str__(self) -> str:
        return f"{self.rule_path.name}::{self.kind}::{self.name}"


def load_rule(path: Path) -> SigmaRule:
    return SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))[0]


def iter_cases() -> Iterator[Case]:
    for fixture in sorted(FIXTURE_DIR.glob("*.yml")):
        data = yaml.safe_load(fixture.read_text(encoding="utf-8"))
        rule_path = REPO_ROOT / data["rule"]
        rule = load_rule(rule_path)
        for kind in ("true_positive", "false_positive"):
            for case in data.get(kind) or []:
                yield Case(
                    fixture=fixture,
                    rule_path=rule_path,
                    rule=rule,
                    kind=kind,
                    name=case["name"],
                    event=case["event"],
                )


def run_case(case: Case) -> tuple[bool, str]:
    """Return (passed, message)."""
    if not logsource_matches(case.rule, case.event):
        return False, "fixture _logsource does not match the rule's logsource"
    matched = rule_matches(case.rule, case.event)
    if matched == case.should_match:
        return True, "ok"
    if case.should_match:
        return False, "rule did not fire on an event it is supposed to detect"
    return False, "rule fired on an event that must not alert"


def untested_rules() -> list[Path]:
    """Rules with no fixture file. Missing tests are a CI failure, not a warning."""
    covered = set()
    for fixture in FIXTURE_DIR.glob("*.yml"):
        data = yaml.safe_load(fixture.read_text(encoding="utf-8"))
        covered.add((REPO_ROOT / data["rule"]).resolve())
    return sorted(p for p in RULES_DIR.rglob("*.yml") if p.resolve() not in covered)


def main() -> int:
    failures: list[str] = []
    total = 0
    for case in iter_cases():
        total += 1
        passed, message = run_case(case)
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {case}")
        if not passed:
            failures.append(f"{case}: {message}")

    missing = untested_rules()
    for path in missing:
        print(f"[FAIL] {path.relative_to(REPO_ROOT)}: no test fixture")
        failures.append(f"{path.relative_to(REPO_ROOT)}: no test fixture")

    print(f"\n{total} case(s) run, {len(failures)} failure(s)")
    for failure in failures:
        print(f"  - {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
