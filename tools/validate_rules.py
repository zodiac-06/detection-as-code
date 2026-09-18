"""Static checks that every rule in ``rules/`` is well formed and reviewable.

These checks are deliberately stricter than "does pySigma parse it". A rule that
parses but has no references, no false-positive notes and no ATT&CK tag is a
rule nobody can triage at three in the morning, so CI treats that as a failure
in the same way a linter treats an unused import.
"""

from __future__ import annotations

import re
import sys
from datetime import date, datetime
from pathlib import Path
from uuid import UUID

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"

ALLOWED_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
ALLOWED_LEVEL = {"informational", "low", "medium", "high", "critical"}

# Filename prefix expected for each logsource, so that a rule can be located
# from an alert without opening it.
FILENAME_PREFIXES = {
    ("windows", None, "process_creation"): "proc_creation_win_",
    ("windows", None, "file_event"): "file_event_win_",
    ("windows", "security", None): "win_security_",
    ("linux", None, "process_creation"): "proc_creation_lnx_",
    ("aws", "cloudtrail", None): "aws_",
    ("azure", "auditlogs", None): "azure_",
}

TAG_PATTERN = re.compile(r"^(attack\.[a-z0-9_.\-]+|cve\.[\d.\-]+|detection\.[a-z_]+|tlp\.[a-z]+)$")


def expected_prefix(logsource) -> str | None:
    key = (logsource.product, logsource.service, logsource.category)
    if key in FILENAME_PREFIXES:
        return FILENAME_PREFIXES[key]
    # Fall back to a product/service-only match.
    for (product, service, category), prefix in FILENAME_PREFIXES.items():
        if product == logsource.product and category is None and service in (None, logsource.service):
            return prefix
    return None


def check_rule(path: Path, seen_ids: dict[str, Path]) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")

    if "\t" in text:
        problems.append("contains a tab character; use four spaces")

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [f"invalid YAML: {exc}"]

    try:
        rule = SigmaCollection.from_yaml(text)[0]
    except SigmaError as exc:
        return [f"pySigma rejected the rule: {exc}"]

    # --- identity -------------------------------------------------------- #
    rule_id = str(raw.get("id", ""))
    try:
        UUID(rule_id)
    except ValueError:
        problems.append("id is not a valid UUID")
    else:
        if rule_id in seen_ids:
            problems.append(f"duplicate id, already used by {seen_ids[rule_id].name}")
        seen_ids[rule_id] = path

    # --- prose ----------------------------------------------------------- #
    title = raw.get("title", "")
    if not title:
        problems.append("missing title")
    else:
        if len(title) > 120:
            problems.append(f"title is {len(title)} characters; keep it under 120")
        if title.endswith("."):
            problems.append("title should not end with a period")

    description = (raw.get("description") or "").strip()
    if len(description) < 64:
        problems.append("description must explain what the rule detects and why (64+ characters)")

    if not raw.get("references"):
        problems.append("missing references; every rule needs a source an analyst can read")

    if not raw.get("falsepositives"):
        problems.append("missing falsepositives; state what benign activity looks like")

    if not raw.get("author"):
        problems.append("missing author")

    # --- enums ----------------------------------------------------------- #
    if raw.get("status") not in ALLOWED_STATUS:
        problems.append(f"status must be one of {sorted(ALLOWED_STATUS)}")

    if raw.get("level") not in ALLOWED_LEVEL:
        problems.append(f"level must be one of {sorted(ALLOWED_LEVEL)}")

    # --- date ------------------------------------------------------------ #
    raw_date = raw.get("date")
    if raw_date is None:
        problems.append("missing date")
    else:
        parsed = raw_date if isinstance(raw_date, date) else None
        if parsed is None:
            try:
                parsed = datetime.strptime(str(raw_date), "%Y-%m-%d").date()
            except ValueError:
                problems.append("date must be YYYY-MM-DD")
        if parsed and parsed > date.today():
            problems.append("date is in the future")

    # --- tags ------------------------------------------------------------ #
    tags = raw.get("tags") or []
    if not any(str(tag).startswith("attack.t") for tag in tags):
        problems.append("missing an ATT&CK technique tag (attack.tXXXX)")
    for tag in tags:
        if not TAG_PATTERN.match(str(tag)):
            problems.append(f"malformed tag: {tag}")

    # --- logsource and filename ------------------------------------------ #
    logsource = rule.logsource
    if not (logsource.product or logsource.service or logsource.category):
        problems.append("logsource must set at least one of product, service, category")
    prefix = expected_prefix(logsource)
    if prefix and not path.name.startswith(prefix):
        problems.append(f"filename should start with '{prefix}' for this logsource")

    # --- detection hygiene ------------------------------------------------ #
    detection = raw.get("detection") or {}
    condition = detection.get("condition")
    if not condition:
        problems.append("missing detection condition")
    named = [key for key in detection if key != "condition"]
    if len(named) > 1 and not any(key.startswith("selection") for key in named):
        problems.append("multi-block detections should name their match blocks 'selection*'")
    for key in named:
        if key.startswith("filter") and not (
            key.startswith("filter_main") or key.startswith("filter_optional")
        ):
            problems.append(
                f"filter block '{key}' should be named filter_main_* (correctness) "
                "or filter_optional_* (environment tuning)"
            )

    return problems


def main() -> int:
    seen_ids: dict[str, Path] = {}
    total_problems = 0
    paths = sorted(RULES_DIR.rglob("*.yml"))
    if not paths:
        print("no rules found")
        return 1

    for path in paths:
        problems = check_rule(path, seen_ids)
        rel = path.relative_to(REPO_ROOT)
        if problems:
            total_problems += len(problems)
            print(f"[FAIL] {rel}")
            for problem in problems:
                print(f"        - {problem}")
        else:
            print(f"[ OK ] {rel}")

    print(f"\n{len(paths)} rule(s) checked, {total_problems} problem(s)")
    return 1 if total_problems else 0


if __name__ == "__main__":
    sys.exit(main())
