"""Compile every rule into the query languages the SOC actually runs.

The point of detection-as-code is that the YAML in ``rules/`` is the single
source of truth and every deployed query is a build artefact. This script does
that compilation and writes the result under ``build/<target>/``.

Backends differ in what they can express. When a backend cannot represent a
rule - the Lucene backend has no way to compare one field against another, for
example - that is recorded as ``unsupported`` rather than failing the build, so
that a rule is not held back from Splunk because Elasticsearch cannot take it.
A genuine error in the rule still fails.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.exceptions import (
    SigmaError,
    SigmaFeatureNotSupportedByBackendError,
    SigmaTransformationError,
)

from sigma.backends.elasticsearch import EqlBackend, LuceneBackend
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.elasticsearch import ecs_windows
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.pipelines.sysmon import sysmon_pipeline

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
BUILD_DIR = REPO_ROOT / "build"


@dataclass
class Target:
    """A deployment target: a backend plus the field-mapping pipelines it needs."""

    name: str
    backend_cls: type
    pipelines: list = field(default_factory=list)
    # Only convert rules whose logsource product is in this set; None means all.
    products: set[str] | None = None
    # Never convert rules whose logsource product is in this set.
    exclude_products: set[str] = field(default_factory=set)

    def build_backend(self):
        if self.pipelines:
            pipeline = self.pipelines[0]()
            for factory in self.pipelines[1:]:
                pipeline = pipeline + factory()
            return self.backend_cls(processing_pipeline=pipeline)
        return self.backend_cls()


TARGETS = [
    # Windows rules are mapped through Sysmon and then into each platform's
    # native Windows field names before conversion.
    Target("splunk-windows", SplunkBackend, [sysmon_pipeline, splunk_windows_pipeline], {"windows"}),
    Target("elastic-windows-lucene", LuceneBackend, [sysmon_pipeline, ecs_windows], {"windows"}),
    Target("elastic-windows-eql", EqlBackend, [sysmon_pipeline, ecs_windows], {"windows"}),
    # Defender XDR advanced hunting. Its schema has no equivalent of the
    # Windows Security channel, so domain controller rules land as unsupported.
    Target("defender-xdr", KustoBackend, [microsoft_xdr_pipeline], {"windows"}),
    # Cloud and Linux rules already use their platform's native field names,
    # so they are converted without a mapping pipeline.
    Target("splunk-cloud", SplunkBackend, [], None, {"windows"}),
    Target("elastic-cloud-lucene", LuceneBackend, [], None, {"windows"}),
]


def rule_files() -> list[Path]:
    return sorted(RULES_DIR.rglob("*.yml"))


def convert_all(fail_on_unsupported: bool = False) -> int:
    BUILD_DIR.mkdir(exist_ok=True)
    report: dict[str, dict[str, object]] = {}
    hard_errors = 0
    unsupported = 0

    for target in TARGETS:
        backend = target.build_backend()
        out_dir = BUILD_DIR / target.name
        out_dir.mkdir(parents=True, exist_ok=True)
        results: dict[str, object] = {}

        for path in rule_files():
            rel = str(path.relative_to(REPO_ROOT))
            collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
            rule = collection[0]
            product = rule.logsource.product
            out_of_scope = (target.products and product not in target.products) or (
                product in target.exclude_products
            )
            if out_of_scope:
                results[rel] = {"status": "skipped", "reason": "logsource out of scope for target"}
                continue
            try:
                queries = backend.convert(collection)
            except SigmaFeatureNotSupportedByBackendError as exc:
                unsupported += 1
                results[rel] = {"status": "unsupported", "reason": str(exc)}
                print(f"[SKIP] {target.name:22} {rel}: {exc}")
                continue
            except SigmaTransformationError as exc:
                # The rule is valid but the target's schema has no table or
                # field for this log source. That is a coverage gap in the
                # platform, not a defect in the rule.
                unsupported += 1
                reason = str(exc).splitlines()[0]
                results[rel] = {"status": "unsupported", "reason": reason}
                print(f"[SKIP] {target.name:22} {rel}: {reason}")
                continue
            except SigmaError as exc:
                hard_errors += 1
                results[rel] = {"status": "error", "reason": str(exc)}
                print(f"[FAIL] {target.name:22} {rel}: {exc}")
                continue

            query_file = out_dir / (path.stem + ".txt")
            query_file.write_text("\n".join(queries) + "\n", encoding="utf-8")
            results[rel] = {"status": "ok", "queries": queries}
            print(f"[ OK ] {target.name:22} {rel}")

        report[target.name] = results

    (BUILD_DIR / "conversion-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(f"\nerrors: {hard_errors}, unsupported: {unsupported}")
    print(f"report written to {(BUILD_DIR / 'conversion-report.json').relative_to(REPO_ROOT)}")

    if hard_errors:
        return 1
    if fail_on_unsupported and unsupported:
        return 1
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fail-on-unsupported",
        action="store_true",
        help="treat a backend limitation as a build failure",
    )
    args = parser.parse_args()
    raise SystemExit(convert_all(args.fail_on_unsupported))
