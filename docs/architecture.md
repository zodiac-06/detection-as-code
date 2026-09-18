# Architecture

## Why the YAML is the source of truth

A detection written in a SIEM console has no history, no review and no tests. You
cannot tell why a filter was added, whether last month's tuning broke the
detection, or how to move the logic to a second platform without rewriting it.
Putting the rules in Git fixes the history and the review. It fixes nothing else
unless something in the pipeline actually checks them, which is what this
repository is.

The rules in `rules/` are the only hand-written detection logic. Everything under
`build/` is generated and gitignored, and every deployed query is compiled from
the YAML at deploy time. There is deliberately no path by which a query reaches
production without passing through the gate.

## The four stages

**Validate** (`tools/validate_rules.py`) is a linter for rule metadata. It checks
what makes a rule reviewable and triageable rather than merely parseable: unique
UUIDs, a substantive description, references, stated false positives, a real
ATT&CK technique tag, a filename matching the log source, and the
`filter_main_` / `filter_optional_` naming convention that tells the next team
which exclusions are safe to edit. Everything here is a hard failure, because
each one is something a reviewer would otherwise have to catch by hand on every
pull request.

**Test** (`tools/rule_tests.py`, `tools/sigma_eval.py`) evaluates each rule
against fixtures of events it must catch and events it must not. pySigma parses
and converts Sigma but ships no matcher, so `sigma_eval.py` walks the condition
tree pySigma produces and evaluates it against a Python dictionary. It handles
`ConditionAND` / `OR` / `NOT` and the leaf value types — wildcards, regular
expressions, CIDR, numeric comparison, `null`, `exists`, expansions and
field-to-field references — with dotted field names resolved into nested
structures, including element-wise descent into lists, which is what CloudTrail
and Entra audit records need.

The design point is that the evaluator lives in `tools/` with its own CLI rather
than inside the test file. `make test` runs it without pytest installed, and
`tests/test_rules.py` is a thin parametrised wrapper so CI, IDEs and coverage
tooling see individual cases. The suite also fails if a rule has no fixture at
all, or has fixtures of only one polarity.

**Compile** (`tools/convert.py`) turns each rule into the query languages the SOC
runs. A target is a backend plus an ordered list of field-mapping pipelines plus
a log source scope: Windows rules pass through the Sysmon pipeline and then into
Splunk's, Elastic's or Defender's field names, while cloud and Linux rules use
their platform's native names and need no mapping. The four-state classification
(`ok`, `skipped`, `unsupported`, `error`) is what keeps a backend limitation from
being confused with a broken rule; see [backend-support.md](backend-support.md).

**Deploy** (`deploy/sentinel.py`) publishes each compiled query as a Sentinel
scheduled analytics rule keyed on the Sigma UUID, so redeployment is idempotent.
Rule `status` maps to whether the analytics rule arrives enabled, `level` maps to
Sentinel severity, and the ATT&CK tags are carried through as native tactics and
techniques so the alerts land on the right part of the matrix in the portal. The
script uses only the standard library, so the step that touches production has no
third-party dependency of its own.

## What CI enforces

`ci.yml` runs validate, test and compile on every pull request and writes a
per-backend summary table into the run summary, then uploads the compiled queries
as an artefact so a reviewer can read the exact SPL or KQL a change produces
without running anything locally. It also re-runs the coverage generator with
`--check`, which fails if `docs/attack-coverage.md` was not regenerated — a
coverage claim that drifts from the rules is worse than no coverage claim.

`deploy.yml` runs on merge to `main` and re-runs the whole gate before deploying.
That is redundant with the pull request run by design: branch protection can be
changed, and the deployment job is the last place to catch it. A concurrency
group prevents two deployments from racing for the same analytics rules.

## Deliberate limitations

Sigma correlation rules (aggregation over a time window) are not used. Several of
these detections would be sharper as thresholds — one RC4 Kerberos ticket is
weak, twenty in a minute is conclusive — but correlation support varies enough
between backends that it would undermine the "compiles everywhere" property. The
aggregation belongs in the SIEM's own alert configuration for now.

Fixtures are synthetic. They prove the rule's logic is what the author intended;
they do not prove the field names match what a given sensor actually emits. That
is what the deployment soak period and the `experimental` status are for.
