# Contributing

Read [docs/writing-rules.md](docs/writing-rules.md) first; it covers the rule
format, naming and fixtures in detail. This file is the process.

## Before you open a pull request

```bash
pip install -r requirements.txt
make all
```

Everything must pass. `make all` runs the linter, the rule fixtures, the
compilation across every backend and the coverage generator, and takes a few
seconds.

Commit the regenerated `docs/attack-coverage.md` along with your rule. CI fails
if it is stale.

## What a reviewer will ask

Whether the detection targets a behaviour the attacker cannot easily avoid,
rather than a tool they can rename. Whether the description explains what the
technique buys the attacker and what a benign firing looks like. Whether each
entry in `falsepositives` has a matching fixture proving the filter handles it.
Whether the exclusions are in `filter_main_*` because the rule is wrong without
them, or in `filter_optional_*` because they are specific to one environment.

## Scope

New rules should come with a reference an analyst can read — a vendor advisory,
an ATT&CK page, a research writeup. A rule with no external reference is a rule
nobody else can evaluate.

Please do not commit real hostnames, internal IP ranges, usernames or sample
hashes from a live environment. Fixtures use documentation ranges
(`198.51.100.0/24`, `203.0.113.0/24`) and invented names.

## Contributing upstream

Rules here that are general enough to help other defenders belong in
[SigmaHQ](https://github.com/SigmaHQ/sigma) as well. Check their
`CONTRIBUTING.md` and rule style guide, confirm nothing in `rules/` already
covers the behaviour, and note in the pull request here when a rule has been
submitted upstream so the two do not drift.
