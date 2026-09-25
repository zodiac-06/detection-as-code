# detection-as-code

A detection engineering pipeline that treats Sigma rules the way a software team
treats source code: every rule is reviewed in a pull request, every rule has
unit tests that prove it fires on the attack and stays quiet on the benign
lookalike, every deployed query is a build artefact compiled from the YAML, and
nothing reaches production without passing the same gate twice.

The problem this solves is the one every SOC eventually hits. Detections get
written directly in the SIEM console, so there is no history of why a filter was
added, no way to tell whether last month's tuning quietly broke the detection,
and no way to move the same logic to a second platform without rewriting it by
hand. Putting the rules in Git only helps if something actually checks them, so
the interesting part of this repository is not the rules — it is the gate.

```
rules/*.yml ──► validate ──► unit test ──► compile ──► deploy
   Sigma        metadata      fires on      Splunk      Sentinel
   source       + naming      TP, silent    Elastic     analytics
   of truth     + hygiene     on FP         Kusto       rules
```

## What is in here

Six rules covering Windows endpoints, a domain controller, Linux and two cloud
control planes, spread across eight ATT&CK techniques — see
[docs/attack-coverage.md](docs/attack-coverage.md), which is generated from the
rules themselves so it cannot drift.

| Rule | Log source | ATT&CK |
| --- | --- | --- |
| MCP server configuration modified by uncommon process | Windows file events | T1546, T1059 |
| Command shell spawned by web server worker process | Windows process creation | T1505.003 |
| Kerberoasting — RC4 service ticket for a user account | Windows Security 4769 | T1558.003 |
| Interactive reverse shell one-liner | Linux process creation | T1059.004 |
| AWS access key created for a different IAM user | CloudTrail | T1098.001 |
| Entra ID consent granted to app with high privilege scopes | Entra audit logs | T1528 |

The first one is the reason this repository exists. AI coding assistants read
their list of permitted tool servers from a plain JSON file on disk — 
`claude_desktop_config.json`, `.cursor/mcp.json`, `.mcp.json` and friends. Anyone
who can write to that file can register a server that the assistant will launch
on the user's behalf, under a trusted parent process, every time it starts. It is
a persistence primitive sitting in a developer's home directory with no
detection coverage in the public rule sets, so the rule alerts on *who wrote the
file* rather than on its contents, which are indistinguishable from a legitimate
configuration.

## Running it

```bash
pip install -r requirements.txt
make all
```

`make all` runs the four stages in order and takes a few seconds:

`make lint` checks every rule for the things that make a rule triageable at
three in the morning — a valid and unique UUID, a description that explains the
*why* and not just the *what*, at least one reference an analyst can read, stated
false positives, a real ATT&CK technique tag, a filename that matches its log
source, and filter blocks named `filter_main_*` (required for correctness) or
`filter_optional_*` (environment tuning someone else will want to change).

`make test` is the part most Sigma repositories do not have. Each rule has a
fixture in `tests/data/` holding the events it must catch and the benign events
it must not, and `tools/sigma_eval.py` evaluates the parsed rule against them
directly. pySigma parses and converts rules but ships no matcher, so this module
walks the condition tree itself and handles wildcards, regular expressions,
CIDR, numeric comparison, `null`, `exists` and field-to-field references, with
dotted field paths resolved into nested JSON so CloudTrail and Entra records work
unflattened. A tightened filter that silently kills a detection fails the build
instead of failing in production.

`make build` compiles every rule into Splunk SPL, Elasticsearch Lucene, Elastic
EQL and Kusto, applying the Sysmon and platform field-mapping pipelines on the
way, and writes the queries under `build/` with a JSON report. Backends differ in
what they can express, so a rule a backend cannot represent is recorded as
`unsupported` rather than failing the build — see
[docs/backend-support.md](docs/backend-support.md) for why that distinction
matters and which limitations this rule set actually hits.

`make coverage` regenerates the ATT&CK table and an ATT&CK Navigator layer.

## Deployment

`deploy/sentinel.py` publishes each compiled query as a Microsoft Sentinel
scheduled analytics rule whose resource name is the Sigma rule's UUID. Because
that UUID is stable, redeploying updates the rule in place rather than creating
duplicates, which is what makes this repository rather than the portal the source
of truth. Rules with `status: experimental` deploy disabled, so a new detection
lands in the workspace ready to enable after a soak period instead of paging
someone the night it merges.

Try it without an Azure subscription:

```bash
make deploy-dry
```

The GitHub Actions workflows wire the same commands together: `ci.yml` runs
lint, tests and compilation on every pull request and posts a per-backend
summary, and `deploy.yml` re-runs the entire gate on merge to `main` before
touching production, with a concurrency group so two deployments never race.
The deploy job is gated behind the repository variable
`ENABLE_SENTINEL_DEPLOY` — it skips cleanly until that is set to `true`, so
merges to `main` do not fail against a Sentinel workspace that does not exist
yet. Set the variable once the workspace and Azure credentials are in place.

## Writing a new rule

[docs/writing-rules.md](docs/writing-rules.md) has the full walkthrough. The
short version: write the rule, write the fixture with at least one true positive
and one false positive, run `make all`, and open a pull request.

## Licence

MIT — see [LICENSE](LICENSE). Rules are written to be lifted into other
environments; upstream contributions to [SigmaHQ](https://github.com/SigmaHQ/sigma)
are dual-licensed under the Detection Rule License as that project requires.
