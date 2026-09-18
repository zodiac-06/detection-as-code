# Writing a rule for this repository

## The shape of a good rule

Start from the behaviour, not from the tool. "Detect Mimikatz" ages out the
moment someone renames the binary; "detect a process opening LSASS with read
permissions it has no reason to hold" survives. Every rule here is written
against something the attacker has to do rather than something they happened to
use, and where that is not possible the rule says so in its description.

The description is the part most rules get wrong. An analyst reading the alert at
three in the morning needs to know what the technique achieves for the attacker
and what would make this particular firing benign, and neither of those is
recoverable from the detection logic. `tools/validate_rules.py` enforces a
minimum length for that reason, but length is not the point — a description that
restates the selection in English is worthless no matter how long it is.

State the false positives honestly. A rule with an empty `falsepositives` list is
either untuned or untested, and the linter rejects it. If you do not know what
the benign version looks like, you have not finished the rule.

## Naming

Filenames carry the log source so a rule can be located from an alert without
opening it:

| Log source | Prefix |
| --- | --- |
| Windows process creation | `proc_creation_win_` |
| Windows file events | `file_event_win_` |
| Windows Security channel | `win_security_` |
| Linux process creation | `proc_creation_lnx_` |
| AWS CloudTrail | `aws_` |
| Azure / Entra audit logs | `azure_` |

Detection blocks that select events are named `selection*`. Blocks that remove
them come in two flavours, and the distinction is load-bearing:
`filter_main_*` is required for the rule to be correct and must not be removed,
while `filter_optional_*` is environment tuning that the next team to adopt the
rule is expected to edit. Encoding that in the name means nobody has to guess
which exclusions are safe to drop.

Generate the UUID with `python -c "import uuid; print(uuid.uuid4())"` and never
reuse one. The UUID is what Sentinel uses as the analytics rule's resource name,
so changing it orphans the deployed rule and creates a duplicate.

## Writing the fixture

Every rule needs `tests/data/<rule-stem>.yml` with at least one true positive and
at least one false positive; the suite fails if either polarity is missing,
because a rule that has only ever been shown to fire has not been shown to be
selective.

```yaml
rule: rules/linux/process_creation/proc_creation_lnx_example.yml
true_positive:
    - name: what the attacker actually did
      event:
          _logsource: {product: linux, category: process_creation}
          Image: '/usr/bin/bash'
          CommandLine: '...'
false_positive:
    - name: the benign thing that looks just like it
      event:
          _logsource: {product: linux, category: process_creation}
          Image: '/usr/bin/bash'
          CommandLine: '...'
```

Write the false positives from the `falsepositives` list in the rule. If the rule
says ASP.NET compilation will trigger it, there should be a fixture proving the
filter handles ASP.NET compilation. That is what stops a future tuning change
from silently removing the protection.

The optional `_logsource` key is checked against the rule's own log source, so a
typo in a fixture fails loudly instead of producing a negative test that passes
for the wrong reason.

Use realistic values. Documentation IP ranges (`198.51.100.0/24`,
`203.0.113.0/24`) and invented hostnames keep real infrastructure out of a public
repository.

## Before opening the pull request

```bash
make all
```

That runs the linter, the fixtures, the compilation across every backend and the
coverage map. If a backend reports your rule as `unsupported`, read
[backend-support.md](backend-support.md) before changing the rule — the
limitation may be real and acceptable, or it may be avoidable by restructuring
the condition.

Commit the regenerated `docs/attack-coverage.md`. CI fails if it is stale.

## Promoting a rule

New rules land as `status: experimental`, which deploys them to Sentinel in a
disabled state. Once a rule has run against production data long enough to know
its false positive rate, move it to `status: test` and then `stable`, tightening
the filters with what you learned. The status field is not decoration: it is what
the deployment script reads to decide whether the rule is enabled on arrival.
