# Backend support and its limits

A Sigma rule is not a query. It is a description of a detection that a backend
translates into whichever query language a platform speaks, and those languages
do not have the same expressive power. This document records where that matters
for this rule set, because a pipeline that pretends every backend is equivalent
will either block good rules or ship broken queries.

## How the pipeline classifies a conversion

`tools/convert.py` puts every rule/target pair into one of four buckets, all of
which land in `build/conversion-report.json`.

`ok` means a query was produced and written to `build/<target>/`.

`skipped` means the rule's log source is out of scope for that target: there is
no point compiling a CloudTrail rule through the Sysmon field-mapping pipeline.

`unsupported` means the backend understands the rule but cannot express it. This
does **not** fail the build. A rule that Splunk can run should not be held back
because Elasticsearch cannot take it, and treating a platform limitation as a
rule defect is how teams end up writing to the weakest common denominator.

`error` means the rule itself is wrong, and that does fail the build.

## Limitations this rule set actually hits

**Elasticsearch Lucene cannot compare one field against another.** The AWS
access key rule needs `requestParameters.userName` compared to
`userIdentity.userName`, because the whole signal is that a principal created a
key for somebody else. Lucene has no syntax for that, so the rule converts for
Splunk — which handles it with a trailing `| where` clause — and is reported as
unsupported for Lucene. Deploying it to Elasticsearch means either running an
ES|QL query instead, or moving the comparison into an ingest-time enrichment
field.

**Splunk cannot OR a field reference into a larger expression.** An earlier
version of the same rule used `condition: selection and not 1 of filter_*`, which
made pySigma OR the field-reference filter together with the others and pushed
the Splunk backend past what it can emit. Keeping the field reference as its own
`not` term produces a valid query. The lesson generalises: when a rule uses an
exotic modifier, give that modifier its own condition term rather than folding it
into a `1 of` group.

**Defender XDR has no Windows Security channel.** The Kerberoasting rule reads
event 4769 from a domain controller's Security log, and the Defender advanced
hunting schema has no table for it, so the Kusto backend cannot determine a
table name. That surfaces as `unsupported` for the `defender-xdr` target while
the rule still compiles for Splunk and both Elasticsearch targets. The fix is a
data problem, not a rule problem: forward domain controller security events into
a workspace that has a table for them.

## A Splunk quirk worth knowing

Generated SPL looks wrong the first time you read it:

```
ParentImage IN (...) Image IN (...) OR OriginalFileName IN (...) NOT (...)
```

In most languages `AND` binds tighter than `OR`, and this would parse as
`(Parent AND Image) OR OriginalFileName`, which is not the rule. Splunk's
`search` command evaluates in the order `NOT`, `OR`, `AND`, so the `OR` group
binds first and the query means what the Sigma rule says. The parentheses are
absent because they are genuinely unnecessary here — but this only holds for
`search`. The `where` command uses conventional precedence, which is one more
reason the trailing `| where` clause in the AWS rule is kept as a separate term.

## Adding a target

Append a `Target` to `TARGETS` in `tools/convert.py` with its backend class, the
processing pipelines to apply in order, and either an allow-list of log source
products or an exclusion set. Re-run `make build` and check the new column in the
conversion report before wiring it into deployment.
