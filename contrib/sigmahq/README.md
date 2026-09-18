# Upstream contribution: MCP server configuration tampering

`file_event_win_mcp_server_config_modification.yml` in this directory is the
SigmaHQ-flavoured copy of the rule in
`rules/windows/file_event/`. It is kept separate because the upstream project
uses a different directory layout and a different licence, and because the
author field has to be yours before it is submitted.

## Why this rule is worth submitting

SigmaHQ carries over 3,100 rules and the AI tooling category is barely covered.
At the time of writing the only rule touching agentic developer tooling is
`proc_creation_win_node_new_agent_skills_installed.yml`, which catches
`npx skills add`. Nothing covers the Model Context Protocol configuration files,
even though writing to one is a cleaner persistence primitive than installing a
skill: the agent launches the declared server automatically at startup, under a
trusted parent process, with whatever command line and environment the file
specifies.

Verify the gap yourself before submitting, since upstream moves quickly:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
cd sigma
grep -ril "mcp.json\|claude_desktop_config\|mcp_config" rules*/
```

An empty result means the gap is still open. If something has appeared, read it
and decide whether this rule adds coverage or duplicates it — a duplicate will be
closed, and proposing a refinement to the existing rule is the better move.

## Before you open the pull request

Replace the author line with your own name and GitHub handle. Upstream will not
merge a placeholder, and the author field is how you get credit for the rule,
which is the entire point of doing this.

Then run their test suite, which this rule already passes:

```bash
cp file_event_win_mcp_server_config_modification.yml \
   /path/to/sigma/rules/windows/file/file_event/
cd /path/to/sigma
python tests/test_rules.py
python tests/test_logsource.py
pip install sigma-cli pysigma-validators-sigmahq
sigma check --fail-on-error --fail-on-issues \
  --validation-config tests/sigma_cli_conf.yml rules/
```

Note the upstream path is `rules/windows/file/file_event/`, with `file/` in it,
which differs from the flatter layout used in this repository.

## Submitting

```bash
# fork SigmaHQ/sigma on GitHub first, then:
git clone https://github.com/<your-handle>/sigma.git
cd sigma
git remote add upstream https://github.com/SigmaHQ/sigma.git
git checkout -b rule-mcp-server-config-tampering
cp /path/to/file_event_win_mcp_server_config_modification.yml \
   rules/windows/file/file_event/
git add rules/windows/file/file_event/file_event_win_mcp_server_config_modification.yml
git commit -m "Add rule for MCP server configuration modification by uncommon process"
git push origin rule-mcp-server-config-tampering
gh pr create --repo SigmaHQ/sigma --fill
```

## Suggested pull request description

> **New rule: MCP Server Configuration Modified By Uncommon Process**
>
> Model Context Protocol configuration files (`claude_desktop_config.json`,
> `.cursor/mcp.json`, `.vscode/mcp.json`, `.mcp.json`, and the Windsurf and
> Gemini CLI equivalents) declare the external servers an AI coding agent is
> permitted to launch, along with the command line and environment used to start
> each one. An attacker who can write to one of these files registers a server
> that the agent executes on the user's behalf at next startup, which gives code
> execution and persistence under a trusted parent process, and places the
> attacker in the path of every prompt, file and credential the agent handles.
>
> The rule alerts on the *writing process* rather than on file contents, because
> a malicious configuration is syntactically identical to a legitimate one. The
> IDE and assistant binaries that own these files are excluded in
> `filter_main_owning_apps`, and package managers that write them during a
> supported "add server" flow are excluded in `filter_optional_installers`, which
> environments with centrally managed MCP servers will want to remove.
>
> Related existing coverage: `proc_creation_win_node_new_agent_skills_installed.yml`
> covers agent *skill* installation via npx; this covers the MCP server
> configuration path, which is a different mechanism.
>
> Tested with `tests/test_rules.py` and `tests/test_logsource.py`. No regression
> test data included — generating it needs a Windows host with Sysmon, and I do
> not have one available.

## What to expect

Maintainers will review within days to a few weeks. Common requests are
tightening the false positive filters, adjusting the level, or renaming the
file. Answer promptly and make the changes; a merged rule with your handle in
the author field is a citable contribution to a project used by SOC teams
worldwide, which is worth considerably more on a CV than another repository of
your own.
