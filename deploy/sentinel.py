"""Deploy compiled rules to Microsoft Sentinel as scheduled analytics rules.

This is the last stage of the pipeline: ``tools/convert.py`` produces KQL under
``build/defender-xdr/``, and this script publishes each query as a Sentinel
analytics rule whose resource name is the Sigma rule's UUID. Because the UUID is
stable, re-running the deployment updates the existing rule in place instead of
creating duplicates, which is what makes the repository - not the portal - the
source of truth.

Authentication uses a service principal via the client credentials flow. Grant
it the ``Microsoft Sentinel Contributor`` role on the workspace and nothing
else. Only the standard library is used so that the deployment step has no
dependency that could itself need patching.

Environment:
    AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
    AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, SENTINEL_WORKSPACE

Usage:
    python deploy/sentinel.py --dry-run
    python deploy/sentinel.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
QUERY_DIR = REPO_ROOT / "build" / "defender-xdr"
API_VERSION = "2023-02-01"

SEVERITY = {
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "High",  # Sentinel has no Critical severity.
}

TACTIC_NAMES = {
    "initial-access": "InitialAccess",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "PrivilegeEscalation",
    "defense-evasion": "DefenseEvasion",
    "credential-access": "CredentialAccess",
    "discovery": "Discovery",
    "lateral-movement": "LateralMovement",
    "collection": "Collection",
    "command-and-control": "CommandAndControl",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


class DeploymentError(RuntimeError):
    pass


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise DeploymentError(f"missing required environment variable {name}")
    return value


def get_token() -> str:
    tenant = require_env("AZURE_TENANT_ID")
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": require_env("AZURE_CLIENT_ID"),
            "client_secret": require_env("AZURE_CLIENT_SECRET"),
            "scope": "https://management.azure.com/.default",
        }
    ).encode()
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return json.load(response)["access_token"]


def rule_payload(raw: dict, query: str) -> dict:
    tags = [str(tag) for tag in raw.get("tags") or []]
    tactics = [
        TACTIC_NAMES[tag[len("attack.") :]]
        for tag in tags
        if tag.startswith("attack.") and tag[len("attack.") :] in TACTIC_NAMES
    ]
    techniques = sorted(
        {
            tag[len("attack.") :].upper().split(".")[0]
            for tag in tags
            if tag.startswith("attack.t")
        }
    )
    description = (raw.get("description") or "").strip()
    references = "\n".join(f"- {ref}" for ref in raw.get("references") or [])
    false_positives = "\n".join(f"- {fp}" for fp in raw.get("falsepositives") or [])

    return {
        "kind": "Scheduled",
        "properties": {
            "displayName": raw["title"],
            "description": f"{description}\n\nReferences:\n{references}\n\nKnown false positives:\n{false_positives}"[
                :5000
            ],
            "severity": SEVERITY.get(raw.get("level", "medium"), "Medium"),
            "enabled": raw.get("status") in {"stable", "test"},
            "query": query,
            "queryFrequency": "PT1H",
            "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "tactics": sorted(set(tactics)),
            "techniques": techniques,
            "alertRuleTemplateName": None,
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": True,
                    "reopenClosedIncident": False,
                    "lookbackDuration": "PT5H",
                    "matchingMethod": "AllEntities",
                },
            },
        },
    }


def iter_deployable() -> list[tuple[Path, dict, str]]:
    deployable = []
    for path in sorted(RULES_DIR.rglob("*.yml")):
        query_file = QUERY_DIR / (path.stem + ".txt")
        if not query_file.exists():
            print(f"[skip] {path.name}: no compiled query for this target")
            continue
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        deployable.append((path, raw, query_file.read_text(encoding="utf-8").strip()))
    return deployable


def deploy(dry_run: bool) -> int:
    if not QUERY_DIR.exists():
        raise DeploymentError(f"{QUERY_DIR} does not exist; run tools/convert.py first")

    deployable = iter_deployable()
    if not deployable:
        raise DeploymentError("nothing to deploy")

    if dry_run:
        for path, raw, query in deployable:
            payload = rule_payload(raw, query)
            print(f"--- {raw['id']}  {path.name}")
            print(json.dumps(payload, indent=2))
        print(f"\n{len(deployable)} rule(s) would be deployed")
        return 0

    subscription = require_env("AZURE_SUBSCRIPTION_ID")
    resource_group = require_env("AZURE_RESOURCE_GROUP")
    workspace = require_env("SENTINEL_WORKSPACE")
    token = get_token()

    failures = 0
    for path, raw, query in deployable:
        payload = rule_payload(raw, query)
        url = (
            f"https://management.azure.com/subscriptions/{subscription}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
            f"/providers/Microsoft.SecurityInsights/alertRules/{raw['id']}"
            f"?api-version={API_VERSION}"
        )
        request = urllib.request.Request(
            url, data=json.dumps(payload).encode(), method="PUT"
        )
        request.add_header("Authorization", f"Bearer {token}")
        request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                status = response.status
            print(f"[ OK ] {status} {raw['id']}  {raw['title']}")
        except urllib.error.HTTPError as exc:
            failures += 1
            detail = exc.read().decode(errors="replace")[:400]
            print(f"[FAIL] {exc.code} {raw['id']}  {raw['title']}: {detail}")

    print(f"\n{len(deployable) - failures}/{len(deployable)} rule(s) deployed")
    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="print payloads without calling Azure")
    args = parser.parse_args()
    try:
        sys.exit(deploy(args.dry_run))
    except DeploymentError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(2)
