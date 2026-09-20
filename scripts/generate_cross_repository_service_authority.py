from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DESIRED = ROOT / "config/desired-state/edge-integration-certification"
CONTRACT_PATH = DESIRED / "middleware-public-api-route-contract.v2.json"
PIN_PATH = DESIRED / "middleware-public-api-route-contract.sha256"
OUTPUT_PATH = DESIRED / "canonical-service-authority.v2.json"


def digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def client(client_id: str, audiences: set[str], scopes: set[str]) -> dict[str, Any]:
    return {
        "clientId": client_id,
        "audiences": sorted(audiences),
        "scopes": sorted(scopes),
        "serviceAccountsEnabled": True,
        "fullScopeAllowed": False,
        "defaultClientScopes": [],
        "optionalClientScopes": [],
        "secretReference": f"secret://keycloak/{client_id}",
        "productionActivationAuthorized": False,
    }


def selector_name(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def main() -> None:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    actual = digest(contract)
    pinned = PIN_PATH.read_text(encoding="utf-8").strip()
    if actual != pinned:
        raise SystemExit(f"contract digest mismatch: pinned={pinned} actual={actual}")

    v2_rows = [
        row
        for row in contract["routes"]
        if row["classification"] == "shared_edge" and row["path"].startswith("/v2/automation/")
    ]
    machine_rows = [
        row
        for row in contract["routes"]
        if row["classification"] in {"shared_edge", "private_only"}
        and (
            row["path"].startswith("/v2/automation/")
            or row["calling_client"] in {"n8n-automation", "odoo-integration", "middleware-worker"}
        )
    ]

    n8n_scopes = {row["scope"] for row in v2_rows}
    n8n_scopes.update({"n8n.policy.check", "n8n.results.read", "n8n.results.submit"})
    document = {
        "schema": "codestra.keycloak.canonical-service-authority.v2",
        "contract": {"schema": contract["schema"], "sha256": actual},
        "productionActivationAuthorized": False,
        "providerEffectsEnabled": False,
        "secretsCommitted": False,
        "realmDefaultClientScopes": [],
        "clients": [
            client("middleware-api", {"middleware-api"}, {"telephony.commands.write"}),
            client(
                "middleware-worker",
                {"codestra-odoo"},
                {
                    "odoo.campaign.actual_state.write",
                    "odoo.integration.automation_results.write",
                },
            ),
            client("n8n-automation", {"middleware-api"}, n8n_scopes),
            client(
                "odoo-integration",
                {"middleware-api"},
                {"odoo.campaigns.read", "odoo.events.publish"},
            ),
        ],
        "routeGrants": [
            {
                "operation_id": row["operation_id"],
                "method": row["method"],
                "path": row["path"],
                "audience": row["audience"],
                "scope": row["scope"],
                "azp": "n8n-automation" if row["path"].startswith("/v2/automation/") else row["calling_client"],
            }
            for row in machine_rows
        ],
        "unresolvedHumanOrDelegatedAzpSelectors": sorted(
            {
                selector_name(row["calling_client"])
                for row in contract["routes"]
                if row["classification"] == "shared_edge"
                and row not in machine_rows
                and not row["path"].startswith("/v2/automation/")
                and row["calling_client"] not in {"n8n-automation", "odoo-integration", "middleware-worker"}
            }
        ),
        "notes": [
            "Repository-only desired state; no realm apply is authorized.",
            "The n8n-automation grant intentionally resolves every /v2/automation operation to the canonical automation identity.",
            "Human/operator and delegated client-family selectors remain unresolved until separately reviewed Keycloak clients are named.",
        ],
    }
    OUTPUT_PATH.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"generated {len(machine_rows)} route grants ({actual})")


if __name__ == "__main__":
    main()
