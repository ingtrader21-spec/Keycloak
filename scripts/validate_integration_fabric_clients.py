#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def validate() -> None:
    path = ROOT / "config" / "contracts" / "integration-fabric-service-clients-v2.json"
    with path.open("r", encoding="utf-8") as handle:
        contract = json.load(handle)

    assert contract["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert contract["audience"] == "middleware-api"
    assert contract["provisioning_state"] == "declared-not-created"
    assert contract["maximum_access_token_lifetime_seconds"] <= 300

    ids: set[str] = set()
    for client in contract["clients"]:
        client_id = client["client_id"]
        assert client_id not in ids
        ids.add(client_id)
        assert "automation.execute" not in client.get("scopes", [])
        assert "automation.command" not in client.get("scopes", [])

    beyvra = next(client for client in contract["clients"] if client["client_id"] == "n8n-beyvra-automation")
    assert beyvra["workflow_families"] == ["product.beyvra-nonfinancial"]
    assert beyvra["command_prefixes"] == ["beyvra.operations."]
    assert "wallet." in beyvra["forbidden_prefixes"]

    contact = next(client for client in contract["clients"] if client["client_id"] == "n8n-contact-center-automation")
    assert contact["cell"] == "telephony-private"
    assert "automation.command.telephony" in contact["scopes"]

    defaults = contract["client_defaults"]
    assert defaults["standard_flow_enabled"] is False
    assert defaults["direct_access_grants_enabled"] is False
    assert defaults["secrets_in_git"] is False


if __name__ == "__main__":
    validate()
    print("INTEGRATION_FABRIC_CLIENTS=PASS")
