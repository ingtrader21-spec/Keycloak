from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIRED = ROOT / "config/desired-state/edge-integration-certification"
CONTRACT = DESIRED / "middleware-public-api-route-contract.v2.json"
PINNED = DESIRED / "middleware-public-api-route-contract.sha256"
AUTHORITY = DESIRED / "canonical-service-authority.v2.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(document: dict) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def test_authority_pins_the_exact_canonical_contract_and_cannot_activate_production():
    contract = load(CONTRACT)
    expected = digest(contract)
    authority = load(AUTHORITY)
    assert PINNED.read_text(encoding="utf-8").strip() == expected
    assert authority["contract"]["sha256"] == expected
    assert authority["contract"]["schema"] == contract["schema"]
    assert authority["productionActivationAuthorized"] is False
    assert authority["providerEffectsEnabled"] is False
    assert authority["secretsCommitted"] is False


def test_canonical_service_clients_have_only_reviewed_audiences_and_scopes():
    authority = load(AUTHORITY)
    clients = {row["clientId"]: row for row in authority["clients"]}
    assert set(clients) == {
        "middleware-api",
        "middleware-worker",
        "n8n-automation",
        "odoo-integration",
    }
    assert clients["middleware-api"]["audiences"] == ["middleware-api"]
    assert clients["middleware-api"]["scopes"] == ["telephony.commands.write"]
    assert clients["middleware-worker"]["audiences"] == ["codestra-odoo"]
    assert set(clients["middleware-worker"]["scopes"]) == {
        "odoo.campaign.actual_state.write",
        "odoo.integration.automation_results.write",
    }
    contract = load(CONTRACT)
    v2_scopes = {
        row["scope"]
        for row in contract["routes"]
        if row["classification"] == "shared_edge" and row["path"].startswith("/v2/automation/")
    }
    expected_n8n = v2_scopes | {"n8n.policy.check", "n8n.results.read", "n8n.results.submit"}
    assert clients["n8n-automation"]["audiences"] == ["middleware-api"]
    assert set(clients["n8n-automation"]["scopes"]) == expected_n8n
    assert clients["odoo-integration"]["audiences"] == ["middleware-api"]
    assert set(clients["odoo-integration"]["scopes"]) == {
        "odoo.campaigns.read",
        "odoo.events.publish",
    }
    for client in clients.values():
        assert client["fullScopeAllowed"] is False
        assert client["defaultClientScopes"] == []
        assert client["optionalClientScopes"] == []
        assert client["secretReference"].startswith("secret://")
        assert "odoo.campaign.control.write" not in client["scopes"]
        assert "telephony:command" not in client["scopes"]


def test_every_machine_route_grant_preserves_contract_audience_scope_and_azp():
    contract = load(CONTRACT)
    authority = load(AUTHORITY)
    expected = {
        row["operation_id"]: row
        for row in contract["routes"]
        if row["classification"] in {"shared_edge", "private_only"}
        and (
            row["path"].startswith("/v2/automation/")
            or row["calling_client"] in {"n8n-automation", "odoo-integration", "middleware-worker"}
        )
    }
    actual = {row["operation_id"]: row for row in authority["routeGrants"]}
    assert set(actual) == set(expected)
    for operation_id, row in actual.items():
        source = expected[operation_id]
        assert row["method"] == source["method"]
        assert row["path"] == source["path"]
        assert row["audience"] == source["audience"]
        assert row["scope"] == source["scope"]
        expected_azp = "n8n-automation" if source["path"].startswith("/v2/automation/") else source["calling_client"]
        assert row["azp"] == expected_azp


def test_no_integration_scope_is_realm_wide_default():
    authority = load(AUTHORITY)
    approved = {scope for row in authority["clients"] for scope in row["scopes"]}
    assert not approved.intersection(authority["realmDefaultClientScopes"])
    realm = load(ROOT / "config/realms/codestra.json")
    defaults = set(realm.get("defaultDefaultClientScopes", [])) | set(
        realm.get("defaultOptionalClientScopes", [])
    )
    assert not approved.intersection(defaults)


def test_unresolved_selector_names_are_human_readable_and_unambiguous():
    authority = load(AUTHORITY)
    selectors = authority["unresolvedHumanOrDelegatedAzpSelectors"]
    assert selectors
    assert all(not value.startswith('"') for value in selectors)
    assert selectors == sorted(set(selectors))
