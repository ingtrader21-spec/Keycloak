from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/contracts/campaign-recycling-access.v1.json"


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _client_scopes(client_id: str) -> set[str]:
    client = _json(ROOT / "config/clients" / f"{client_id}.json")
    mapper = next(
        item for item in client["protocolMappers"]
        if item["name"] == "reviewed-service-scopes"
    )
    return set(mapper["config"]["claim.value"].split())


def test_all_mcr_scopes_are_explicit_optional_scope_definitions() -> None:
    contract = _json(CONTRACT)
    for scope in contract["scopes"]:
        definition = _json(ROOT / "config/client-scopes" / f"{scope}.json")
        assert definition["name"] == scope
        assert definition["protocol"] == "openid-connect"
        assert definition["attributes"]["include.in.token.scope"] == "true"
        assert definition["protocolMappers"] == []


def test_mcr_operation_scope_contract_is_exact_and_execute_stays_closed() -> None:
    contract = _json(CONTRACT)
    assert contract["production_execution_authorized"] is False
    assert contract["provider_effects_enabled"] is False
    assert contract["operations"] == {
        "POST /platform/v1/campaign-engine/plan": "campaign.engine.plan",
        "POST /platform/v1/campaign-engine/execute": "campaign.engine.execute",
        "GET /platform/v1/leads/{lead_id}/journey": "leads.journey.read",
        "GET /platform/v1/leads/{lead_id}/next-action": "campaign.engine.read",
        "GET /platform/v1/campaigns/{campaign_id}/eligible-leads": "campaign.engine.read",
        "POST /platform/v1/delivery-events": "campaign.delivery_events.publish",
        "POST /platform/v1/suppressions": "campaign.suppressions.write",
        "GET /platform/v1/campaign-engine/status": "campaign.engine.read",
    }


def test_provider_gateways_only_gain_delivery_event_publish() -> None:
    for client in ("klyrow-gateway", "telnexa-gateway"):
        scopes = _client_scopes(client)
        assert "campaign.delivery_events.publish" in scopes
        assert "campaign.engine.execute" not in scopes
        assert "campaign.engine.plan" not in scopes
        assert "campaign.engine.candidates.read" not in scopes
        assert "campaign.suppressions.write" not in scopes


def test_odoo_gets_read_and_suppression_not_execution() -> None:
    scopes = _client_scopes("odoo-integration")
    assert {
        "campaign.engine.read",
        "campaign.suppressions.write",
        "leads.journey.read",
    } <= scopes
    assert "campaign.engine.execute" not in scopes
    assert "campaign.engine.plan" not in scopes
    assert "campaign.engine.candidates.read" not in scopes


def test_automation_workers_do_not_gain_mcr_decision_authority() -> None:
    forbidden = {
        "campaign.engine.plan",
        "campaign.engine.execute",
        "campaign.engine.read",
        "campaign.engine.candidates.read",
        "campaign.suppressions.write",
        "leads.journey.read",
    }
    for client in ("n8n-automation", "middleware-worker"):
        assert not (_client_scopes(client) & forbidden)


def test_contract_grants_match_client_files() -> None:
    contract = _json(CONTRACT)
    for client, expected in contract["client_grants"].items():
        assert set(expected) <= _client_scopes(client)
