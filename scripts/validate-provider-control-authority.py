#!/usr/bin/env python3
"""Validate exact Keycloak authority for the Middleware provider control plane."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "contracts" / "service-access-matrix.json"
EXPECTED_APPLICATION_GRANTS = {
    ("codestra-ai", "middleware-api"): {"ai.inference.request"},
    ("codestra-communication", "middleware-api"): {
        "communication.email.request", "communication.sms.request",
    },
    ("codestra-marketing", "middleware-api"): {"marketing.campaign.request"},
    ("codestra-social", "middleware-api"): {"social.publish.request"},
    ("n8n-automation", "middleware-api"): {
        "automation.command.request", "workflow.result.publish",
    },
    ("odoo-integration", "middleware-api"): {
        "odoo.delivery.result.publish", "odoo.events.publish",
    },
}
EXPECTED_PROVIDER_GRANTS = {
    ("middleware-worker", "ai-provider-adapter"): {"ai.provider.dispatch"},
    ("middleware-worker", "marketing-provider-adapter"): {"marketing.provider.dispatch"},
    ("middleware-worker", "klyrow-gateway"): {"email.send", "email.status.read"},
    ("middleware-worker", "telnexa-gateway"): {"sms.send", "sms.status.read"},
    ("middleware-worker", "postly-adapter"): {"social.publish", "social.status.read"},
}
PROVIDER_TARGETS = {target for _caller, target in EXPECTED_PROVIDER_GRANTS}


def validate(contract: dict) -> None:
    if contract.get("issuer") != "https://auth.codestra.co/realms/codestra":
        raise ValueError("canonical issuer drift")
    services = {item["clientId"]: item for item in contract.get("services", [])}
    grants: dict[tuple[str, str], set[str]] = {}
    for grant in contract.get("grants", []):
        key = (grant.get("callerClientId"), grant.get("targetClientId"))
        if key in grants:
            raise ValueError(f"duplicate grant: {key}")
        if grant.get("audience") != grant.get("targetClientId"):
            raise ValueError(f"audience drift: {key}")
        grants[key] = set(grant.get("scopes", []))
    for expected in (EXPECTED_APPLICATION_GRANTS, EXPECTED_PROVIDER_GRANTS):
        for key, scopes in expected.items():
            if key[0] not in services or key[1] not in services:
                raise ValueError(f"missing service identity: {key}")
            if grants.get(key) != scopes:
                raise ValueError(f"exact grant drift: {key}")
    for target in PROVIDER_TARGETS:
        if ("middleware-api", target) in grants:
            raise ValueError(f"direct middleware provider grant: {target}")
        if ("n8n-automation", target) in grants:
            raise ValueError(f"direct n8n provider grant: {target}")


def main() -> int:
    validate(json.loads(CONTRACT.read_text(encoding="utf-8")))
    print("KEYCLOAK_PROVIDER_CONTROL_AUTHORITY=PASS")
    print("DIRECT_PROVIDER_IDENTITY_GRANTS=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
