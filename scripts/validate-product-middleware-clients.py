#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/contracts/product-middleware-clients.json"
ACCESS_MATRIX = ROOT / "config/contracts/service-access-matrix.json"
CLIENT_DIR = ROOT / "config/clients"
ALLOWLIST_DIR = ROOT / "config/export-allowlists"
MANAGED = ROOT / "config/policy/managed-clients.json"
CREATABLE = ROOT / "config/policy/creatable-clients.json"

EXPECTED = {
    "moneybee-backend": (
        ["moneybee.middleware.command.write", "moneybee.middleware.status.read"],
        ["crm."],
        ["odoo-19"],
    ),
    "breero-backend": (
        ["breero.middleware.command.write", "breero.middleware.status.read"],
        ["crm."],
        ["odoo-19"],
    ),
    "larim-a-backend": (
        ["larim-a.middleware.command.write", "larim-a.middleware.status.read"],
        ["crm."],
        ["odoo-19"],
    ),
    "transportation-backend": (
        ["transportation.middleware.command.write", "transportation.middleware.status.read"],
        ["crm."],
        ["odoo-19"],
    ),
    "beyvra-backend": (
        ["beyvra.middleware.command.write", "beyvra.middleware.status.read"],
        ["crm."],
        ["odoo-19"],
    ),
    "social-codestra": (
        ["social.middleware.command.write", "social.middleware.status.read"],
        ["social."],
        ["postly-social"],
    ),
    "odoo-email": (
        ["odoo.email.command.write", "odoo.email.status.read"],
        ["email."],
        ["klyrow-email"],
    ),
    "production-operator": (
        ["email.production.read", "email.production.write"],
        [],
        [],
    ),
}

TOP = [
    "clientId",
    "name",
    "description",
    "enabled",
    "protocol",
    "publicClient",
    "bearerOnly",
    "consentRequired",
    "standardFlowEnabled",
    "implicitFlowEnabled",
    "directAccessGrantsEnabled",
    "serviceAccountsEnabled",
    "authorizationServicesEnabled",
    "frontchannelLogout",
    "fullScopeAllowed",
    "redirectUris",
    "webOrigins",
    "defaultClientScopes",
    "optionalClientScopes",
    "attributes",
    "protocolMappers",
]
ATTR = [
    "access.token.lifespan",
    "oauth2.device.authorization.grant.enabled",
    "oidc.ciba.grant.enabled",
]


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def mapper(client: dict, name: str) -> dict:
    matches = [item for item in client["protocolMappers"] if item.get("name") == name]
    assert len(matches) == 1, (client["clientId"], name)
    return matches[0]


def main() -> None:
    contract = load(CONTRACT)
    access = load(ACCESS_MATRIX)

    assert contract["schemaVersion"] == 1
    assert contract["extendsAccessMatrix"] == "service-access-matrix.json"
    assert contract["targetClientId"] == "middleware-api"
    assert contract["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert contract["audience"] == "middleware-api"
    assert contract["grantType"] == "client_credentials"
    assert contract["maximumAccessTokenLifetimeSeconds"] == 300
    assert contract["refreshTokensAllowed"] is False
    assert contract["tokenExchange"] is False
    assert contract["forwardOriginalBearer"] is True
    assert contract["directProviderAccess"] is False
    assert contract["tenantClaim"] == {
        "claim": "tenant_id",
        "source": "service-account-user-attribute",
        "attribute": "tenant_id",
        "wildcardAllowed": False,
    }
    assert [item["clientId"] for item in contract["clients"]] == list(EXPECTED)

    assert access["issuer"] == contract["issuer"]
    services = {item["clientId"]: item for item in access["services"]}
    middleware = services[contract["targetClientId"]]
    assert middleware["resourceServer"] is True
    assert middleware["audience"] == contract["audience"]

    base_grants = {
        (item["callerClientId"], item["targetClientId"]): set(item["scopes"])
        for item in access["grants"]
    }
    managed = load(MANAGED)["clients"]
    creatable = load(CREATABLE)["clients"]
    composed_grants = dict(base_grants)

    for item in contract["clients"]:
        client_id = item["clientId"]
        scopes, prefixes, targets = EXPECTED[client_id]
        assert item["scopes"] == scopes
        assert item["allowedCommandPrefixes"] == prefixes
        assert item["allowedTargets"] == targets
        assert client_id in managed and client_id in creatable
        assert client_id not in services
        composed_key = (client_id, contract["targetClientId"])
        assert composed_key not in base_grants
        composed_grants[composed_key] = set(scopes)
        assert composed_grants[composed_key] == set(scopes)
        assert all("*" not in scope for scope in scopes)

        desired = load(CLIENT_DIR / f"{client_id}.json")
        assert desired["clientId"] == client_id
        assert desired["enabled"] is True
        assert desired["protocol"] == "openid-connect"
        assert desired["publicClient"] is False
        assert desired["bearerOnly"] is False
        assert desired["standardFlowEnabled"] is False
        assert desired["implicitFlowEnabled"] is False
        assert desired["directAccessGrantsEnabled"] is False
        assert desired["serviceAccountsEnabled"] is True
        assert desired["authorizationServicesEnabled"] is False
        assert desired["fullScopeAllowed"] is False
        assert desired["redirectUris"] == []
        assert desired["webOrigins"] == []
        assert desired["defaultClientScopes"] == []
        assert desired["optionalClientScopes"] == []
        assert desired["attributes"] == {
            "access.token.lifespan": "300",
            "oauth2.device.authorization.grant.enabled": "false",
            "oidc.ciba.grant.enabled": "false",
        }

        audience = mapper(desired, "audience-middleware-api")
        assert audience["protocolMapper"] == "oidc-audience-mapper"
        assert audience["config"] == {
            "included.custom.audience": "middleware-api",
            "id.token.claim": "false",
            "access.token.claim": "true",
        }

        scope_mapper = mapper(desired, "reviewed-product-middleware-scopes")
        assert scope_mapper["protocolMapper"] == "oidc-hardcoded-claim-mapper"
        assert scope_mapper["config"]["claim.name"] == "scope"
        assert scope_mapper["config"]["claim.value"] == " ".join(scopes)

        tenant = mapper(desired, "tenant-id-from-service-account")
        assert tenant["protocolMapper"] == "oidc-usermodel-attribute-mapper"
        assert tenant["config"] == {
            "user.attribute": "tenant_id",
            "claim.name": "tenant_id",
            "jsonType.label": "String",
            "id.token.claim": "false",
            "access.token.claim": "true",
            "userinfo.token.claim": "false",
            "multivalued": "false",
        }

        allowlist = load(ALLOWLIST_DIR / f"{client_id}.json")
        assert allowlist == {
            "clientId": client_id,
            "topLevelFields": TOP,
            "attributeFields": ATTR,
        }

    for client_id in ("breero-backend", "larim-a-backend", "transportation-backend"):
        assert "telephony." not in EXPECTED[client_id][1]
    assert "crm." not in EXPECTED["social-codestra"][1]

    assert len(composed_grants) == len(base_grants) + len(EXPECTED)
    for client_id, (scopes, _prefixes, _targets) in EXPECTED.items():
        assert composed_grants[(client_id, "middleware-api")] == set(scopes)

    print(f"PRODUCT_SERVICE_ACCESS_BASE_GRANTS={len(base_grants)}")
    print(f"PRODUCT_SERVICE_ACCESS_COMPOSED_GRANTS={len(composed_grants)}")
    print("PRODUCT_SERVICE_ACCESS_COMPOSITION=PASS")
    print("PRODUCT_MIDDLEWARE_CLIENTS=PASS")


if __name__ == "__main__":
    main()
