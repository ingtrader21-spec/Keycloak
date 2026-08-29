#!/usr/bin/env python3
"""Validate protected Keycloak desired state without contacting a live realm."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from observability_identity_policy import PolicyError as ObservabilityPolicyError, validate_source as validate_observability_source

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"
CLIENT_DIR = CONFIG / "clients"
ROLE_DIR = CONFIG / "realm-roles"
ALLOWLIST_DIR = CONFIG / "export-allowlists"
ROLE_ALLOWLIST_DIR = ALLOWLIST_DIR / "realm-roles"

EXPECTED_MANAGED_CLIENTS = [
    "beyvra-backend", "breero-backend", "klyrow-portal", "kong-gateway",
    "klyrow-gateway", "kyqra-gateway", "larim-a-backend", "middleware-api",
    "middleware-worker", "monitoring-readonly", "moneybee-admin",
    "moneybee-backend", "moneybee-borrower", "moneybee-lender",
    "n8n-automation", "odoo-integration", "postly-adapter",
    "provisioning-service", "social-codestra", "telnexa-gateway",
    "transportation-backend", "vicidial-adapter", "grafana-observability",
    "superset-analytics", "openbao-secrets",
]
EXPECTED_CREATABLE_CLIENTS = [item for item in EXPECTED_MANAGED_CLIENTS if item != "klyrow-portal"]
EXPECTED_ROLES = [
    "observability-viewer", "observability-operator", "observability-admin",
    "secrets-operator", "secrets-admin",
]
OBSERVABILITY_CLIENTS = {
    "grafana-observability": ("https://graf.codestra.media", ["https://graf.codestra.media/login/generic_oauth"]),
    "superset-analytics": ("https://supe.codestra.media", ["https://supe.codestra.media/oauth-authorized/keycloak"]),
    "openbao-secrets": (
        "https://bao.codestra.media",
        [
            "https://bao.codestra.media/v1/auth/oidc/callback",
            "https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback",
            "http://localhost:8250/oidc/callback",
        ],
    ),
}
SENSITIVE = re.compile(r"^(secret|clientsecret|client_secret|password|privatekey|private_key|access_token|accesstoken|refresh_token|refreshtoken|credential|credentials)$", re.I)


def fail(message: str) -> None:
    print(f"VALIDATION_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {path}: {exc}")


def walk_sensitive(value, path: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE.fullmatch(key) and child not in (None, "", [], {}):
                fail(f"prohibited secret-bearing field {path}.{key}")
            walk_sensitive(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk_sensitive(child, f"{path}[{index}]")


def valid_uri(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme == "https" and parsed.hostname:
        return "*" not in value and not value.endswith("/*")
    return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"} and "*" not in value


def validate_ruleset() -> None:
    value = load(CONFIG / "github" / "main-ruleset.json")
    types = [item.get("type") for item in value.get("rules", [])]
    assert value.get("name") == "Protect main"
    assert value.get("target") == "branch"
    assert value.get("enforcement") == "active"
    assert value.get("conditions", {}).get("ref_name", {}).get("include") == ["~DEFAULT_BRANCH"]
    for required in ("deletion", "non_fast_forward", "pull_request", "required_status_checks"):
        assert required in types
    pr = next(item["parameters"] for item in value["rules"] if item["type"] == "pull_request")
    assert pr["required_approving_review_count"] == 1
    assert pr["dismiss_stale_reviews_on_push"] is True
    assert pr["require_last_push_approval"] is True
    assert pr["required_review_thread_resolution"] is True
    checks = next(item["parameters"] for item in value["rules"] if item["type"] == "required_status_checks")
    assert [item["context"] for item in checks["required_status_checks"]] == ["validate-source", "validate-merge-result"]


def main() -> None:
    try:
        validate_observability_source(CONFIG)
    except ObservabilityPolicyError as exc:
        fail(f"observability identity policy failed: {exc}")
    for path in sorted(CONFIG.rglob("*.json")):
        value = load(path)
        walk_sensitive(value, str(path.relative_to(ROOT)))

    endpoints = load(CONFIG / "endpoints" / "codestra.json")
    expected_public = "https://auth.codestra.co"
    assert endpoints == {
        **endpoints,
        "publicUrl": expected_public,
        "adminApiBaseUrl": expected_public,
        "realm": "codestra",
        "issuer": f"{expected_public}/realms/codestra",
        "discoveryUrl": f"{expected_public}/realms/codestra/.well-known/openid-configuration",
        "authorizationEndpoint": f"{expected_public}/realms/codestra/protocol/openid-connect/auth",
        "tokenEndpoint": f"{expected_public}/realms/codestra/protocol/openid-connect/token",
        "userInfoEndpoint": f"{expected_public}/realms/codestra/protocol/openid-connect/userinfo",
        "jwksUri": f"{expected_public}/realms/codestra/protocol/openid-connect/certs",
        "introspectionEndpoint": f"{expected_public}/realms/codestra/protocol/openid-connect/token/introspect",
        "logoutEndpoint": f"{expected_public}/realms/codestra/protocol/openid-connect/logout",
        "adminRealmEndpoint": f"{expected_public}/admin/realms/codestra",
    }
    realm = load(CONFIG / "realms" / "codestra.json")
    assert realm.get("realm") == "codestra" and realm.get("enabled") is True

    managed = load(CONFIG / "policy" / "managed-clients.json")["clients"]
    creatable = load(CONFIG / "policy" / "creatable-clients.json")["clients"]
    assert managed == EXPECTED_MANAGED_CLIENTS
    assert creatable == EXPECTED_CREATABLE_CLIENTS
    assert len(managed) == len(set(managed)) and len(creatable) == len(set(creatable))
    configured = sorted(load(path)["clientId"] for path in CLIENT_DIR.glob("*.json"))
    assert configured == sorted(managed)

    allowed_top = {
        "clientId", "name", "description", "enabled", "protocol",
        "clientAuthenticatorType", "publicClient", "bearerOnly", "consentRequired",
        "standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled",
        "serviceAccountsEnabled", "authorizationServicesEnabled", "frontchannelLogout",
        "fullScopeAllowed", "rootUrl", "baseUrl", "redirectUris", "webOrigins",
        "defaultClientScopes", "optionalClientScopes", "attributes", "protocolMappers",
    }
    allowed_attrs = {
        "pkce.code.challenge.method", "post.logout.redirect.uris",
        "oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled",
        "access.token.lifespan",
    }

    for path in sorted(CLIENT_DIR.glob("*.json")):
        client = load(path)
        client_id = client["clientId"]
        assert client.get("enabled") is True and client.get("protocol") == "openid-connect"
        assert isinstance(client.get("redirectUris"), list) and isinstance(client.get("webOrigins"), list)
        assert len(client["redirectUris"]) == len(set(client["redirectUris"]))
        assert len(client["webOrigins"]) == len(set(client["webOrigins"]))
        assert all(valid_uri(value) for value in [*client["redirectUris"], *client["webOrigins"]])
        if client.get("publicClient") is True:
            assert client.get("standardFlowEnabled") is True
            assert client.get("implicitFlowEnabled") is False
            assert client.get("directAccessGrantsEnabled") is False
            assert client.get("serviceAccountsEnabled") is False
            assert client.get("attributes", {}).get("pkce.code.challenge.method") == "S256"
        if client.get("serviceAccountsEnabled") is True:
            assert client.get("publicClient") is False
            assert client.get("standardFlowEnabled") is False
            assert client.get("implicitFlowEnabled") is False
            assert client.get("directAccessGrantsEnabled") is False
            assert client.get("fullScopeAllowed") is False
            assert client["redirectUris"] == [] and client["webOrigins"] == []
        if client_id in OBSERVABILITY_CLIENTS:
            origin, redirects = OBSERVABILITY_CLIENTS[client_id]
            assert client.get("clientAuthenticatorType") == "client-secret"
            assert client.get("publicClient") is False
            assert client.get("standardFlowEnabled") is True
            assert client.get("implicitFlowEnabled") is False
            assert client.get("directAccessGrantsEnabled") is False
            assert client.get("serviceAccountsEnabled") is False
            assert client.get("fullScopeAllowed") is False
            assert client.get("rootUrl") == origin and client.get("webOrigins") == [origin]
            assert client.get("redirectUris") == redirects
            assert client.get("attributes", {}).get("pkce.code.challenge.method") == "S256"
            assert client.get("attributes", {}).get("access.token.lifespan") == "300"
            mappers = [item for item in client.get("protocolMappers", []) if item.get("name") == "codestra-realm-roles"]
            assert len(mappers) == 1
            assert mappers[0].get("protocolMapper") == "oidc-usermodel-realm-role-mapper"
            assert mappers[0].get("config") == {
                "multivalued": "true", "userinfo.token.claim": "true",
                "id.token.claim": "true", "access.token.claim": "true",
                "claim.name": "realm_access.roles", "jsonType.label": "String",
            }

        allowlist = load(ALLOWLIST_DIR / f"{client_id}.json")
        assert allowlist.get("clientId") == client_id
        assert set(allowlist.get("topLevelFields", [])) == set(client)
        assert set(allowlist.get("topLevelFields", [])).issubset(allowed_top)
        attributes = client.get("attributes", {})
        assert set(allowlist.get("attributeFields", [])) == set(attributes)
        assert set(allowlist.get("attributeFields", [])).issubset(allowed_attrs)

    role_policy = load(CONFIG / "policy" / "managed-realm-roles.json")["roles"]
    role_creatable = load(CONFIG / "policy" / "creatable-realm-roles.json")["roles"]
    assert role_policy == EXPECTED_ROLES and role_creatable == EXPECTED_ROLES
    configured_roles = sorted(load(path)["name"] for path in ROLE_DIR.glob("*.json"))
    assert configured_roles == sorted(EXPECTED_ROLES)
    for path in sorted(ROLE_DIR.glob("*.json")):
        role = load(path)
        name = role["name"]
        family = role["attributes"]["codestra.role.family"]
        level = role["attributes"]["codestra.role.level"]
        assert role.get("composite") is False and role.get("clientRole") is False
        assert family in (["observability"], ["secrets"])
        assert level in (["viewer"], ["operator"], ["admin"])
        assert role["attributes"]["codestra.assignment.independent_approval"] == ["true"]
        assert role["attributes"]["codestra.cross_family_grant"] == ["false"]
        assert (name.startswith("observability-") and family == ["observability"]) or (name.startswith("secrets-") and family == ["secrets"])
        allowlist = load(ROLE_ALLOWLIST_DIR / f"{name}.json")
        assert allowlist.get("roleName") == name
        assert set(allowlist.get("topLevelFields", [])) == set(role)
        assert set(allowlist.get("attributeFields", [])) == set(role["attributes"])

    assert load(CONFIG / "policy" / "secret-export-clients.json") == {"clients": list(OBSERVABILITY_CLIENTS)}
    contract = load(CONFIG / "contracts" / "observability-browser-clients.json")
    assert contract["activation"] == {
        "contractReviewed": True,
        "managedClientApplySupportAdded": True,
        "liveClientsCreated": False,
        "liveSecretsGenerated": False,
        "productionAccessEnabled": False,
    }
    assert contract["roleIsolation"] == {
        "observabilityRolesDoNotGrantSecretsAccess": True,
        "secretsRolesDoNotGrantObservabilityAdmin": True,
        "administrativeMfaRequired": True,
        "leastPrivilegeRequired": True,
    }
    validate_ruleset()

    required = [
        ROOT / "scripts" / "protected_identity_engine.py",
        ROOT / "scripts" / "export-generated-client-secrets.sh",
        ROOT / "scripts" / "test-plan-gate.sh",
    ]
    assert all(path.is_file() for path in required)

    print(f"MANAGED_CLIENTS={len(managed)}")
    print(f"MANAGED_REALM_ROLES={len(role_policy)}")
    print("OBSERVABILITY_ROLE_ISOLATION=PASS")
    print("SECRET_MATERIAL_POLICY=PASS")
    print("PROTECTED_IDENTITY_SOURCE=PASS")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        fail(f"assertion failed: {exc}")
