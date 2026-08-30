#!/usr/bin/env python3
"""Validate the protected Codestra observability browser-client contract."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "contracts" / "observability-browser-clients.json"
CLIENT_DIR = ROOT / "config" / "clients"
EXPECTED_ISSUER = "https://auth.codestra.co/realms/codestra"
EXPECTED = {
    "grafana-observability": {
        "origin": "https://graf.codestra.media",
        "baseUrl": "https://graf.codestra.media/",
        "redirects": ["https://graf.codestra.media/login/generic_oauth"],
        "roles": {"observability-viewer", "observability-operator", "observability-admin"},
        "mfa": {"observability-operator", "observability-admin"},
        "idle": 900,
        "maximum": 14400,
    },
    "superset-analytics": {
        "origin": "https://supe.codestra.media",
        "baseUrl": "https://supe.codestra.media/",
        "redirects": ["https://supe.codestra.media/oauth-authorized/keycloak"],
        "roles": {"observability-viewer", "observability-operator", "observability-admin"},
        "mfa": {"observability-operator", "observability-admin"},
        "idle": 900,
        "maximum": 14400,
    },
    "openbao-secrets": {
        "origin": "https://bao.codestra.media",
        "baseUrl": "https://bao.codestra.media/ui/",
        "redirects": [
            "https://bao.codestra.media/v1/auth/oidc/callback",
            "https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback",
            "http://localhost:8250/oidc/callback",
        ],
        "roles": {"secrets-operator", "secrets-admin"},
        "mfa": {"secrets-operator", "secrets-admin"},
        "idle": 600,
        "maximum": 3600,
    },
}
EXPECTED_ACTIVATION = {
    "contractReviewed": True,
    "managedClientApplySupportAdded": True,
    "roleProvisioningSupportAdded": True,
    "secretExportSupportAdded": True,
    "roleAssignmentsApplied": False,
    "liveClientsCreated": False,
    "liveSecretsGenerated": False,
    "productionAccessEnabled": False,
}


def fail(message: str) -> None:
    print(f"OBSERVABILITY_OIDC_VALIDATION_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {path.relative_to(ROOT)}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain an object")
    return value


def allowed_uri(value: str) -> bool:
    parsed = urlparse(value)
    if "*" in value or parsed.username or parsed.password or parsed.fragment:
        return False
    if parsed.scheme == "https" and parsed.hostname:
        return True
    return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}


def validate_mapper(client_id: str, client: dict) -> None:
    mappers = [
        item
        for item in client.get("protocolMappers", [])
        if isinstance(item, dict) and item.get("name") == "codestra-realm-roles"
    ]
    if len(mappers) != 1:
        fail(f"{client_id}: exactly one realm-role mapper is required")
    mapper = mappers[0]
    if mapper.get("protocolMapper") != "oidc-usermodel-realm-role-mapper":
        fail(f"{client_id}: realm-role mapper type mismatch")
    if mapper.get("config") != {
        "multivalued": "true",
        "userinfo.token.claim": "true",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "claim.name": "realm_access.roles",
        "jsonType.label": "String",
    }:
        fail(f"{client_id}: realm-role mapper configuration mismatch")


def main() -> None:
    contract = load(CONTRACT)
    if contract.get("version") != 1 or contract.get("issuer") != EXPECTED_ISSUER:
        fail("contract version or issuer mismatch")
    clients = contract.get("clients")
    if not isinstance(clients, list) or [item.get("clientId") for item in clients] != list(EXPECTED):
        fail("client set/order mismatch")

    for item in clients:
        client_id = item["clientId"]
        expected = EXPECTED[client_id]
        if item.get("applicationUrl") != expected["origin"]:
            fail(f"{client_id}: application URL mismatch")
        if item.get("redirectUris") != expected["redirects"]:
            fail(f"{client_id}: redirect URI mismatch")
        if item.get("webOrigins") != [expected["origin"]]:
            fail(f"{client_id}: web origin mismatch")
        if item.get("postLogoutRedirectUris") != [expected["origin"] + "/"]:
            fail(f"{client_id}: post-logout redirect mismatch")
        if item.get("clientType") != "confidential" or item.get("grantType") != "authorization_code" or item.get("pkceCodeChallengeMethod") != "S256":
            fail(f"{client_id}: unsafe client type or grant")
        if any(item.get(key) is not False for key in ("directAccessGrantsEnabled", "implicitFlowEnabled", "serviceAccountsEnabled")):
            fail(f"{client_id}: unsafe flow enabled")
        if item.get("secretSource") != "protected-generated-client-secret-export":
            fail(f"{client_id}: protected secret-export source is required")
        if set(item.get("requiredRoles", [])) != expected["roles"]:
            fail(f"{client_id}: role set mismatch")
        if set(item.get("mfaRequiredRoles", [])) != expected["mfa"]:
            fail(f"{client_id}: MFA role set mismatch")
        if item.get("sessionIdleSeconds") != expected["idle"] or item.get("sessionMaxSeconds") != expected["maximum"]:
            fail(f"{client_id}: session policy mismatch")
        if not all(allowed_uri(uri) for uri in item["redirectUris"]):
            fail(f"{client_id}: unsafe callback")

        desired = load(CLIENT_DIR / f"{client_id}.json")
        if desired.get("clientId") != client_id:
            fail(f"{client_id}: managed overlay identity mismatch")
        if desired.get("rootUrl") != expected["origin"] or desired.get("baseUrl") != expected["baseUrl"]:
            fail(f"{client_id}: managed overlay base URL mismatch")
        if desired.get("redirectUris") != expected["redirects"] or desired.get("webOrigins") != [expected["origin"]]:
            fail(f"{client_id}: managed overlay does not match URL contract")
        if desired.get("clientAuthenticatorType") != "client-secret" or desired.get("publicClient") is not False or desired.get("standardFlowEnabled") is not True:
            fail(f"{client_id}: managed overlay is not confidential authorization-code")
        if any(desired.get(key) is not False for key in ("implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled", "authorizationServicesEnabled")):
            fail(f"{client_id}: managed overlay enabled an unsafe flow")
        attributes = desired.get("attributes", {})
        if attributes.get("pkce.code.challenge.method") != "S256" or attributes.get("access.token.lifespan") != "300":
            fail(f"{client_id}: PKCE/token lifespan mismatch")
        if attributes.get("client.session.idle.timeout") != str(expected["idle"]) or attributes.get("client.session.max.lifespan") != str(expected["maximum"]):
            fail(f"{client_id}: managed session policy mismatch")
        validate_mapper(client_id, desired)

    if contract.get("activation") != EXPECTED_ACTIVATION:
        fail("activation state must show source support without live activation")
    isolation = contract.get("roleIsolation", {})
    if not all(
        isolation.get(key) is True
        for key in (
            "observabilityRolesDoNotGrantSecretsAccess",
            "secretsRolesDoNotGrantObservabilityAdmin",
            "administrativeMfaRequired",
            "leastPrivilegeRequired",
        )
    ):
        fail("role isolation controls are incomplete")
    if set(clients[2]["requiredRoles"]) & set(clients[0]["requiredRoles"]):
        fail("OpenBao and observability role families overlap")

    print("OBSERVABILITY_OIDC_CONTRACT_VALID=1")
    print("OBSERVABILITY_MANAGED_OVERLAYS=PASS")
    print("OBSERVABILITY_MANAGED_REALM_ROLE_MAPPER=PASS")
    print("OBSERVABILITY_SESSION_AND_MFA_POLICY=PASS")
    print("OBSERVABILITY_LIVE_ACTIVATION=DISABLED")


if __name__ == "__main__":
    main()
