#!/usr/bin/env python3
"""Validate the managed Codestra observability browser-client and role contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
CLIENT_DIR = ROOT / "config" / "clients"
CONTRACT_PATH = ROOT / "config" / "contracts" / "observability-browser-clients.json"
ROLES_PATH = ROOT / "config" / "roles" / "observability-realm-roles.json"
EXPECTED_ISSUER = "https://auth.codestra.co/realms/codestra"

OBSERVABILITY_ROLES = [
    "observability-viewer",
    "observability-operator",
    "observability-admin",
]
SECRETS_ROLES = ["secrets-operator", "secrets-admin"]
EXPECTED_ROLES = {
    "observability-viewer": [],
    "observability-operator": ["observability-viewer"],
    "observability-admin": ["observability-operator"],
    "secrets-operator": [],
    "secrets-admin": ["secrets-operator"],
}
EXPECTED_CLIENTS = {
    "grafana-observability": {
        "applicationUrl": "https://graf.codestra.media",
        "redirectUris": ["https://graf.codestra.media/login/generic_oauth"],
        "postLogoutRedirectUris": ["https://graf.codestra.media/"],
        "roles": OBSERVABILITY_ROLES,
        "mfaRoles": ["observability-admin"],
        "idle": 900,
        "maximum": 14400,
    },
    "superset-analytics": {
        "applicationUrl": "https://supe.codestra.media",
        "redirectUris": ["https://supe.codestra.media/oauth-authorized/keycloak"],
        "postLogoutRedirectUris": ["https://supe.codestra.media/"],
        "roles": OBSERVABILITY_ROLES,
        "mfaRoles": ["observability-admin"],
        "idle": 900,
        "maximum": 14400,
    },
    "openbao-secrets": {
        "applicationUrl": "https://bao.codestra.media",
        "redirectUris": [
            "https://bao.codestra.media/v1/auth/oidc/callback",
            "https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback",
            "http://localhost:8250/oidc/callback",
        ],
        "postLogoutRedirectUris": ["https://bao.codestra.media/"],
        "roles": SECRETS_ROLES,
        "mfaRoles": SECRETS_ROLES,
        "idle": 600,
        "maximum": 3600,
    },
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
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def is_allowed_uri(value: str) -> bool:
    parsed = urlparse(value)
    if "*" in value or parsed.username or parsed.password or parsed.fragment:
        return False
    if parsed.scheme == "https" and parsed.hostname:
        return True
    return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}


def validate_roles() -> None:
    data = load(ROLES_PATH)
    if data.get("schemaVersion") != 1 or data.get("realm") != "codestra":
        fail("realm-role contract identity mismatch")
    if data.get("provisioningState") != "review-required-before-role-aware-apply":
        fail("realm roles must remain review-gated")
    if data.get("defaultAssignments") != []:
        fail("observability roles must never be assigned by default")
    if data.get("automaticCrossClientInheritance") is not False:
        fail("cross-client role inheritance must be disabled")

    roles = data.get("roles")
    if not isinstance(roles, list):
        fail("realm roles must be a list")
    configured = {role.get("name"): role for role in roles if isinstance(role, dict)}
    if list(configured) != list(EXPECTED_ROLES):
        fail("realm-role set or canonical order mismatch")
    for role_name, composites in EXPECTED_ROLES.items():
        if configured[role_name].get("composites") != composites:
            fail(f"{role_name}: composite mapping mismatch")


def validate_managed_client(client_id: str, expected: dict) -> None:
    client = load(CLIENT_DIR / f"{client_id}.json")
    if client.get("clientId") != client_id or client.get("enabled") is not True:
        fail(f"{client_id}: managed client identity mismatch")
    if client.get("protocol") != "openid-connect":
        fail(f"{client_id}: protocol must be openid-connect")
    if client.get("clientAuthenticatorType") != "client-secret":
        fail(f"{client_id}: distinct confidential credential is required")
    if client.get("publicClient") is not False or client.get("bearerOnly") is not False:
        fail(f"{client_id}: client must be confidential and browser-capable")
    if client.get("standardFlowEnabled") is not True:
        fail(f"{client_id}: Authorization Code Flow is required")
    for key in (
        "implicitFlowEnabled",
        "directAccessGrantsEnabled",
        "serviceAccountsEnabled",
        "authorizationServicesEnabled",
    ):
        if client.get(key) is not False:
            fail(f"{client_id}: {key} must be disabled")
    if client.get("fullScopeAllowed") is not False:
        fail(f"{client_id}: fullScopeAllowed must be disabled")
    if client.get("rootUrl") != expected["applicationUrl"]:
        fail(f"{client_id}: root URL mismatch")
    if client.get("redirectUris") != expected["redirectUris"]:
        fail(f"{client_id}: managed redirect URI mismatch")
    if client.get("webOrigins") != [expected["applicationUrl"]]:
        fail(f"{client_id}: managed web origin mismatch")
    if "secret" in client:
        fail(f"{client_id}: credential material must not be committed")

    attributes = client.get("attributes") or {}
    if attributes.get("pkce.code.challenge.method") != "S256":
        fail(f"{client_id}: PKCE S256 is required")
    if attributes.get("access.token.lifespan") != "300":
        fail(f"{client_id}: access token lifespan must be 300 seconds")
    if attributes.get("client.session.idle.timeout") != str(expected["idle"]):
        fail(f"{client_id}: session idle timeout mismatch")
    if attributes.get("client.session.max.lifespan") != str(expected["maximum"]):
        fail(f"{client_id}: session maximum mismatch")
    if attributes.get("post.logout.redirect.uris") != expected["postLogoutRedirectUris"][0]:
        fail(f"{client_id}: post-logout redirect mismatch")
    for disabled_attribute in (
        "oauth2.device.authorization.grant.enabled",
        "oidc.ciba.grant.enabled",
    ):
        if attributes.get(disabled_attribute) != "false":
            fail(f"{client_id}: {disabled_attribute} must be disabled")


def main() -> None:
    data = load(CONTRACT_PATH)
    if data.get("version") != 1:
        fail("contract version must be 1")
    if data.get("issuer") != EXPECTED_ISSUER:
        fail("issuer is not the canonical Codestra issuer")

    clients = data.get("clients")
    if not isinstance(clients, list) or len(clients) != len(EXPECTED_CLIENTS):
        fail("exactly three reviewed clients are required")
    configured_ids = [client.get("clientId") for client in clients if isinstance(client, dict)]
    if configured_ids != list(EXPECTED_CLIENTS):
        fail("clients must be unique and in canonical order")

    for contract_client in clients:
        client_id = contract_client["clientId"]
        expected = EXPECTED_CLIENTS[client_id]
        if contract_client.get("applicationUrl") != expected["applicationUrl"]:
            fail(f"{client_id}: application URL mismatch")
        if contract_client.get("clientType") != "confidential":
            fail(f"{client_id}: client must be confidential")
        if contract_client.get("grantType") != "authorization_code":
            fail(f"{client_id}: only authorization_code is allowed")
        if contract_client.get("pkceCodeChallengeMethod") != "S256":
            fail(f"{client_id}: PKCE S256 is required")
        for key in (
            "directAccessGrantsEnabled",
            "implicitFlowEnabled",
            "serviceAccountsEnabled",
        ):
            if contract_client.get(key) is not False:
                fail(f"{client_id}: {key} must be disabled")
        if contract_client.get("secretSource") != "external-secret-manager":
            fail(f"{client_id}: secret source must remain external")
        if contract_client.get("redirectUris") != expected["redirectUris"]:
            fail(f"{client_id}: exact redirect URI allowlist mismatch")
        if contract_client.get("webOrigins") != [expected["applicationUrl"]]:
            fail(f"{client_id}: exact web origin mismatch")
        if contract_client.get("postLogoutRedirectUris") != expected["postLogoutRedirectUris"]:
            fail(f"{client_id}: exact post-logout redirect mismatch")
        if not all(is_allowed_uri(uri) for uri in contract_client["redirectUris"]):
            fail(f"{client_id}: unsafe redirect URI")
        if contract_client.get("requiredRoles") != expected["roles"]:
            fail(f"{client_id}: role mapping mismatch")
        if contract_client.get("mfaRequiredRoles") != expected["mfaRoles"]:
            fail(f"{client_id}: MFA role mapping mismatch")
        if contract_client.get("sessionIdleSeconds") != expected["idle"]:
            fail(f"{client_id}: contract session idle timeout mismatch")
        if contract_client.get("sessionMaxSeconds") != expected["maximum"]:
            fail(f"{client_id}: contract session maximum mismatch")
        validate_managed_client(client_id, expected)

    if set(OBSERVABILITY_ROLES) & set(SECRETS_ROLES):
        fail("observability and secrets role families overlap")
    openbao_roles = set(clients[2]["requiredRoles"])
    if openbao_roles & set(OBSERVABILITY_ROLES):
        fail("Grafana/Superset access must not grant OpenBao access")

    isolation = data.get("roleIsolation") or {}
    for key in (
        "observabilityRolesDoNotGrantSecretsAccess",
        "secretsRolesDoNotGrantObservabilityAdmin",
        "administrativeMfaRequired",
        "leastPrivilegeRequired",
    ):
        if isolation.get(key) is not True:
            fail(f"role isolation control disabled: {key}")

    activation = data.get("activation") or {}
    if activation.get("managedClientApplySupportAdded") is not True:
        fail("managed-client plan/apply support must cover these desired clients")
    for key in (
        "contractReviewed",
        "roleProvisioningSupportAdded",
        "roleAssignmentsApplied",
        "liveClientsCreated",
        "liveSecretsGenerated",
        "productionAccessEnabled",
    ):
        if activation.get(key) is not False:
            fail(f"activation gate must remain false: {key}")

    validate_roles()
    print("OBSERVABILITY_OIDC_CONTRACT=PASS")
    print("OBSERVABILITY_OIDC_CLIENTS=" + ",".join(EXPECTED_CLIENTS))
    print("OPENBAO_ROLE_SEPARATION=PASS")
    print("ADMINISTRATIVE_MFA_POLICY=PASS")
    print("MANAGED_CLIENT_PLAN_APPLY_SUPPORT=PASS")
    print("ROLE_PROVISIONING_READY=NO")
    print("LIVE_IDENTITY_APPLY_AUTHORIZED=NO")


if __name__ == "__main__":
    main()
