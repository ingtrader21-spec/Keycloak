#!/usr/bin/env python3
"""Validate protected Keycloak desired state without contacting a live realm."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from observability_identity_policy import (
    PolicyError as ObservabilityPolicyError,
    validate_source as validate_observability_source,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"
CLIENTS = CONFIG / "clients"
ROLES = CONFIG / "realm-roles"
ALLOWLISTS = CONFIG / "export-allowlists"
ROLE_ALLOWLISTS = ALLOWLISTS / "realm-roles"

MANAGED_CLIENTS = [
    "beyvra-backend", "breero-backend", "klyrow-portal", "kong-gateway",
    "klyrow-gateway", "kyqra-gateway", "larim-a-backend", "middleware-api",
    "middleware-worker", "monitoring-readonly", "moneybee-admin",
    "moneybee-backend", "moneybee-borrower", "moneybee-lender",
    "n8n-automation", "odoo-integration", "postly-adapter",
    "provisioning-service", "social-codestra", "telnexa-gateway",
    "transportation-backend", "vicidial-adapter", "grafana-observability",
    "superset-analytics", "openbao-secrets",
]
CREATABLE_CLIENTS = [item for item in MANAGED_CLIENTS if item != "klyrow-portal"]
MANAGED_ROLES = [
    "observability-viewer", "observability-operator", "observability-admin",
    "secrets-operator", "secrets-admin",
]
OBSERVABILITY = {
    "grafana-observability": {
        "origin": "https://graf.codestra.media",
        "redirects": ["https://graf.codestra.media/login/generic_oauth"],
        "idle": "900",
        "maximum": "14400",
    },
    "superset-analytics": {
        "origin": "https://supe.codestra.media",
        "redirects": ["https://supe.codestra.media/oauth-authorized/keycloak"],
        "idle": "900",
        "maximum": "14400",
    },
    "openbao-secrets": {
        "origin": "https://bao.codestra.media",
        "redirects": [
            "https://bao.codestra.media/v1/auth/oidc/callback",
            "https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback",
            "http://localhost:8250/oidc/callback",
        ],
        "idle": "600",
        "maximum": "3600",
    },
}
SENSITIVE = re.compile(
    r"^(secret|clientsecret|client_secret|password|privatekey|private_key|"
    r"access_token|accesstoken|refresh_token|refreshtoken|credential|credentials)$",
    re.I,
)
ALLOWED_CLIENT_FIELDS = {
    "clientId", "name", "description", "enabled", "protocol",
    "clientAuthenticatorType", "publicClient", "bearerOnly", "consentRequired",
    "standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled",
    "serviceAccountsEnabled", "authorizationServicesEnabled", "frontchannelLogout",
    "fullScopeAllowed", "rootUrl", "baseUrl", "redirectUris", "webOrigins",
    "defaultClientScopes", "optionalClientScopes", "attributes", "protocolMappers",
}
ALLOWED_ATTRIBUTE_FIELDS = {
    "pkce.code.challenge.method", "post.logout.redirect.uris",
    "oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled",
    "access.token.lifespan", "client.session.idle.timeout",
    "client.session.max.lifespan",
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
    print(f"VALIDATION_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {path.relative_to(ROOT)}: {exc}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def scan_secrets(value, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE.fullmatch(str(key)) and child not in (None, "", [], {}):
                fail(f"prohibited secret-bearing field {label}.{key}")
            scan_secrets(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_secrets(child, f"{label}[{index}]")


def valid_uri(value: str) -> bool:
    parsed = urlparse(value)
    if "*" in value or value.endswith("/*") or parsed.username or parsed.password:
        return False
    if parsed.scheme == "https" and parsed.hostname:
        return True
    return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}


def validate_ruleset() -> None:
    value = load(CONFIG / "github" / "main-ruleset.json")
    require(value.get("name") == "Protect main", "main ruleset name mismatch")
    require(value.get("target") == "branch", "main ruleset target mismatch")
    require(value.get("enforcement") == "active", "main ruleset is not active")
    require(
        value.get("conditions", {}).get("ref_name", {}).get("include")
        == ["~DEFAULT_BRANCH"],
        "main ruleset default-branch condition mismatch",
    )
    rules = {item.get("type"): item.get("parameters", {}) for item in value.get("rules", [])}
    require(
        {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}
        <= set(rules),
        "main ruleset is incomplete",
    )
    pr = rules["pull_request"]
    require(pr.get("required_approving_review_count") == 1, "one approval is required")
    require(pr.get("dismiss_stale_reviews_on_push") is True, "stale review dismissal required")
    require(pr.get("require_last_push_approval") is True, "last-push approval required")
    require(pr.get("required_review_thread_resolution") is True, "thread resolution required")
    checks = [
        item.get("context")
        for item in rules["required_status_checks"].get("required_status_checks", [])
    ]
    require(checks == ["validate-source", "validate-merge-result"], "required checks mismatch")


def validate_client(client_id: str, client: dict) -> None:
    require(client.get("enabled") is True, f"{client_id}: disabled")
    require(client.get("protocol") == "openid-connect", f"{client_id}: protocol mismatch")
    redirects = client.get("redirectUris")
    origins = client.get("webOrigins")
    require(isinstance(redirects, list), f"{client_id}: redirectUris must be an array")
    require(isinstance(origins, list), f"{client_id}: webOrigins must be an array")
    require(len(redirects) == len(set(redirects)), f"{client_id}: duplicate redirect URI")
    require(len(origins) == len(set(origins)), f"{client_id}: duplicate web origin")
    require(all(valid_uri(item) for item in [*redirects, *origins]), f"{client_id}: unsafe URI")

    if client.get("publicClient") is True:
        require(client.get("standardFlowEnabled") is True, f"{client_id}: standard flow required")
        require(client.get("implicitFlowEnabled") is False, f"{client_id}: implicit flow prohibited")
        require(client.get("directAccessGrantsEnabled") is False, f"{client_id}: direct grants prohibited")
        require(client.get("serviceAccountsEnabled") is False, f"{client_id}: service account prohibited")
        require(
            client.get("attributes", {}).get("pkce.code.challenge.method") == "S256",
            f"{client_id}: PKCE S256 required",
        )

    if client.get("serviceAccountsEnabled") is True:
        require(client.get("publicClient") is False, f"{client_id}: service client must be confidential")
        require(client.get("standardFlowEnabled") is False, f"{client_id}: browser flow prohibited")
        require(client.get("implicitFlowEnabled") is False, f"{client_id}: implicit flow prohibited")
        require(client.get("directAccessGrantsEnabled") is False, f"{client_id}: direct grants prohibited")
        require(client.get("fullScopeAllowed") is False, f"{client_id}: full scope prohibited")
        require(redirects == [] and origins == [], f"{client_id}: service client URI list must be empty")

    expected = OBSERVABILITY.get(client_id)
    if expected:
        require(client.get("clientAuthenticatorType") == "client-secret", f"{client_id}: authenticator mismatch")
        require(client.get("publicClient") is False, f"{client_id}: must be confidential")
        require(client.get("standardFlowEnabled") is True, f"{client_id}: authorization code required")
        require(client.get("implicitFlowEnabled") is False, f"{client_id}: implicit flow prohibited")
        require(client.get("directAccessGrantsEnabled") is False, f"{client_id}: direct grants prohibited")
        require(client.get("serviceAccountsEnabled") is False, f"{client_id}: service account prohibited")
        require(client.get("fullScopeAllowed") is False, f"{client_id}: full scope prohibited")
        require(client.get("rootUrl") == expected["origin"], f"{client_id}: root URL mismatch")
        require(origins == [expected["origin"]], f"{client_id}: web origin mismatch")
        require(redirects == expected["redirects"], f"{client_id}: callback mismatch")
        attrs = client.get("attributes", {})
        require(attrs.get("pkce.code.challenge.method") == "S256", f"{client_id}: PKCE mismatch")
        require(attrs.get("access.token.lifespan") == "300", f"{client_id}: token TTL mismatch")
        require(attrs.get("client.session.idle.timeout") == expected["idle"], f"{client_id}: idle timeout mismatch")
        require(attrs.get("client.session.max.lifespan") == expected["maximum"], f"{client_id}: max session mismatch")
        mappers = [
            item for item in client.get("protocolMappers", [])
            if item.get("name") == "codestra-realm-roles"
        ]
        require(len(mappers) == 1, f"{client_id}: realm-role mapper missing or duplicated")
        require(
            mappers[0].get("protocolMapper") == "oidc-usermodel-realm-role-mapper",
            f"{client_id}: realm-role mapper type mismatch",
        )
        require(
            mappers[0].get("config") == {
                "multivalued": "true",
                "userinfo.token.claim": "true",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "claim.name": "realm_access.roles",
                "jsonType.label": "String",
            },
            f"{client_id}: realm-role mapper configuration mismatch",
        )

    allowlist = load(ALLOWLISTS / f"{client_id}.json")
    require(allowlist.get("clientId") == client_id, f"{client_id}: allowlist identity mismatch")
    top = set(allowlist.get("topLevelFields", []))
    attrs = set(allowlist.get("attributeFields", []))
    require(top == set(client), f"{client_id}: allowlist must exactly cover client fields")
    require(top <= ALLOWED_CLIENT_FIELDS, f"{client_id}: unsafe top-level allowlist field")
    require(attrs == set(client.get("attributes", {})), f"{client_id}: attribute allowlist mismatch")
    require(attrs <= ALLOWED_ATTRIBUTE_FIELDS, f"{client_id}: unsafe attribute allowlist field")


def main() -> None:
    try:
        validate_observability_source(CONFIG)
    except ObservabilityPolicyError as exc:
        fail(f"observability identity policy failed: {exc}")

    for path in sorted(CONFIG.rglob("*.json")):
        scan_secrets(load(path), str(path.relative_to(ROOT)))

    endpoints = load(CONFIG / "endpoints" / "codestra.json")
    public = "https://auth.codestra.co"
    expected_endpoints = {
        "publicUrl": public,
        "adminApiBaseUrl": public,
        "realm": "codestra",
        "issuer": f"{public}/realms/codestra",
        "discoveryUrl": f"{public}/realms/codestra/.well-known/openid-configuration",
        "authorizationEndpoint": f"{public}/realms/codestra/protocol/openid-connect/auth",
        "tokenEndpoint": f"{public}/realms/codestra/protocol/openid-connect/token",
        "userInfoEndpoint": f"{public}/realms/codestra/protocol/openid-connect/userinfo",
        "jwksUri": f"{public}/realms/codestra/protocol/openid-connect/certs",
        "introspectionEndpoint": f"{public}/realms/codestra/protocol/openid-connect/token/introspect",
        "logoutEndpoint": f"{public}/realms/codestra/protocol/openid-connect/logout",
        "adminRealmEndpoint": f"{public}/admin/realms/codestra",
    }
    for key, value in expected_endpoints.items():
        require(endpoints.get(key) == value, f"canonical endpoint mismatch: {key}")

    realm = load(CONFIG / "realms" / "codestra.json")
    require(realm.get("realm") == "codestra" and realm.get("enabled") is True, "realm invariant mismatch")

    managed = load(CONFIG / "policy" / "managed-clients.json").get("clients")
    creatable = load(CONFIG / "policy" / "creatable-clients.json").get("clients")
    require(managed == MANAGED_CLIENTS, "managed-client policy mismatch")
    require(creatable == CREATABLE_CLIENTS, "creatable-client policy mismatch")
    configured = sorted(load(path).get("clientId") for path in CLIENTS.glob("*.json"))
    require(configured == sorted(MANAGED_CLIENTS), "client desired-state inventory mismatch")
    for path in sorted(CLIENTS.glob("*.json")):
        client = load(path)
        validate_client(client["clientId"], client)

    managed_roles = load(CONFIG / "policy" / "managed-realm-roles.json").get("roles")
    creatable_roles = load(CONFIG / "policy" / "creatable-realm-roles.json").get("roles")
    require(managed_roles == MANAGED_ROLES, "managed realm-role policy mismatch")
    require(creatable_roles == MANAGED_ROLES, "creatable realm-role policy mismatch")
    configured_roles = sorted(load(path).get("name") for path in ROLES.glob("*.json"))
    require(configured_roles == sorted(MANAGED_ROLES), "realm-role desired-state inventory mismatch")

    for path in sorted(ROLES.glob("*.json")):
        role = load(path)
        name = role["name"]
        attrs = role.get("attributes", {})
        family = attrs.get("codestra.role.family")
        level = attrs.get("codestra.role.level")
        require(role.get("composite") is False and role.get("clientRole") is False, f"{name}: role shape mismatch")
        require(family in (["observability"], ["secrets"]), f"{name}: role family mismatch")
        require(level in (["viewer"], ["operator"], ["admin"]), f"{name}: role level mismatch")
        require(attrs.get("codestra.assignment.independent_approval") == ["true"], f"{name}: independent approval required")
        require(attrs.get("codestra.cross_family_grant") == ["false"], f"{name}: cross-family grant prohibited")
        require(
            (name.startswith("observability-") and family == ["observability"])
            or (name.startswith("secrets-") and family == ["secrets"]),
            f"{name}: role family/name mismatch",
        )
        allowlist = load(ROLE_ALLOWLISTS / f"{name}.json")
        require(allowlist.get("roleName") == name, f"{name}: role allowlist identity mismatch")
        require(set(allowlist.get("topLevelFields", [])) == set(role), f"{name}: role allowlist mismatch")
        require(set(allowlist.get("attributeFields", [])) == set(attrs), f"{name}: role attribute allowlist mismatch")

    require(
        load(CONFIG / "policy" / "secret-export-clients.json")
        == {"clients": list(OBSERVABILITY)},
        "secret-export client policy mismatch",
    )
    contract = load(CONFIG / "contracts" / "observability-browser-clients.json")
    require(contract.get("activation") == EXPECTED_ACTIVATION, "observability activation contract mismatch")
    require(
        contract.get("roleIsolation") == {
            "observabilityRolesDoNotGrantSecretsAccess": True,
            "secretsRolesDoNotGrantObservabilityAdmin": True,
            "administrativeMfaRequired": True,
            "leastPrivilegeRequired": True,
        },
        "observability role-isolation contract mismatch",
    )
    validate_ruleset()

    for path in (
        ROOT / "scripts" / "protected_identity_engine.py",
        ROOT / "scripts" / "export-generated-client-secrets.sh",
        ROOT / "scripts" / "test-plan-gate.sh",
    ):
        require(path.is_file(), f"required protected-identity file missing: {path.name}")

    print(f"MANAGED_CLIENTS={len(MANAGED_CLIENTS)}")
    print(f"MANAGED_REALM_ROLES={len(MANAGED_ROLES)}")
    print("OBSERVABILITY_ROLE_ISOLATION=PASS")
    print("SECRET_MATERIAL_POLICY=PASS")
    print("PROTECTED_IDENTITY_SOURCE=PASS")


if __name__ == "__main__":
    main()
