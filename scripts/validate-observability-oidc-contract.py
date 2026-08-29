#!/usr/bin/env python3
"""Validate the reviewed Codestra observability browser-client contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "contracts" / "observability-browser-clients.json"
EXPECTED_ISSUER = "https://auth.codestra.co/realms/codestra"
EXPECTED_CLIENTS = {
    "grafana-observability": {
        "applicationUrl": "https://graf.codestra.media",
        "redirectUris": ["https://graf.codestra.media/login/generic_oauth"],
        "roles": {
            "observability-viewer",
            "observability-operator",
            "observability-admin",
        },
    },
    "superset-analytics": {
        "applicationUrl": "https://supe.codestra.media",
        "redirectUris": ["https://supe.codestra.media/oauth-authorized/keycloak"],
        "roles": {
            "observability-viewer",
            "observability-operator",
            "observability-admin",
        },
    },
    "openbao-secrets": {
        "applicationUrl": "https://bao.codestra.media",
        "redirectUris": [
            "https://bao.codestra.media/v1/auth/oidc/callback",
            "https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback",
            "http://localhost:8250/oidc/callback",
        ],
        "roles": {"secrets-operator", "secrets-admin"},
    },
}


def fail(message: str) -> None:
    print(f"OBSERVABILITY_OIDC_VALIDATION_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def is_allowed_uri(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme == "https" and parsed.hostname:
        return True
    return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}


def main() -> None:
    if not CONTRACT.is_file():
        fail(f"missing contract: {CONTRACT}")

    try:
        data = json.loads(CONTRACT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse contract: {exc}")

    if data.get("version") != 1:
        fail("version must be 1")
    if data.get("issuer") != EXPECTED_ISSUER:
        fail("issuer is not the canonical Codestra issuer")

    clients = data.get("clients")
    if not isinstance(clients, list) or len(clients) != len(EXPECTED_CLIENTS):
        fail("exactly three reviewed clients are required")

    configured_ids = [client.get("clientId") for client in clients]
    if configured_ids != list(EXPECTED_CLIENTS):
        fail("clients must be unique and in canonical order")

    for client in clients:
        client_id = client["clientId"]
        expected = EXPECTED_CLIENTS[client_id]

        if client.get("applicationUrl") != expected["applicationUrl"]:
            fail(f"{client_id}: application URL mismatch")
        if client.get("clientType") != "confidential":
            fail(f"{client_id}: client must be confidential")
        if client.get("grantType") != "authorization_code":
            fail(f"{client_id}: only authorization_code is allowed")
        if client.get("pkceCodeChallengeMethod") != "S256":
            fail(f"{client_id}: PKCE S256 is required")
        if client.get("directAccessGrantsEnabled") is not False:
            fail(f"{client_id}: direct grants must be disabled")
        if client.get("implicitFlowEnabled") is not False:
            fail(f"{client_id}: implicit flow must be disabled")
        if client.get("serviceAccountsEnabled") is not False:
            fail(f"{client_id}: service accounts must be disabled")
        if client.get("secretSource") != "external-secret-manager":
            fail(f"{client_id}: secret source must remain external")

        redirects = client.get("redirectUris")
        if redirects != expected["redirectUris"]:
            fail(f"{client_id}: redirect URI mismatch")
        if len(set(redirects)) != len(redirects):
            fail(f"{client_id}: duplicate redirect URI")
        if not all(is_allowed_uri(uri) and "*" not in uri for uri in redirects):
            fail(f"{client_id}: unsafe redirect URI")

        origins = client.get("webOrigins")
        if origins != [expected["applicationUrl"]]:
            fail(f"{client_id}: web origin mismatch")
        if set(client.get("requiredRoles", [])) != expected["roles"]:
            fail(f"{client_id}: required role set mismatch")

    isolation = data.get("roleIsolation", {})
    required_true = (
        "observabilityRolesDoNotGrantSecretsAccess",
        "secretsRolesDoNotGrantObservabilityAdmin",
        "administrativeMfaRequired",
        "leastPrivilegeRequired",
    )
    if not all(isolation.get(key) is True for key in required_true):
        fail("role isolation and MFA controls must remain enabled")

    activation = data.get("activation", {})
    unsafe_true = [
        key
        for key, value in activation.items()
        if key != "contractReviewed" and value is True
    ]
    if unsafe_true:
        fail(f"contract branch must not activate live identity: {unsafe_true}")

    print("OBSERVABILITY_OIDC_CONTRACT_VALID=1")


if __name__ == "__main__":
    main()
