#!/usr/bin/env python3
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
    "grafana-observability": ("https://graf.codestra.media", ["https://graf.codestra.media/login/generic_oauth"], {"observability-viewer", "observability-operator", "observability-admin"}),
    "superset-analytics": ("https://supe.codestra.media", ["https://supe.codestra.media/oauth-authorized/keycloak"], {"observability-viewer", "observability-operator", "observability-admin"}),
    "openbao-secrets": ("https://bao.codestra.media", ["https://bao.codestra.media/v1/auth/oidc/callback", "https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback", "http://localhost:8250/oidc/callback"], {"secrets-operator", "secrets-admin"}),
}


def fail(message: str) -> None:
    print(f"OBSERVABILITY_OIDC_VALIDATION_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(str(exc))


def allowed_uri(value: str) -> bool:
    parsed = urlparse(value)
    return (parsed.scheme == "https" and bool(parsed.hostname) and "*" not in value) or (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"} and "*" not in value)


def main() -> None:
    contract = load(CONTRACT)
    if contract.get("version") != 1 or contract.get("issuer") != EXPECTED_ISSUER:
        fail("contract version or issuer mismatch")
    clients = contract.get("clients")
    if not isinstance(clients, list) or [item.get("clientId") for item in clients] != list(EXPECTED):
        fail("client set/order mismatch")
    for item in clients:
        client_id = item["clientId"]
        origin, redirects, roles = EXPECTED[client_id]
        if item.get("applicationUrl") != origin or item.get("redirectUris") != redirects:
            fail(f"{client_id}: URL mismatch")
        if item.get("clientType") != "confidential" or item.get("grantType") != "authorization_code" or item.get("pkceCodeChallengeMethod") != "S256":
            fail(f"{client_id}: unsafe client type or grant")
        if any(item.get(key) is not False for key in ("directAccessGrantsEnabled", "implicitFlowEnabled", "serviceAccountsEnabled")):
            fail(f"{client_id}: unsafe flow enabled")
        if item.get("secretSource") != "external-secret-manager" or set(item.get("requiredRoles", [])) != roles:
            fail(f"{client_id}: secret source or role set mismatch")
        if not all(allowed_uri(uri) for uri in redirects):
            fail(f"{client_id}: unsafe callback")
        desired = load(CLIENT_DIR / f"{client_id}.json")
        if desired.get("clientId") != client_id or desired.get("redirectUris") != redirects or desired.get("webOrigins") != [origin]:
            fail(f"{client_id}: managed overlay does not match contract")
        if desired.get("clientAuthenticatorType") != "client-secret" or desired.get("publicClient") is not False or desired.get("standardFlowEnabled") is not True:
            fail(f"{client_id}: managed overlay is not confidential authorization-code")
    if contract.get("activation") != {"contractReviewed": True, "managedClientApplySupportAdded": True, "liveClientsCreated": False, "liveSecretsGenerated": False, "productionAccessEnabled": False}:
        fail("activation state must show source support without live activation")
    isolation = contract.get("roleIsolation", {})
    if not all(isolation.get(key) is True for key in ("observabilityRolesDoNotGrantSecretsAccess", "secretsRolesDoNotGrantObservabilityAdmin", "administrativeMfaRequired", "leastPrivilegeRequired")):
        fail("role isolation controls are incomplete")
    print("OBSERVABILITY_OIDC_CONTRACT_VALID=1")
    print("OBSERVABILITY_MANAGED_OVERLAYS=PASS")
    print("OBSERVABILITY_LIVE_ACTIVATION=DISABLED")


if __name__ == "__main__":
    main()
