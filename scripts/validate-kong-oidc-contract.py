#!/usr/bin/env python3
"""Validate Keycloak's source-side trust contract for Kong.

This validator is read-only. It proves the reviewed desired-state files expose the
issuer/audience/scope contract Kong is expected to enforce; it does not prove a live
Kong or Keycloak runtime is configured.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"KONG_OIDC_CONTRACT=FAIL expected object: {path}")
    return value


def fail(message: str) -> None:
    raise SystemExit(f"KONG_OIDC_CONTRACT=FAIL {message}")


def mapper(client: dict, name: str) -> dict:
    for item in client.get("protocolMappers", []):
        if item.get("name") == name:
            return item
    fail(f"missing mapper {name}")
    raise AssertionError


def main() -> int:
    endpoints = load(CONFIG / "endpoints" / "codestra.json")
    kong = load(CONFIG / "clients" / "kong-gateway.json")
    matrix = load(CONFIG / "contracts" / "service-access-matrix.json")
    machine = load(CONFIG / "contracts" / "machine-clients.json")

    issuer = "https://auth.codestra.co/realms/codestra"
    if endpoints.get("issuer") != issuer:
        fail("canonical issuer drifted")
    if endpoints.get("discoveryUrl") != issuer + "/.well-known/openid-configuration":
        fail("OIDC discovery URL drifted")
    if endpoints.get("jwksUri") != issuer + "/protocol/openid-connect/certs":
        fail("JWKS URL drifted")

    required_shape = {
        "clientId": "kong-gateway",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "authorizationServicesEnabled": False,
        "fullScopeAllowed": False,
    }
    for key, expected in required_shape.items():
        if kong.get(key) != expected:
            fail(f"kong-gateway {key} must be {expected!r}")
    if kong.get("redirectUris") != [] or kong.get("webOrigins") != []:
        fail("kong-gateway machine client must not have browser redirect/origin wildcards")
    if "secret" in kong or "credentials" in kong:
        fail("kong-gateway desired state must not contain credentials")
    if int(kong.get("attributes", {}).get("access.token.lifespan", "0")) > 300:
        fail("kong-gateway access token lifetime exceeds 300 seconds")

    audience = mapper(kong, "audience-middleware-api")
    if audience.get("config", {}).get("included.custom.audience") != "middleware-api":
        fail("kong-gateway must emit middleware-api audience")
    scopes = mapper(kong, "reviewed-service-scopes").get("config", {}).get("claim.value", "").split()
    if set(scopes) != {"middleware.request.forward", "middleware.status.read"}:
        fail("kong-gateway reviewed service scopes drifted")

    clients = {item.get("clientId"): item for item in machine.get("clients", [])}
    for client_id in ("kong-gateway", "middleware-api", "n8n-automation"):
        item = clients.get(client_id)
        if not item:
            fail(f"missing protected machine client {client_id}")
        if item.get("clientType") != "confidential" or item.get("serviceAccountsEnabled") is not True:
            fail(f"{client_id} must remain a confidential service-account client")

    grants = [
        item
        for item in matrix.get("grants", [])
        if item.get("callerClientId") == "kong-gateway"
        and item.get("targetClientId") == "middleware-api"
    ]
    if len(grants) != 1:
        fail("expected exactly one kong-gateway -> middleware-api grant")
    grant = grants[0]
    if grant.get("audience") != "middleware-api":
        fail("Kong -> Middleware grant audience drifted")
    if set(grant.get("scopes", [])) != {"middleware.request.forward", "middleware.status.read"}:
        fail("Kong -> Middleware grant scopes drifted")

    print("KONG_OIDC_CONTRACT=PASS")
    print(f"ISSUER={issuer}")
    print("KONG_CLIENT=kong-gateway")
    print("MIDDLEWARE_AUDIENCE=middleware-api")
    print("SIGNATURE_EXPIRY_RUNTIME_EVIDENCE=REQUIRED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
