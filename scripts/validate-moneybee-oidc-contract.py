#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "identity" / "moneybee-oidc-clients.json"

EXPECTED_ISSUER = "https://auth.codestra.co/realms/codestra"
EXPECTED_CANONICAL_DOMAIN = "moneybeeloan.com"
EXPECTED_AUDIENCE = "moneybee-api"
EXPECTED_FORBIDDEN = {"moneybeeloans.com", "moneybee.loan"}
EXPECTED_CLIENTS = {
    "borrower": {
        "clientId": "moneybee-borrower",
        "origin": "https://app.moneybeeloan.com",
    },
    "lender": {
        "clientId": "moneybee-lender",
        "origin": "https://lenders.moneybeeloan.com",
    },
    "admin": {
        "clientId": "moneybee-admin",
        "origin": "https://admin.moneybeeloan.com",
    },
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def exact_https(url: str, label: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.fragment:
        fail(f"{label} must be an absolute HTTPS URL")
    if "*" in url:
        fail(f"{label} must not contain wildcards")
    if parsed.hostname in EXPECTED_FORBIDDEN:
        fail(f"{label} uses a forbidden MoneyBee runtime domain")


def main() -> int:
    data = json.loads(CONTRACT.read_text(encoding="utf-8"))
    if data.get("schemaVersion") != 1:
        fail("schemaVersion must be 1")
    if data.get("realm") != "codestra" or data.get("issuer") != EXPECTED_ISSUER:
        fail("MoneyBee must use the canonical Codestra realm and issuer")
    if data.get("canonicalDomain") != EXPECTED_CANONICAL_DOMAIN:
        fail("canonical MoneyBee domain must be moneybeeloan.com")
    if data.get("apiAudience") != EXPECTED_AUDIENCE:
        fail("MoneyBee API audience changed")
    if set(data.get("forbiddenRuntimeDomains", [])) != EXPECTED_FORBIDDEN:
        fail("forbidden MoneyBee runtime domains changed")

    policy = data.get("policy") or {}
    expected_policy = {
        "publicClientsOnly": True,
        "authorizationCodeFlow": True,
        "pkceMethod": "S256",
        "implicitFlow": False,
        "directAccessGrants": False,
        "serviceAccounts": False,
        "wildcardRedirectUris": False,
        "exactWebOrigins": True,
    }
    if policy != expected_policy:
        fail("MoneyBee OIDC security policy changed")

    clients = data.get("clients")
    if not isinstance(clients, list) or len(clients) != 3:
        fail("exactly three MoneyBee human portal clients are required")

    seen_portals: set[str] = set()
    seen_client_ids: set[str] = set()
    for client in clients:
        portal = client.get("portal")
        if portal not in EXPECTED_CLIENTS or portal in seen_portals:
            fail(f"unexpected or duplicate MoneyBee portal: {portal}")
        seen_portals.add(portal)
        expected = EXPECTED_CLIENTS[portal]
        if client.get("clientId") != expected["clientId"]:
            fail(f"{portal}: clientId mismatch")
        if client["clientId"] in seen_client_ids:
            fail("MoneyBee portal client IDs must be distinct")
        seen_client_ids.add(client["clientId"])

        origin = client.get("origin")
        if origin != expected["origin"]:
            fail(f"{portal}: origin mismatch")
        exact_https(origin, f"{portal}.origin")

        expected_redirects = [
            f"{origin}/auth/callback",
            f"{origin}/auth/silent-callback",
        ]
        if client.get("redirectUris") != expected_redirects:
            fail(f"{portal}: exact redirect URI contract changed")
        if client.get("postLogoutRedirectUris") != [f"{origin}/auth/login"]:
            fail(f"{portal}: exact post-logout redirect contract changed")
        if client.get("webOrigins") != [origin]:
            fail(f"{portal}: exact web origin contract changed")

        for label in ("redirectUris", "postLogoutRedirectUris", "webOrigins"):
            values = client.get(label)
            if not isinstance(values, list) or not values:
                fail(f"{portal}.{label} must be a non-empty list")
            for offset, value in enumerate(values):
                exact_https(value, f"{portal}.{label}[{offset}]")

    if seen_portals != set(EXPECTED_CLIENTS):
        fail("MoneyBee portal membership changed")

    serialized = CONTRACT.read_text(encoding="utf-8").lower()
    if "client_secret" in serialized or "begin private key" in serialized:
        fail("MoneyBee OIDC contract must not contain secrets")

    print("MONEYBEE_OIDC_CONTRACT=PASS")
    print("MONEYBEE_CANONICAL_DOMAIN=moneybeeloan.com")
    print("MONEYBEE_HUMAN_CLIENTS=3")
    print("MONEYBEE_PKCE=S256")
    print("MONEYBEE_FORBIDDEN_DOMAINS=moneybeeloans.com,moneybee.loan")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
