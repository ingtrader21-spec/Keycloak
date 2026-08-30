#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "identity" / "moneybee-oidc-clients.json"
DOMAIN_REGISTRY = ROOT / "config" / "identity" / "application-domain-registry.json"
MANAGED_CLIENTS = ROOT / "config" / "policy" / "managed-clients.json"
CREATABLE_CLIENTS = ROOT / "config" / "policy" / "creatable-clients.json"
MACHINE_CLIENTS = ROOT / "config" / "contracts" / "machine-clients.json"
PRODUCT_MIDDLEWARE_CLIENTS = ROOT / "config" / "contracts" / "product-middleware-clients.json"
CLIENT_DIR = ROOT / "config" / "clients"

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
EXPECTED_CLIENT_IDS = {item["clientId"] for item in EXPECTED_CLIENTS.values()}


def fail(message: str) -> None:
    raise RuntimeError(message)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable to load {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def exact_https(url: str, label: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.fragment:
        fail(f"{label} must be an absolute HTTPS URL")
    if "*" in url:
        fail(f"{label} must not contain wildcards")
    if parsed.hostname in EXPECTED_FORBIDDEN:
        fail(f"{label} uses a forbidden MoneyBee runtime domain")


def validate_audience_mapper(overlay: dict, client_id: str) -> None:
    mappers = overlay.get("protocolMappers")
    if not isinstance(mappers, list) or len(mappers) != 1:
        fail(f"{client_id}: exactly one managed protocol mapper is required")
    mapper = mappers[0]
    if not isinstance(mapper, dict):
        fail(f"{client_id}: protocol mapper must be an object")
    expected = {
        "name": "moneybee-api-audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "consentRequired": False,
        "config": {
            "included.custom.audience": EXPECTED_AUDIENCE,
            "id.token.claim": "false",
            "access.token.claim": "true",
        },
    }
    if mapper != expected:
        fail(f"{client_id}: moneybee-api audience mapper changed")


def main() -> int:
    data = load(CONTRACT)
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
        if not isinstance(client, dict):
            fail("MoneyBee client entries must be objects")
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

        client_id = client["clientId"]
        overlay_path = CLIENT_DIR / f"{client_id}.json"
        overlay = load(overlay_path)
        if overlay.get("clientId") != client_id:
            fail(f"{client_id}: desired-state overlay clientId mismatch")
        if overlay.get("rootUrl") != origin or overlay.get("baseUrl") != f"{origin}/":
            fail(f"{client_id}: desired-state origin mismatch")
        if overlay.get("redirectUris") != expected_redirects:
            fail(f"{client_id}: desired-state redirect URIs diverge from contract")
        if overlay.get("webOrigins") != [origin]:
            fail(f"{client_id}: desired-state web origin diverges from contract")
        attributes = overlay.get("attributes") or {}
        if attributes.get("pkce.code.challenge.method") != "S256":
            fail(f"{client_id}: PKCE S256 is required")
        if attributes.get("post.logout.redirect.uris") != f"{origin}/auth/login":
            fail(f"{client_id}: desired-state logout redirect diverges from contract")
        if overlay.get("publicClient") is not True:
            fail(f"{client_id}: browser client must remain public")
        if overlay.get("standardFlowEnabled") is not True:
            fail(f"{client_id}: Authorization Code flow must remain enabled")
        if overlay.get("implicitFlowEnabled") is not False:
            fail(f"{client_id}: implicit flow must remain disabled")
        if overlay.get("directAccessGrantsEnabled") is not False:
            fail(f"{client_id}: direct grants must remain disabled")
        if overlay.get("serviceAccountsEnabled") is not False:
            fail(f"{client_id}: service accounts must remain disabled")
        validate_audience_mapper(overlay, client_id)

    if seen_portals != set(EXPECTED_CLIENTS):
        fail("MoneyBee portal membership changed")
    if seen_client_ids != EXPECTED_CLIENT_IDS:
        fail("MoneyBee portal client IDs changed")

    managed = load(MANAGED_CLIENTS)
    managed_ids = set(managed.get("clients") or [])
    if not EXPECTED_CLIENT_IDS.issubset(managed_ids):
        fail("all MoneyBee clients must be in the protected managed-client policy")

    creatable = load(CREATABLE_CLIENTS)
    machine_ids = {
        item.get("clientId")
        for item in load(MACHINE_CLIENTS).get("clients", [])
        if isinstance(item, dict)
    }
    product_ids = {
        item.get("clientId")
        for item in load(PRODUCT_MIDDLEWARE_CLIENTS).get("clients", [])
        if isinstance(item, dict)
    }
    if None in product_ids:
        fail("product Middleware client contract contains an invalid clientId")
    expected_creatable = EXPECTED_CLIENT_IDS | machine_ids | product_ids | {
        "klyrow-portal",
        "n8n-editor-gateway",
    }
    if set(creatable.get("clients") or []) != expected_creatable:
        fail(
            "creatable clients must be exactly MoneyBee, klyrow portal, "
            "n8n editor gateway, and reviewed machine identities"
        )

    registry = load(DOMAIN_REGISTRY)
    domains = registry.get("domains")
    if not isinstance(domains, list):
        fail("application-domain registry domains must be a list")
    by_domain = {
        item.get("domain"): item
        for item in domains
        if isinstance(item, dict) and isinstance(item.get("domain"), str)
    }
    canonical = by_domain.get("moneybeeloan.com") or {}
    legacy = by_domain.get("moneybee.loan") or {}
    if canonical.get("canonicalDomain") != EXPECTED_CANONICAL_DOMAIN:
        fail("general registry disagrees on MoneyBee canonical domain")
    if canonical.get("apiAudience") != EXPECTED_AUDIENCE:
        fail("general registry disagrees on MoneyBee API audience")
    if canonical.get("humanClientId") is not None:
        fail("general MoneyBee registry must delegate human clients to dedicated contract")
    if canonical.get("clientKind") != "multi-public-pkce":
        fail("general MoneyBee registry must declare multi-public-pkce")
    if legacy.get("canonicalDomain") != EXPECTED_CANONICAL_DOMAIN:
        fail("moneybee.loan must point to moneybeeloan.com")
    if legacy.get("state") != "legacy-disabled" or legacy.get("enabled") is not False:
        fail("moneybee.loan must remain disabled")
    if legacy.get("humanClientId") is not None:
        fail("moneybee.loan must not retain a human client")

    serialized = "\n".join(
        [
            CONTRACT.read_text(encoding="utf-8"),
            DOMAIN_REGISTRY.read_text(encoding="utf-8"),
        ]
    ).lower()
    if "moneybee-portal" in serialized:
        fail("superseded moneybee-portal identity is prohibited")
    if "client_secret" in serialized or "begin private key" in serialized:
        fail("MoneyBee identity contracts must not contain secrets")

    print("MONEYBEE_OIDC_CONTRACT=PASS")
    print("MONEYBEE_CANONICAL_DOMAIN=moneybeeloan.com")
    print("MONEYBEE_HUMAN_CLIENTS=3")
    print("MONEYBEE_PKCE=S256")
    print("MONEYBEE_API_AUDIENCE=moneybee-api")
    print("MONEYBEE_AUDIENCE_MAPPER=PASS")
    print("MONEYBEE_MANAGED_POLICY=PASS")
    print("MONEYBEE_CREATABLE_POLICY=PASS")
    print("MONEYBEE_REGISTRY_CROSS_VALIDATION=PASS")
    print("MONEYBEE_FORBIDDEN_DOMAINS=moneybeeloans.com,moneybee.loan")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
