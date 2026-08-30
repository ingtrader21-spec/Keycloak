#!/usr/bin/env python3
"""Validate the MoneyBee OIDC contract and its protected-client composition."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"
CONTRACT = CONFIG / "identity" / "moneybee-oidc-clients.json"
DOMAIN_REGISTRY = CONFIG / "identity" / "application-domain-registry.json"
MANAGED_CLIENTS = CONFIG / "policy" / "managed-clients.json"
CREATABLE_CLIENTS = CONFIG / "policy" / "creatable-clients.json"
MACHINE_CLIENTS = CONFIG / "contracts" / "machine-clients.json"
PRODUCT_CLIENTS = CONFIG / "contracts" / "product-middleware-clients.json"
OBSERVABILITY_CLIENTS = CONFIG / "contracts" / "observability-browser-clients.json"
CLIENT_DIR = CONFIG / "clients"

ISSUER = "https://auth.codestra.co/realms/codestra"
CANONICAL_DOMAIN = "moneybeeloan.com"
AUDIENCE = "moneybee-api"
FORBIDDEN_DOMAINS = {"moneybeeloans.com", "moneybee.loan"}
PORTALS = {
    "borrower": ("moneybee-borrower", "https://app.moneybeeloan.com"),
    "lender": ("moneybee-lender", "https://lenders.moneybeeloan.com"),
    "admin": ("moneybee-admin", "https://admin.moneybeeloan.com"),
}
PORTAL_IDS = {client_id for client_id, _origin in PORTALS.values()}
ADDITIONAL_REVIEWED_SERVICE_IDS = {"sdk-intake"}


def fail(message: str) -> None:
    raise RuntimeError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable to load {path}: {exc}")
    require(isinstance(value, dict), f"{path} must contain a JSON object")
    return value


def exact_https(url: str, label: str) -> None:
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and bool(parsed.hostname), f"{label} must be an absolute HTTPS URL")
    require(not parsed.fragment and "*" not in url, f"{label} must be exact and fragment-free")
    require(parsed.hostname not in FORBIDDEN_DOMAINS, f"{label} uses a forbidden MoneyBee domain")


def validate_audience_mapper(overlay: dict, client_id: str) -> None:
    expected = {
        "name": "moneybee-api-audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "consentRequired": False,
        "config": {
            "included.custom.audience": AUDIENCE,
            "id.token.claim": "false",
            "access.token.claim": "true",
        },
    }
    require(overlay.get("protocolMappers") == [expected], f"{client_id}: audience mapper changed")


def contract_client_ids(path: Path, *, field: str = "clients") -> set[str]:
    values = load(path).get(field, [])
    require(isinstance(values, list), f"{path}: {field} must be an array")
    result: set[str] = set()
    for item in values:
        if isinstance(item, str):
            client_id = item
        else:
            require(isinstance(item, dict), f"{path}: invalid {field} entry")
            client_id = item.get("clientId")
        require(isinstance(client_id, str) and client_id, f"{path}: invalid clientId")
        require(client_id not in result, f"{path}: duplicate clientId {client_id}")
        result.add(client_id)
    return result


def approved_observability_client_ids() -> set[str]:
    contract = load(OBSERVABILITY_CLIENTS)
    require(contract.get("version") == 1, "observability browser-client contract version changed")
    require(contract.get("issuer") == ISSUER, "observability browser-client issuer changed")
    activation = contract.get("activation") or {}
    require(activation.get("managedClientApplySupportAdded") is True, "observability managed-client support is not approved")
    require(activation.get("liveClientsCreated") is False, "observability live clients must remain disabled")
    require(activation.get("productionAccessEnabled") is False, "observability production access must remain disabled")
    clients = contract.get("clients")
    require(isinstance(clients, list), "observability clients must be an array")
    expected = {"grafana-observability", "superset-analytics", "openbao-secrets"}
    found = {
        item.get("clientId")
        for item in clients
        if isinstance(item, dict) and isinstance(item.get("clientId"), str)
    }
    require(found == expected, "approved observability browser-client set changed")
    return found


def validate_additional_reviewed_service(client_id: str) -> None:
    overlay = load(CLIENT_DIR / f"{client_id}.json")
    require(overlay.get("clientId") == client_id, f"{client_id}: overlay identity mismatch")
    require(overlay.get("enabled") is True, f"{client_id}: must be enabled in desired state")
    require(overlay.get("protocol") == "openid-connect", f"{client_id}: protocol mismatch")
    require(overlay.get("publicClient") is False, f"{client_id}: must be confidential")
    require(overlay.get("bearerOnly") is False, f"{client_id}: bearerOnly mismatch")
    require(overlay.get("standardFlowEnabled") is False, f"{client_id}: browser code flow prohibited")
    require(overlay.get("implicitFlowEnabled") is False, f"{client_id}: implicit flow prohibited")
    require(overlay.get("directAccessGrantsEnabled") is False, f"{client_id}: direct grants prohibited")
    require(overlay.get("serviceAccountsEnabled") is True, f"{client_id}: service account required")
    require(overlay.get("authorizationServicesEnabled") is False, f"{client_id}: authorization services prohibited")
    require(overlay.get("fullScopeAllowed") is False, f"{client_id}: full scope prohibited")
    require(overlay.get("redirectUris") == [] and overlay.get("webOrigins") == [], f"{client_id}: browser URIs prohibited")
    attrs = overlay.get("attributes") or {}
    require(attrs.get("access.token.lifespan") == "300", f"{client_id}: token lifetime must be 300 seconds")
    mappers = {item.get("name"): item for item in overlay.get("protocolMappers", []) if isinstance(item, dict)}
    audience = mappers.get("audience-middleware-api") or {}
    require(audience.get("protocolMapper") == "oidc-audience-mapper", f"{client_id}: audience mapper type mismatch")
    require(
        audience.get("config", {}).get("included.custom.audience") == "middleware-api"
        and audience.get("config", {}).get("access.token.claim") == "true",
        f"{client_id}: middleware-api audience mapper mismatch",
    )
    scope = mappers.get("intake-service-scope") or {}
    require(scope.get("protocolMapper") == "oidc-hardcoded-claim-mapper", f"{client_id}: scope mapper type mismatch")
    require(
        scope.get("config", {}).get("claim.name") == "scope"
        and scope.get("config", {}).get("claim.value") == "leads.write surveys.write"
        and scope.get("config", {}).get("access.token.claim") == "true",
        f"{client_id}: intake scope mapper mismatch",
    )


def main() -> int:
    data = load(CONTRACT)
    require(data.get("schemaVersion") == 1, "schemaVersion must be 1")
    require(data.get("realm") == "codestra" and data.get("issuer") == ISSUER, "MoneyBee realm/issuer changed")
    require(data.get("canonicalDomain") == CANONICAL_DOMAIN, "MoneyBee canonical domain changed")
    require(data.get("apiAudience") == AUDIENCE, "MoneyBee API audience changed")
    require(set(data.get("forbiddenRuntimeDomains", [])) == FORBIDDEN_DOMAINS, "forbidden MoneyBee domains changed")
    require(
        data.get("policy") == {
            "publicClientsOnly": True,
            "authorizationCodeFlow": True,
            "pkceMethod": "S256",
            "implicitFlow": False,
            "directAccessGrants": False,
            "serviceAccounts": False,
            "wildcardRedirectUris": False,
            "exactWebOrigins": True,
        },
        "MoneyBee OIDC security policy changed",
    )

    clients = data.get("clients")
    require(isinstance(clients, list) and len(clients) == 3, "exactly three MoneyBee portal clients are required")
    seen_portals: set[str] = set()
    seen_ids: set[str] = set()
    for client in clients:
        require(isinstance(client, dict), "MoneyBee client entries must be objects")
        portal = client.get("portal")
        require(portal in PORTALS and portal not in seen_portals, f"unexpected or duplicate portal: {portal}")
        seen_portals.add(portal)
        expected_id, origin = PORTALS[portal]
        client_id = client.get("clientId")
        require(client_id == expected_id and client_id not in seen_ids, f"{portal}: clientId mismatch")
        seen_ids.add(client_id)
        require(client.get("origin") == origin, f"{portal}: origin mismatch")
        exact_https(origin, f"{portal}.origin")
        redirects = [f"{origin}/auth/callback", f"{origin}/auth/silent-callback"]
        logout = [f"{origin}/auth/login"]
        require(client.get("redirectUris") == redirects, f"{portal}: redirect URI contract changed")
        require(client.get("postLogoutRedirectUris") == logout, f"{portal}: logout contract changed")
        require(client.get("webOrigins") == [origin], f"{portal}: web-origin contract changed")
        for label, values in (
            ("redirectUris", redirects),
            ("postLogoutRedirectUris", logout),
            ("webOrigins", [origin]),
        ):
            for index, value in enumerate(values):
                exact_https(value, f"{portal}.{label}[{index}]")

        overlay = load(CLIENT_DIR / f"{client_id}.json")
        require(overlay.get("clientId") == client_id, f"{client_id}: overlay identity mismatch")
        require(overlay.get("rootUrl") == origin and overlay.get("baseUrl") == f"{origin}/", f"{client_id}: overlay origin mismatch")
        require(overlay.get("redirectUris") == redirects, f"{client_id}: overlay callbacks changed")
        require(overlay.get("webOrigins") == [origin], f"{client_id}: overlay web origin changed")
        attrs = overlay.get("attributes") or {}
        require(attrs.get("pkce.code.challenge.method") == "S256", f"{client_id}: PKCE S256 required")
        require(attrs.get("post.logout.redirect.uris") == logout[0], f"{client_id}: logout overlay changed")
        require(overlay.get("publicClient") is True, f"{client_id}: portal must remain public")
        require(overlay.get("standardFlowEnabled") is True, f"{client_id}: code flow required")
        require(overlay.get("implicitFlowEnabled") is False, f"{client_id}: implicit flow prohibited")
        require(overlay.get("directAccessGrantsEnabled") is False, f"{client_id}: direct grants prohibited")
        require(overlay.get("serviceAccountsEnabled") is False, f"{client_id}: service account prohibited")
        validate_audience_mapper(overlay, client_id)

    require(seen_portals == set(PORTALS) and seen_ids == PORTAL_IDS, "MoneyBee portal membership changed")

    managed_ids = contract_client_ids(MANAGED_CLIENTS)
    require(PORTAL_IDS <= managed_ids, "MoneyBee clients are missing from managed policy")
    machine_ids = contract_client_ids(MACHINE_CLIENTS)
    product_ids = contract_client_ids(PRODUCT_CLIENTS)
    observability_ids = approved_observability_client_ids()
    for client_id in ADDITIONAL_REVIEWED_SERVICE_IDS:
        require(client_id in managed_ids, f"{client_id}: reviewed service is missing from managed policy")
        validate_additional_reviewed_service(client_id)
    expected_creatable = PORTAL_IDS | machine_ids | product_ids | observability_ids | ADDITIONAL_REVIEWED_SERVICE_IDS
    actual_creatable = contract_client_ids(CREATABLE_CLIENTS)
    require(
        actual_creatable == expected_creatable,
        "creatable clients must be exactly MoneyBee, reviewed machine identities, approved observability browsers, and explicitly reviewed service identities",
    )

    registry = load(DOMAIN_REGISTRY)
    domains = registry.get("domains")
    require(isinstance(domains, list), "application-domain registry domains must be an array")
    by_domain = {
        item.get("domain"): item
        for item in domains
        if isinstance(item, dict) and isinstance(item.get("domain"), str)
    }
    canonical = by_domain.get(CANONICAL_DOMAIN) or {}
    legacy = by_domain.get("moneybee.loan") or {}
    require(canonical.get("canonicalDomain") == CANONICAL_DOMAIN, "registry canonical domain mismatch")
    require(canonical.get("apiAudience") == AUDIENCE, "registry audience mismatch")
    require(canonical.get("humanClientId") is None, "registry must delegate MoneyBee human clients")
    require(canonical.get("clientKind") == "multi-public-pkce", "registry MoneyBee client kind changed")
    require(legacy.get("canonicalDomain") == CANONICAL_DOMAIN, "legacy alias target changed")
    require(legacy.get("state") == "legacy-disabled" and legacy.get("enabled") is False, "legacy alias must remain disabled")
    require(legacy.get("humanClientId") is None, "legacy alias must not retain a client")

    serialized = (CONTRACT.read_text(encoding="utf-8") + DOMAIN_REGISTRY.read_text(encoding="utf-8")).lower()
    require("moneybee-portal" not in serialized, "superseded moneybee-portal identity is prohibited")
    require("client_secret" not in serialized and "begin private key" not in serialized, "identity contracts contain secret material")

    print("MONEYBEE_OIDC_CONTRACT=PASS")
    print("MONEYBEE_CANONICAL_DOMAIN=moneybeeloan.com")
    print("MONEYBEE_HUMAN_CLIENTS=3")
    print("MONEYBEE_PKCE=S256")
    print("MONEYBEE_API_AUDIENCE=moneybee-api")
    print("MONEYBEE_AUDIENCE_MAPPER=PASS")
    print("MONEYBEE_MANAGED_POLICY=PASS")
    print("MONEYBEE_CREATABLE_POLICY=PASS")
    print("MONEYBEE_OBSERVABILITY_COMPOSITION=PASS")
    print("MONEYBEE_ADDITIONAL_REVIEWED_SERVICES=PASS")
    print("MONEYBEE_REGISTRY_CROSS_VALIDATION=PASS")
    print("MONEYBEE_FORBIDDEN_DOMAINS=moneybeeloans.com,moneybee.loan")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())