#!/usr/bin/env python3
"""Fail-closed validation for the Codestra application/domain identity registry."""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "config" / "identity" / "application-domain-registry.json"
MONEYBEE_CONTRACT = ROOT / "config" / "identity" / "moneybee-oidc-clients.json"
MANAGED_CLIENTS = ROOT / "config" / "policy" / "managed-clients.json"
CANONICAL_ISSUER = "https://auth.codestra.co/realms/codestra"
EXPECTED_DOMAINS = {
    "codestra.agency",
    "codestra.co",
    "nativoenglish.com",
    "moneybeeloan.com",
    "codestra.cloud",
    "codestra.digital",
    "codestra.media",
    "moneybee.loan",
    "klyrow.com",
    "beyvra.com",
    "kyqra.com",
    "breero.com",
    "breero.shop",
    "telnexa.co",
    "booked4seasons.com",
}
EXPECTED_ALIAS_CLIENTS = {
    "codestra-portal-production": {"codestra.agency", "codestra.co"},
    "breero-portal": {"breero.com", "breero.shop"},
}
EXPECTED_MONEYBEE_CLIENTS = {
    "moneybee-admin",
    "moneybee-borrower",
    "moneybee-lender",
}
POSTAL_OK = "reported-spf-dkim-mx-return-path-ok"
POSTAL_UNCONFIRMED = "not-confirmed-no-completed-postal-dns-check"
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
CLIENT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")


class RegistryError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise RegistryError(message)


def object_at(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def array_at(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        fail(f"{label} keys changed: expected={sorted(expected)} actual={sorted(actual)}")


def validate_https_uri(value: str, label: str) -> None:
    if "*" in value:
        fail(f"{label} must not contain a wildcard")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        fail(f"{label} must be an absolute HTTPS URI")
    if parsed.username or parsed.password or parsed.fragment:
        fail(f"{label} contains prohibited URL components")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        return object_at(json.loads(path.read_text(encoding="utf-8")), label)
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable to load {path}: {exc}")


def validate() -> None:
    document = load_json(REGISTRY, "registry")
    exact_keys(
        document,
        {
            "schemaVersion",
            "realm",
            "issuer",
            "postalDnsEvidence",
            "policy",
            "domains",
        },
        "registry",
    )
    if document["schemaVersion"] != 1:
        fail("schemaVersion must be 1")
    if document["realm"] != "codestra" or document["issuer"] != CANONICAL_ISSUER:
        fail("realm or canonical issuer changed")

    evidence = object_at(document["postalDnsEvidence"], "postalDnsEvidence")
    exact_keys(
        evidence,
        {
            "source",
            "capturedDate",
            "runtimeReverificationRequired",
            "confirmedOkDomains",
            "unconfirmedDomains",
        },
        "postalDnsEvidence",
    )
    if evidence != {
        "source": "operator-reported-latest-postal-checks",
        "capturedDate": "2026-08-27",
        "runtimeReverificationRequired": True,
        "confirmedOkDomains": 14,
        "unconfirmedDomains": ["booked4seasons.com"],
    }:
        fail("Postal DNS evidence contract changed")

    policy = object_at(document["policy"], "policy")
    expected_policy = {
        "separateClientPerApplication": True,
        "exactRedirectUrisRequired": True,
        "wildcardRedirectUrisAllowed": False,
        "clientCreationBeforeRuntimeVerification": False,
        "localPasswordResetAllowed": False,
        "legacyIssuerAllowed": False,
    }
    if policy != expected_policy:
        fail("identity registry policy changed")

    domains = array_at(document["domains"], "domains")
    if len(domains) != 15:
        fail(f"exactly fifteen domains are required, found {len(domains)}")

    seen_domains: set[str] = set()
    clients_to_domains: dict[str, set[str]] = defaultdict(set)
    human_domains: set[str] = set()
    postal_ok_domains: set[str] = set()

    expected_entry_keys = {
        "domain",
        "application",
        "classification",
        "clientKind",
        "humanClientId",
        "apiAudience",
        "state",
        "canonicalDomain",
        "postalDnsState",
        "redirectUris",
        "webOrigins",
        "passwordResetDelegatedToKeycloak",
        "localPasswordResetAllowed",
        "enabled",
    }

    for index, raw in enumerate(domains):
        entry = object_at(raw, f"domains[{index}]")
        exact_keys(entry, expected_entry_keys, f"domains[{index}]")

        domain = entry["domain"]
        if not isinstance(domain, str) or not DOMAIN_PATTERN.fullmatch(domain):
            fail(f"domains[{index}].domain is invalid")
        if domain in seen_domains:
            fail(f"duplicate domain: {domain}")
        seen_domains.add(domain)

        canonical_domain = entry["canonicalDomain"]
        if not isinstance(canonical_domain, str) or not DOMAIN_PATTERN.fullmatch(
            canonical_domain
        ):
            fail(f"{domain}: canonicalDomain is invalid")

        if not isinstance(entry["application"], str) or not entry["application"]:
            fail(f"{domain}: application is required")
        if not isinstance(entry["classification"], str) or not entry["classification"]:
            fail(f"{domain}: classification is required")

        client_kind = entry["clientKind"]
        if client_kind not in {
            "public-pkce",
            "multi-public-pkce",
            "confidential-service",
            "legacy-disabled",
        }:
            fail(f"{domain}: unsupported clientKind")

        human_client = entry["humanClientId"]
        api_audience = entry["apiAudience"]
        for label, value in (
            ("humanClientId", human_client),
            ("apiAudience", api_audience),
        ):
            if value is not None and (
                not isinstance(value, str) or not CLIENT_PATTERN.fullmatch(value)
            ):
                fail(f"{domain}: {label} is invalid")

        state = entry["state"]
        if state not in {
            "managed",
            "managed-multi-client",
            "declared-runtime-binding-required",
            "declared-blocked-dns-unconfirmed",
            "legacy-disabled",
        }:
            fail(f"{domain}: unsupported state")

        postal_dns_state = entry["postalDnsState"]
        if postal_dns_state == POSTAL_OK:
            postal_ok_domains.add(domain)
        elif postal_dns_state == POSTAL_UNCONFIRMED:
            if domain != "booked4seasons.com":
                fail(f"{domain}: only booked4seasons.com may be DNS-unconfirmed")
        else:
            fail(f"{domain}: unsupported Postal DNS state")

        redirects = array_at(entry["redirectUris"], f"{domain}.redirectUris")
        origins = array_at(entry["webOrigins"], f"{domain}.webOrigins")
        if len(redirects) != len(set(redirects)) or len(origins) != len(set(origins)):
            fail(f"{domain}: duplicate redirect URI or web origin")
        for offset, uri in enumerate(redirects):
            if not isinstance(uri, str):
                fail(f"{domain}.redirectUris[{offset}] must be a string")
            validate_https_uri(uri, f"{domain}.redirectUris[{offset}]")
        for offset, origin in enumerate(origins):
            if not isinstance(origin, str):
                fail(f"{domain}.webOrigins[{offset}] must be a string")
            validate_https_uri(origin, f"{domain}.webOrigins[{offset}]")
            parsed = urlsplit(origin)
            if parsed.path not in {"", "/"} or parsed.query:
                fail(f"{domain}.webOrigins[{offset}] must contain only an origin")

        if entry["localPasswordResetAllowed"] is not False:
            fail(f"{domain}: local password reset must remain disabled")
        if not isinstance(entry["enabled"], bool):
            fail(f"{domain}: enabled must be boolean")
        if not isinstance(entry["passwordResetDelegatedToKeycloak"], bool):
            fail(f"{domain}: password-reset delegation must be boolean")

        if domain == "booked4seasons.com":
            if state != "declared-blocked-dns-unconfirmed":
                fail("booked4seasons.com must remain DNS-blocked")
            if postal_dns_state != POSTAL_UNCONFIRMED:
                fail("booked4seasons.com Postal DNS check must remain unconfirmed")
            if redirects or origins or entry["enabled"] is not False:
                fail("booked4seasons.com must remain disabled without redirects/origins")
        elif postal_dns_state != POSTAL_OK:
            fail(f"{domain}: expected operator-reported Postal DNS OK state")

        if client_kind == "public-pkce":
            if human_client is None:
                fail(f"{domain}: public PKCE client requires humanClientId")
            human_domains.add(domain)
            clients_to_domains[human_client].add(domain)
            if entry["passwordResetDelegatedToKeycloak"] is not True:
                fail(f"{domain}: public client must delegate password reset")
            if state == "managed":
                if domain != "klyrow.com":
                    fail("only klyrow.com may use single-client managed mode")
                if redirects != ["https://klyrow.com/"] or origins != [
                    "https://klyrow.com"
                ]:
                    fail("klyrow.com exact redirect/origin changed")
                if entry["enabled"] is not True:
                    fail("managed klyrow.com client must be enabled")
            else:
                if redirects or origins or entry["enabled"] is not False:
                    fail(
                        f"{domain}: unverified public client must remain disabled "
                        "with empty redirect/origin lists"
                    )
        elif client_kind == "multi-public-pkce":
            if domain != "moneybeeloan.com":
                fail("only moneybeeloan.com may use multi-public-pkce")
            if human_client is not None or api_audience != "moneybee-api":
                fail("moneybeeloan.com must delegate clients and declare moneybee-api")
            if state != "managed-multi-client" or canonical_domain != "moneybeeloan.com":
                fail("MoneyBee canonical multi-client state changed")
            if redirects or origins:
                fail("MoneyBee portal redirects belong in the dedicated OIDC contract")
            if entry["enabled"] is not True:
                fail("MoneyBee canonical application identity must be enabled")
            if entry["passwordResetDelegatedToKeycloak"] is not True:
                fail("MoneyBee must delegate password reset to Keycloak")
        elif client_kind == "confidential-service":
            if human_client is not None or not api_audience:
                fail(f"{domain}: service-only entry has invalid client mapping")
            if redirects or origins or entry["enabled"] is not False:
                fail(f"{domain}: unverified service entry must remain disabled")
            if entry["passwordResetDelegatedToKeycloak"] is not False:
                fail(f"{domain}: service-only entry cannot use password reset")
        else:
            if domain == "codestra.agency":
                if state != "legacy-disabled" or canonical_domain != "codestra.co":
                    fail("codestra.agency legacy mapping changed")
                if human_client:
                    clients_to_domains[human_client].add(domain)
            elif domain == "moneybee.loan":
                if state != "legacy-disabled" or canonical_domain != "moneybeeloan.com":
                    fail("moneybee.loan must remain a disabled alias of moneybeeloan.com")
                if human_client is not None or api_audience is not None:
                    fail("moneybee.loan must not define a runtime client or audience")
            else:
                fail("unsupported legacy-disabled domain")
            if redirects or origins or entry["enabled"] is not False:
                fail("legacy domain must remain disabled without redirect origins")
            if entry["passwordResetDelegatedToKeycloak"] is not False:
                fail("legacy domain must not initiate password recovery")

    if seen_domains != EXPECTED_DOMAINS:
        fail(
            "domain membership changed: "
            f"missing={sorted(EXPECTED_DOMAINS - seen_domains)} "
            f"extra={sorted(seen_domains - EXPECTED_DOMAINS)}"
        )
    if postal_ok_domains != EXPECTED_DOMAINS - {"booked4seasons.com"}:
        fail("operator-reported Postal DNS OK membership changed")

    for client_id, domains_for_client in clients_to_domains.items():
        if len(domains_for_client) > 1:
            expected = EXPECTED_ALIAS_CLIENTS.get(client_id)
            if expected != domains_for_client:
                fail(
                    f"unapproved client sharing for {client_id}: "
                    f"{sorted(domains_for_client)}"
                )
    for client_id, expected in EXPECTED_ALIAS_CLIENTS.items():
        if clients_to_domains.get(client_id) != expected:
            fail(f"approved alias mapping changed for {client_id}")

    by_domain = {entry["domain"]: entry for entry in domains}
    beyvra = by_domain["beyvra.com"]
    if (
        beyvra["humanClientId"] != "beyvra-web-production"
        or beyvra["apiAudience"] != "beyvra-api-production"
    ):
        fail("Beyvra trading frontend/backend identity mapping changed")
    if by_domain["codestra.cloud"]["clientKind"] != "confidential-service":
        fail("codestra.cloud must remain service-only")

    moneybee = load_json(MONEYBEE_CONTRACT, "MoneyBee OIDC contract")
    if moneybee.get("canonicalDomain") != "moneybeeloan.com":
        fail("MoneyBee dedicated contract canonical domain changed")
    if moneybee.get("apiAudience") != "moneybee-api":
        fail("MoneyBee dedicated contract API audience changed")
    moneybee_clients = {
        item.get("clientId") for item in array_at(moneybee.get("clients"), "MoneyBee clients")
    }
    if moneybee_clients != EXPECTED_MONEYBEE_CLIENTS:
        fail("MoneyBee dedicated portal client membership changed")

    managed = load_json(MANAGED_CLIENTS, "managed-client policy")
    managed_clients = set(array_at(managed.get("clients"), "managed clients"))
    if not EXPECTED_MONEYBEE_CLIENTS.issubset(managed_clients):
        fail("all MoneyBee portal clients must be protected managed clients")

    canonical_moneybee = by_domain["moneybeeloan.com"]
    legacy_moneybee = by_domain["moneybee.loan"]
    if canonical_moneybee["canonicalDomain"] != moneybee["canonicalDomain"]:
        fail("MoneyBee registry and dedicated contract disagree on canonical domain")
    if canonical_moneybee["apiAudience"] != moneybee["apiAudience"]:
        fail("MoneyBee registry and dedicated contract disagree on API audience")
    if legacy_moneybee["canonicalDomain"] != moneybee["canonicalDomain"]:
        fail("MoneyBee legacy alias does not point at the canonical domain")

    serialized = REGISTRY.read_text(encoding="utf-8").lower()
    retired_issuer = "auth.codestra" + ".agency/realms/codestra"
    prohibited = (
        "client_secret",
        "begin private key",
        "smtp_password",
        retired_issuer,
        "moneybee-portal",
    )
    if any(marker in serialized for marker in prohibited):
        fail("registry contains a secret-bearing, retired, or superseded identity literal")

    if len(human_domains) != 11:
        fail(f"expected eleven single-client public human domains, found {len(human_domains)}")


def main() -> int:
    try:
        validate()
    except RegistryError as exc:
        print(f"DOMAIN_IDENTITY_REGISTRY_ERROR={exc}", file=sys.stderr)
        return 1
    print("DOMAIN_IDENTITY_REGISTRY=PASS")
    print("DOMAIN_COUNT=15")
    print("SINGLE_CLIENT_HUMAN_PKCE_DOMAINS=11")
    print("MONEYBEE_MULTI_CLIENT_DOMAIN=PASS")
    print("MONEYBEE_CANONICAL_DOMAIN=moneybeeloan.com")
    print("MONEYBEE_LEGACY_ALIAS_DISABLED=PASS")
    print("SERVICE_ONLY_DOMAINS=1")
    print("LEGACY_DISABLED_DOMAINS=2")
    print("POSTAL_DNS_REPORTED_OK_DOMAINS=14")
    print("BOOKED4SEASONS_DNS_BLOCK=PASS")
    print("BEYVRA_TRADING_IDENTITY_MAPPING=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
