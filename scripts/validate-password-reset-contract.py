#!/usr/bin/env python3
"""Validate the Codestra Keycloak password-reset and Klyrow SMTP contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "email" / "keycloak-security-smtp.json"
DOMAIN_REGISTRY = ROOT / "config" / "identity" / "application-domain-registry.json"
CANONICAL_ISSUER = "https://auth.codestra.co/realms/codestra"
EXPECTED_APPLICATIONS = {
    "codestra.co": ("codestra-portal-production", "declared-runtime-binding-required"),
    "nativoenglish.com": ("nativoenglish-portal", "declared-runtime-binding-required"),
    "app.moneybeeloan.com": ("moneybee-borrower", "managed-multi-client"),
    "lenders.moneybeeloan.com": ("moneybee-lender", "managed-multi-client"),
    "admin.moneybeeloan.com": ("moneybee-admin", "managed-multi-client"),
    "codestra.digital": ("codestra-digital-portal", "declared-runtime-binding-required"),
    "codestra.media": ("codestra-media-portal", "declared-runtime-binding-required"),
    "klyrow.com": ("klyrow-portal", "managed"),
    "beyvra.com": ("beyvra-web-production", "declared-runtime-binding-required"),
    "kyqra.com": ("kyqra-portal", "declared-runtime-binding-required"),
    "breero.com": ("breero-portal", "declared-runtime-binding-required"),
    "breero.shop": ("breero-portal", "declared-runtime-binding-required"),
    "telnexa.co": ("telnexa-portal", "declared-runtime-binding-required"),
    "booked4seasons.com": (
        "booked4seasons-portal",
        "declared-blocked-dns-unconfirmed",
    ),
}
EXPECTED_DELEGATED_DOMAINS = {
    "codestra.co",
    "nativoenglish.com",
    "moneybeeloan.com",
    "codestra.digital",
    "codestra.media",
    "klyrow.com",
    "beyvra.com",
    "kyqra.com",
    "breero.com",
    "breero.shop",
    "telnexa.co",
    "booked4seasons.com",
}
EXPECTED_FORBIDDEN_CONSUMERS = {
    "kong-gateway",
    "middleware-api",
    "middleware-worker",
    "moneybee-backend",
    "odoo-integration",
    "n8n-automation",
    "vicidial-adapter",
    "telnexa-gateway",
    "klyrow-gateway",
    "kyqra-gateway",
    "postly-adapter",
    "provisioning-service",
    "monitoring-readonly",
    "codestra-api-production",
    "beyvra-api-production",
    "breero-api-production",
}
ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]+$")


class ContractError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ContractError(message)


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


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable to load {path}: {exc}")
    return object_at(value, label)


def validate() -> None:
    document = load_json(CONTRACT, "contract")
    exact_keys(
        document,
        {
            "schemaVersion",
            "realm",
            "issuer",
            "domainRegistry",
            "passwordReset",
            "smtp",
            "humanApplications",
            "forbiddenResetDataConsumers",
        },
        "contract",
    )
    if document["schemaVersion"] != 1:
        fail("schemaVersion must be 1")
    if document["realm"] != "codestra" or document["issuer"] != CANONICAL_ISSUER:
        fail("realm or canonical issuer is invalid")
    if document["domainRegistry"] != "config/identity/application-domain-registry.json":
        fail("password-reset contract must reference the fifteen-domain registry")

    reset = object_at(document["passwordReset"], "passwordReset")
    exact_keys(
        reset,
        {
            "enabled",
            "updatePasswordRequiredActionEnabled",
            "forceLoginAfterReset",
            "resetTokenLifespanSeconds",
            "genericAccountLookupResponse",
            "passwordAuthority",
        },
        "passwordReset",
    )
    if reset["enabled"] is not True:
        fail("forgot-password flow must be enabled")
    if reset["updatePasswordRequiredActionEnabled"] is not True:
        fail("UPDATE_PASSWORD required action must be enabled")
    if reset["forceLoginAfterReset"] is not True:
        fail("password reset must force re-authentication")
    if reset["genericAccountLookupResponse"] is not True:
        fail("password reset must resist account enumeration")
    if reset["passwordAuthority"] != "keycloak-only":
        fail("Keycloak must be the only password authority")
    lifespan = reset["resetTokenLifespanSeconds"]
    if not isinstance(lifespan, int) or not 300 <= lifespan <= 1800:
        fail("reset-token lifespan must be between 300 and 1800 seconds")

    smtp = object_at(document["smtp"], "smtp")
    exact_keys(
        smtp,
        {
            "provider",
            "connectivity",
            "hostEnvironment",
            "portEnvironment",
            "defaultHost",
            "privateAddress",
            "defaultPort",
            "encryption",
            "authenticationType",
            "usernameSecret",
            "passwordSecret",
            "fromAddressEnvironment",
            "fromDisplayNameEnvironment",
            "replyToEnvironment",
            "envelopeFromEnvironment",
            "requiredKlyrowStream",
            "senderMustBeVerified",
            "credentialsMustBeDedicated",
        },
        "smtp",
    )
    if smtp["provider"] != "klyrow-postal":
        fail("SMTP provider must be klyrow-postal")
    if smtp["connectivity"] != "private-vlan-only":
        fail("Keycloak SMTP must remain on the private network")
    if (smtp["defaultHost"] != "mail.klyrow.com" or smtp["privateAddress"] != "10.40.0.4"
            or smtp["defaultPort"] != 587):
        fail("approved private Klyrow SMTP endpoint changed")
    if smtp["encryption"] != "starttls" or smtp["authenticationType"] != "password":
        fail("Klyrow SMTP must use authenticated STARTTLS")
    if smtp["requiredKlyrowStream"] != "SECURITY":
        fail("Keycloak mail must use the dedicated SECURITY stream")
    if smtp["senderMustBeVerified"] is not True or smtp["credentialsMustBeDedicated"] is not True:
        fail("Keycloak requires a verified sender and dedicated SMTP credential")

    environment_fields = (
        "hostEnvironment",
        "portEnvironment",
        "usernameSecret",
        "passwordSecret",
        "fromAddressEnvironment",
        "fromDisplayNameEnvironment",
        "replyToEnvironment",
        "envelopeFromEnvironment",
    )
    for field in environment_fields:
        value = smtp[field]
        if not isinstance(value, str) or not ENVIRONMENT_NAME.fullmatch(value):
            fail(f"smtp.{field} must be an environment or secret name")
    if smtp["usernameSecret"] != "KC_SMTP_USERNAME" or smtp["passwordSecret"] != "KC_SMTP_PASSWORD":
        fail("SMTP credential secret names changed")

    applications = array_at(document["humanApplications"], "humanApplications")
    if len(applications) != len(EXPECTED_APPLICATIONS):
        fail("human application membership changed")
    seen: set[str] = set()
    for index, raw in enumerate(applications):
        app = object_at(raw, f"humanApplications[{index}]")
        exact_keys(
            app,
            {"application", "clientId", "state", "localPasswordResetAllowed"},
            f"humanApplications[{index}]",
        )
        application = app["application"]
        if application not in EXPECTED_APPLICATIONS or application in seen:
            fail(f"unknown or duplicate human application: {application}")
        seen.add(application)
        expected_client, expected_state = EXPECTED_APPLICATIONS[application]
        if app["clientId"] != expected_client or app["state"] != expected_state:
            fail(f"{application}: client or state changed")
        if app["localPasswordResetAllowed"] is not False:
            fail(f"{application}: local password reset must remain disabled")

    forbidden = array_at(document["forbiddenResetDataConsumers"], "forbiddenResetDataConsumers")
    if set(forbidden) != EXPECTED_FORBIDDEN_CONSUMERS or len(forbidden) != len(set(forbidden)):
        fail("password-reset data consumer prohibition changed")

    registry = load_json(DOMAIN_REGISTRY, "domain registry")
    registry_entries = array_at(registry.get("domains"), "domain registry domains")
    delegated = {
        entry["domain"]
        for entry in registry_entries
        if object_at(entry, "domain registry entry").get(
            "passwordResetDelegatedToKeycloak"
        )
    }
    if delegated != EXPECTED_DELEGATED_DOMAINS:
        fail(
            "password-reset applications do not match the fifteen-domain "
            "identity registry"
        )

    by_domain = {entry["domain"]: entry for entry in registry_entries}
    booked = object_at(by_domain["booked4seasons.com"], "booked4seasons.com")
    if (
        booked.get("state") != "declared-blocked-dns-unconfirmed"
        or booked.get("postalDnsState")
        != "not-confirmed-no-completed-postal-dns-check"
        or booked.get("enabled") is not False
    ):
        fail("booked4seasons.com must remain blocked until Postal DNS is confirmed")

    evidence = object_at(registry.get("postalDnsEvidence"), "postalDnsEvidence")
    if evidence.get("confirmedOkDomains") != 14:
        fail("expected fourteen operator-reported Postal DNS OK domains")
    if evidence.get("runtimeReverificationRequired") is not True:
        fail("Postal DNS evidence must require runtime reverification")

    serialized = CONTRACT.read_text(encoding="utf-8").lower()
    retired_issuer = "auth.codestra" + ".agency/realms/codestra"
    prohibited_secret_literals = (
        "begin openssh private key",
        "client_secret=",
        "smtp_password=",
        '"password":',
        retired_issuer,
    )
    if any(marker in serialized for marker in prohibited_secret_literals):
        fail("contract contains a prohibited secret-bearing or retired-issuer literal")


def main() -> int:
    try:
        validate()
    except ContractError as exc:
        print(f"PASSWORD_RESET_CONTRACT_ERROR={exc}", file=sys.stderr)
        return 1
    print("PASSWORD_RESET_CONTRACT=PASS")
    print("KEYCLOAK_PASSWORD_AUTHORITY=PASS")
    print("KLYROW_SECURITY_SMTP_CONTRACT=PASS")
    print("HUMAN_PASSWORD_RESET_APPLICATIONS=13")
    print("POSTAL_DNS_REPORTED_OK_DOMAINS=14")
    print("BOOKED4SEASONS_DNS_BLOCK=PASS")
    print("MACHINE_RESET_TOKEN_PROHIBITION=PASS")
    print("BEYVRA_TRADING_PASSWORD_AUTHORITY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
