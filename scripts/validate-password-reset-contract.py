#!/usr/bin/env python3
"""Validate the Codestra Keycloak password-reset and Klyrow SMTP contract."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import re
import sys
from pathlib import Path
from typing import Any

import yaml

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


def validate_private_smtp_transport(
    smtp: dict[str, Any], realm: dict[str, Any], compose: dict[str, Any]
) -> None:
    """Bind the certificate DNS identity to the reviewed private relay."""
    if smtp.get("defaultHost") != "mail.klyrow.com":
        fail("SMTP must use the verified mail.klyrow.com certificate identity")
    if smtp.get("privateAddress") != "10.40.0.4" or smtp.get("defaultPort") != 587:
        fail("approved private Klyrow SMTP address or port changed")
    server = object_at(realm.get("smtpServer"), "realm smtpServer")
    if server.get("host") != smtp["defaultHost"] or server.get("port") != "587":
        fail("realm SMTP endpoint must match the private transport contract")
    if any(server.get(k) != v for k, v in
           {"auth": "true", "starttls": "true", "ssl": "false"}.items()):
        fail("realm SMTP must require authentication and STARTTLS")
    service = object_at(
        object_at(compose.get("services"), "Compose services").get("keycloak"),
        "Compose Keycloak service",
    )
    hosts = service.get("extra_hosts", {})
    if smtp_host_addresses(hosts, smtp["defaultHost"]) != {smtp["privateAddress"]}:
        fail("Keycloak must pin mail.klyrow.com to the private SMTP address")
    if service.get("network_mode") == "host":
        fail("Keycloak must retain its isolated container network")


def smtp_host_addresses(hosts: Any, hostname: str) -> set[str]:
    """Normalize both Compose and Docker inspect extra_hosts representations."""
    if isinstance(hosts, dict):
        value = hosts.get(hostname)
        return {value} if isinstance(value, str) else set()
    if isinstance(hosts, list):
        addresses = set()
        for entry in hosts:
            if not isinstance(entry, str):
                fail("SMTP host mapping entries must be strings")
            match = re.fullmatch(r"([^:=]+)[:=](.+)", entry)
            if not match:
                fail("SMTP host mapping entry is invalid")
            if match[1] == hostname:
                addresses.add(match[2])
        return addresses
    fail("SMTP host mapping must be an object or array")


def validate_email_environment_example(smtp: dict[str, Any], text: str) -> None:
    entries = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in entries:
            fail("SMTP environment example has invalid or duplicate variables")
        entries[key] = value
    if entries.get(smtp["hostEnvironment"]) != smtp["defaultHost"]:
        fail("SMTP environment example must use the certificate DNS identity")
    if entries.get(smtp["portEnvironment"]) != str(smtp["defaultPort"]):
        fail("SMTP environment example must retain the private relay port")


def runtime_command(command: list[str], label: str) -> str:
    # Compose output and Docker inspection can contain credentials. Capture them
    # in memory; never echo command output or subprocess exception details.
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        fail(f"{label} could not complete")
    if result.returncode:
        fail(f"{label} failed")
    return result.stdout


def runtime_json(command: list[str], label: str) -> Any:
    try:
        return json.loads(runtime_command(command, label))
    except json.JSONDecodeError:
        fail(f"{label} did not return valid JSON")


def validate_runtime_private_smtp_transport() -> None:
    """Require the effective Compose service and its running container route."""
    smtp = load_json(CONTRACT, "contract")["smtp"]
    runtime_paths = {}
    for name in ("RUNTIME_REPO_DIR", "RUNTIME_COMPOSE_FILE", "RUNTIME_ENV_FILE"):
        value = os.environ.get(name, "")
        path = Path(value)
        if not value or not path.is_absolute():
            fail(f"{name} must be an absolute runtime path")
        if not (path.is_dir() if name == "RUNTIME_REPO_DIR" else path.is_file()):
            fail(f"{name} is unavailable")
        runtime_paths[name] = str(path)
    service_name = os.environ.get("RUNTIME_KEYCLOAK_SERVICE", "") or "keycloak"
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", service_name):
        fail("RUNTIME_KEYCLOAK_SERVICE is invalid")
    compose_command = [
        "docker", "compose",
        "--project-directory", runtime_paths["RUNTIME_REPO_DIR"],
        "--env-file", runtime_paths["RUNTIME_ENV_FILE"],
        "-f", runtime_paths["RUNTIME_COMPOSE_FILE"],
    ]
    compose = object_at(
        runtime_json(compose_command + ["config", "--format", "json"], "Runtime Compose rendering"),
        "runtime Compose",
    )
    project = compose.get("name")
    if not isinstance(project, str) or not project:
        fail("Runtime Compose project identity is missing")
    service = object_at(
        object_at(compose.get("services"), "runtime services").get(service_name),
        "runtime Keycloak service",
    )
    if service.get("network_mode") == "host":
        fail("Runtime Keycloak must retain its isolated container network")
    if smtp_host_addresses(service.get("extra_hosts", {}), smtp["defaultHost"]) != {smtp["privateAddress"]}:
        fail("Rendered runtime Compose is missing the private SMTP mapping")

    container_ids = runtime_command(
        compose_command + ["ps", "--all", "--quiet", service_name], "Runtime container lookup",
    ).split()
    if len(container_ids) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", container_ids[0]):
        fail("Expected exactly one runtime Keycloak container")
    container_id = container_ids[0]
    containers = runtime_json(["docker", "inspect", container_id], "Runtime container inspection")
    if not isinstance(containers, list) or len(containers) != 1:
        fail("Runtime container inspection is ambiguous")
    container = object_at(containers[0], "runtime container")
    if object_at(container.get("State"), "runtime state").get("Running") is not True:
        fail("Runtime Keycloak container is not running")
    labels = object_at(object_at(container.get("Config"), "container config").get("Labels"), "container labels")
    if labels.get("com.docker.compose.project") != project or labels.get("com.docker.compose.service") != service_name:
        fail("Runtime Keycloak container does not match the rendered Compose project/service")
    host_config = object_at(container.get("HostConfig"), "container host config")
    if host_config.get("NetworkMode") == "host":
        fail("Running Keycloak must retain its isolated container network")
    if smtp_host_addresses(host_config.get("ExtraHosts", []), smtp["defaultHost"]) != {smtp["privateAddress"]}:
        fail("Running Keycloak has not activated the private SMTP mapping")
    resolution = runtime_command(
        ["docker", "exec", container_id, "getent", "ahosts", smtp["defaultHost"]],
        "Runtime SMTP hostname resolution",
    )
    addresses = {line.split()[0] for line in resolution.splitlines() if line.split()}
    if addresses != {smtp["privateAddress"]}:
        fail("Running Keycloak SMTP resolution is not exclusively the private relay")


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
    validate_private_smtp_transport(
        smtp,
        load_json(ROOT / "config/realms/codestra.json", "realm"),
        yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8")),
    )
    validate_email_environment_example(
        smtp, (ROOT / "deploy/keycloak-email.env.example").read_text(encoding="utf-8"),
    )
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--runtime', action='store_true',
        help='also verify rendered runtime Compose and running container SMTP resolution',
    )
    args = parser.parse_args()
    try:
        validate()
        if args.runtime:
            validate_runtime_private_smtp_transport()
    except ContractError as exc:
        print(f"PASSWORD_RESET_CONTRACT_ERROR={exc}", file=sys.stderr)
        return 1
    if args.runtime:
        print("KLYROW_RUNTIME_PRIVATE_SMTP_ROUTE=PASS")
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
