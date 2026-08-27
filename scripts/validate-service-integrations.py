#!/usr/bin/env python3
"""Validate Codestra service identities, audiences, scopes, APIs, and webhooks."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = ROOT / "config" / "contracts"
CANONICAL_ISSUER = "https://auth.codestra.co/realms/codestra"
EXPECTED_CLIENTS = [
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
]
EXPECTED_WEBHOOK_PRODUCERS = {
    "odoo-integration",
    "n8n-automation",
    "vicidial-adapter",
    "telnexa-gateway",
    "klyrow-gateway",
    "kyqra-gateway",
    "postly-adapter",
}
REQUIRED_HEADERS = {
    "Authorization",
    "Content-Type",
    "Idempotency-Key",
    "X-Codestra-Event-Id",
    "X-Codestra-Event-Type",
    "X-Codestra-Source",
    "X-Codestra-Tenant-Id",
    "X-Codestra-Timestamp",
    "X-Codestra-Signature",
    "X-Correlation-Id",
}
SCOPE = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")
EVENT_TYPE = re.compile(r"^[a-z][a-z0-9]*(?:\.[a-z0-9]+){2,}$")
ENVIRONMENT = re.compile(r"^[A-Z][A-Z0-9_]*_BASE_URL$")


class ContractError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ContractError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{path}: unable to load JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{path}: document root must be an object")
    return value


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        fail(f"{label}: expected keys {sorted(expected)}, found {sorted(actual)}")


def validate() -> None:
    machine = load_json(CONTRACT_ROOT / "machine-clients.json")
    access = load_json(CONTRACT_ROOT / "service-access-matrix.json")
    webhooks = load_json(CONTRACT_ROOT / "webhook-contracts.json")

    machine_clients = machine.get("clients")
    if not isinstance(machine_clients, list):
        fail("machine-clients.json: clients must be an array")
    machine_ids = [entry.get("clientId") for entry in machine_clients if isinstance(entry, dict)]
    if machine_ids != EXPECTED_CLIENTS:
        fail(f"machine client ordering or membership changed: {machine_ids}")

    if access.get("schemaVersion") != 1 or access.get("issuer") != CANONICAL_ISSUER:
        fail("service access matrix issuer or schema version is invalid")
    if access.get("tokenEndpoint") != f"{CANONICAL_ISSUER}/protocol/openid-connect/token":
        fail("service access matrix token endpoint is invalid")
    if access.get("jwksUri") != f"{CANONICAL_ISSUER}/protocol/openid-connect/certs":
        fail("service access matrix JWKS URI is invalid")

    policy = access.get("tokenPolicy")
    if not isinstance(policy, dict):
        fail("service access matrix tokenPolicy must be an object")
    if policy.get("grantType") != "client_credentials":
        fail("machine identities must use client_credentials")
    if not isinstance(policy.get("maximumAccessTokenLifetimeSeconds"), int):
        fail("maximum access-token lifetime must be an integer")
    if not 1 <= policy["maximumAccessTokenLifetimeSeconds"] <= 300:
        fail("machine access-token lifetime must be between 1 and 300 seconds")
    if policy.get("refreshTokensAllowed") is not False:
        fail("machine refresh tokens must be disabled")
    if policy.get("fullScopeAllowed") is not False:
        fail("full-scope mode must be disabled")
    if policy.get("secretStorage") != "external-secret-store-only":
        fail("machine credentials must remain outside Git")
    required_claims = policy.get("requiredClaims")
    if required_claims != ["iss", "sub", "aud", "azp", "iat", "exp", "jti", "scope"]:
        fail("required machine-token claims are invalid")

    services = access.get("services")
    if not isinstance(services, list):
        fail("service access matrix services must be an array")
    service_ids: list[str] = []
    service_by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(services):
        if not isinstance(raw, dict):
            fail(f"services[{index}] must be an object")
        client_id = raw.get("clientId")
        if not isinstance(client_id, str) or client_id not in EXPECTED_CLIENTS:
            fail(f"services[{index}] has an unknown clientId")
        if client_id in service_by_id:
            fail(f"duplicate service entry: {client_id}")
        if raw.get("audience") != client_id:
            fail(f"{client_id}: service audience must equal clientId")
        if not isinstance(raw.get("resourceServer"), bool):
            fail(f"{client_id}: resourceServer must be boolean")
        if raw["resourceServer"]:
            base_env = raw.get("baseUrlEnvironment")
            if not isinstance(base_env, str) or not ENVIRONMENT.fullmatch(base_env):
                fail(f"{client_id}: resource server requires a *_BASE_URL environment variable")
        elif "baseUrlEnvironment" in raw:
            fail(f"{client_id}: non-resource workload must not declare a base URL")
        service_ids.append(client_id)
        service_by_id[client_id] = raw
    if service_ids != EXPECTED_CLIENTS:
        fail("service access matrix must list every machine client in canonical order")

    grants = access.get("grants")
    if not isinstance(grants, list) or not grants:
        fail("service access matrix grants must be a non-empty array")
    grant_index: dict[tuple[str, str], set[str]] = {}
    for index, raw in enumerate(grants):
        if not isinstance(raw, dict):
            fail(f"grants[{index}] must be an object")
        require_exact_keys(
            raw,
            {"callerClientId", "targetClientId", "audience", "scopes"},
            f"grants[{index}]",
        )
        caller = raw["callerClientId"]
        target = raw["targetClientId"]
        if caller not in service_by_id or target not in service_by_id:
            fail(f"grants[{index}] references an unknown service")
        if caller == target:
            fail(f"grants[{index}] must not grant a service to itself")
        if raw["audience"] != target:
            fail(f"grants[{index}] audience must equal targetClientId")
        if not service_by_id[target]["resourceServer"]:
            fail(f"grants[{index}] target {target} is not a resource server")
        scopes = raw["scopes"]
        if (
            not isinstance(scopes, list)
            or not scopes
            or not all(isinstance(scope, str) and SCOPE.fullmatch(scope) for scope in scopes)
        ):
            fail(f"grants[{index}] has invalid scopes")
        if len(scopes) != len(set(scopes)) or scopes != sorted(scopes):
            fail(f"grants[{index}] scopes must be unique and sorted")
        key = (caller, target)
        if key in grant_index:
            fail(f"duplicate caller-target grant: {caller}->{target}")
        grant_index[key] = set(scopes)

    required_edges = {
        ("middleware-worker", "middleware-api"),
        ("moneybee-backend", "middleware-api"),
        ("odoo-integration", "middleware-api"),
        ("middleware-api", "odoo-integration"),
        ("n8n-automation", "middleware-api"),
        ("vicidial-adapter", "middleware-api"),
        ("middleware-api", "vicidial-adapter"),
        ("middleware-api", "telnexa-gateway"),
        ("telnexa-gateway", "middleware-api"),
        ("middleware-api", "klyrow-gateway"),
        ("klyrow-gateway", "middleware-api"),
        ("middleware-api", "kyqra-gateway"),
        ("kyqra-gateway", "middleware-api"),
        ("middleware-api", "postly-adapter"),
        ("postly-adapter", "middleware-api"),
        ("provisioning-service", "middleware-api"),
    }
    missing_edges = required_edges - set(grant_index)
    if missing_edges:
        fail(f"required service grants are missing: {sorted(missing_edges)}")

    prohibited = access.get("prohibitedDirectTargets")
    if prohibited != {
        "n8n-automation": [
            "odoo-integration",
            "vicidial-adapter",
            "telnexa-gateway",
            "klyrow-gateway",
            "kyqra-gateway",
            "postly-adapter",
        ]
    }:
        fail("n8n direct-provider prohibition is missing or changed")
    for target in prohibited["n8n-automation"]:
        if ("n8n-automation", target) in grant_index:
            fail(f"n8n must not receive a direct grant to {target}")

    boundaries = access.get("administrativeBoundaries", {})
    provisioning_boundary = boundaries.get("provisioning-service")
    if not isinstance(provisioning_boundary, dict):
        fail("provisioning-service administrative boundary is missing")
    if provisioning_boundary.get("keycloakAdminApiAccess") is not False:
        fail("provisioning-service must not receive Keycloak Admin API access")
    if provisioning_boundary.get("prohibitedRealmManagementRoles") != [
        "realm-admin",
        "manage-realm",
        "manage-clients",
    ]:
        fail("provisioning-service realm-management prohibition is invalid")

    moneybee_boundary = boundaries.get("moneybee-backend")
    if not isinstance(moneybee_boundary, dict):
        fail("moneybee-backend administrative boundary is missing")
    if moneybee_boundary.get("keycloakAdminApiAccess") is not False:
        fail("moneybee-backend must not receive Keycloak Admin API access")
    if moneybee_boundary.get("allowedTarget") != "middleware-api":
        fail("moneybee-backend may target only middleware-api")
    if moneybee_boundary.get("allowedScopes") != ["moneybee.events.publish"]:
        fail("moneybee-backend scope boundary is invalid")
    if moneybee_boundary.get("prohibitedRealmManagementRoles") != [
        "realm-admin",
        "manage-realm",
        "manage-clients",
    ]:
        fail("moneybee-backend realm-management prohibition is invalid")
    if grant_index.get(("moneybee-backend", "middleware-api")) != {
        "moneybee.events.publish"
    }:
        fail("moneybee-backend must receive only moneybee.events.publish to middleware-api")

    for (caller, target), scopes in grant_index.items():
        if caller == "monitoring-readonly":
            if scopes != {"health.read", "metrics.read"}:
                fail("monitoring-readonly may receive only health.read and metrics.read")
        if caller == "provisioning-service" and any(
            word in scope for scope in scopes for word in ("admin", "realm", "client.manage")
        ):
            fail("provisioning-service has a prohibited administrative scope")
        if caller == "moneybee-backend" and (
            target != "middleware-api" or scopes != {"moneybee.events.publish"}
        ):
            fail("moneybee-backend has a grant outside its event-publisher boundary")
        if "*" in scopes:
            fail("wildcard scopes are prohibited")

    if webhooks.get("schemaVersion") != 1 or webhooks.get("issuer") != CANONICAL_ISSUER:
        fail("webhook contract issuer or schema version is invalid")
    if webhooks.get("consumerClientId") != "middleware-api":
        fail("middleware-api must be the canonical webhook consumer")
    if webhooks.get("consumerBaseUrlEnvironment") != "MIDDLEWARE_API_BASE_URL":
        fail("webhook consumer base URL must be configured through MIDDLEWARE_API_BASE_URL")
    if webhooks.get("eventEnvelopeContract") != "codestra.event-envelope.v1":
        fail("webhook event-envelope contract is invalid")

    security = webhooks.get("security")
    if not isinstance(security, dict):
        fail("webhook security policy is missing")
    if security.get("authorization") != "oidc_bearer":
        fail("webhooks must require an OIDC bearer token")
    if security.get("signatureAlgorithm") != "hmac-sha256":
        fail("webhooks must use HMAC-SHA256")
    if security.get("signatureVersion") != "v1":
        fail("webhook signature version must be v1")
    if security.get("maximumClockSkewSeconds") != 300:
        fail("webhook clock skew must be exactly 300 seconds")
    if not isinstance(security.get("replayRetentionSeconds"), int) or security[
        "replayRetentionSeconds"
    ] < 86400:
        fail("webhook replay retention must be at least 24 hours")
    if set(security.get("requiredHeaders", [])) != REQUIRED_HEADERS:
        fail("webhook required header set is invalid")
    if security.get("contentType") != "application/json":
        fail("webhook content type must be application/json")
    if security.get("signatureHeaderFormat") != "sha256=<lowercase-hex>":
        fail("webhook signature header format is invalid")
    if security.get("idempotencyKeySource") != "X-Codestra-Event-Id":
        fail("webhook idempotency must derive from the event ID")
    if security.get("canonicalSignatureFields") != [
        "version",
        "method",
        "path",
        "timestamp",
        "eventId",
        "sourceClientId",
        "bodySha256",
    ]:
        fail("webhook canonical signature fields are invalid")

    hooks = webhooks.get("webhooks")
    if not isinstance(hooks, list) or not hooks:
        fail("webhook contract must contain webhook definitions")
    hook_ids: set[str] = set()
    hook_paths: set[str] = set()
    event_types: set[str] = set()
    producers: set[str] = set()
    for index, raw in enumerate(hooks):
        if not isinstance(raw, dict):
            fail(f"webhooks[{index}] must be an object")
        require_exact_keys(
            raw,
            {
                "id",
                "producerClientId",
                "consumerClientId",
                "audience",
                "requiredScope",
                "path",
                "eventTypes",
                "delivery",
            },
            f"webhooks[{index}]",
        )
        hook_id = raw["id"]
        if not isinstance(hook_id, str) or hook_id in hook_ids:
            fail(f"webhooks[{index}] has a duplicate or invalid id")
        hook_ids.add(hook_id)
        producer = raw["producerClientId"]
        consumer = raw["consumerClientId"]
        if producer not in service_by_id or consumer != "middleware-api":
            fail(f"webhooks[{index}] references an invalid producer or consumer")
        if raw["audience"] != consumer:
            fail(f"webhooks[{index}] audience must equal the consumer")
        required_scope = raw["requiredScope"]
        if required_scope not in grant_index.get((producer, consumer), set()):
            fail(f"webhooks[{index}] scope is not granted to its producer")
        path = raw["path"]
        if (
            not isinstance(path, str)
            or not path.startswith("/api/v1/")
            or "://" in path
            or path in hook_paths
        ):
            fail(f"webhooks[{index}] path must be unique, relative, and under /api/v1/")
        hook_paths.add(path)
        if raw["delivery"] != "at_least_once":
            fail(f"webhooks[{index}] must use at_least_once delivery")
        hook_event_types = raw["eventTypes"]
        if not isinstance(hook_event_types, list) or not hook_event_types:
            fail(f"webhooks[{index}] eventTypes must be a non-empty array")
        for event_type in hook_event_types:
            if not isinstance(event_type, str) or not EVENT_TYPE.fullmatch(event_type):
                fail(f"webhooks[{index}] contains an invalid event type")
            if event_type in event_types:
                fail(f"duplicate webhook event type: {event_type}")
            event_types.add(event_type)
        producers.add(producer)

    if producers != EXPECTED_WEBHOOK_PRODUCERS:
        fail(
            "every provider/adapter must publish at least one webhook contract: "
            f"expected {sorted(EXPECTED_WEBHOOK_PRODUCERS)}, found {sorted(producers)}"
        )

    print(f"SERVICE_CLIENTS={len(service_ids)}")
    print(f"SERVICE_GRANTS={len(grant_index)}")
    print(f"WEBHOOK_CONTRACTS={len(hook_ids)}")
    print(f"WEBHOOK_EVENT_TYPES={len(event_types)}")
    print("SERVICE_ACCESS_POLICY=PASS")
    print("WEBHOOK_CONTRACT_POLICY=PASS")
    print("SERVICE_INTEGRATION_VALIDATION=PASS")


if __name__ == "__main__":
    try:
        validate()
    except ContractError as exc:
        print(f"SERVICE_INTEGRATION_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
