#!/usr/bin/env python3
"""Fail-closed validation for Codestra machine identities and service grants."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"
CONTRACTS = CONFIG / "contracts"
ISSUER = "https://auth.codestra.co/realms/codestra"
MACHINE_IDS = [
    "kong-gateway", "middleware-api", "middleware-worker", "codestra-ai",
    "codestra-communication", "codestra-marketing", "codestra-social",
    "sdk-intake", "alertmanager", "ai-provider-adapter",
    "marketing-provider-adapter", "odoo-integration", "n8n-automation",
    "vicidial-adapter", "telnexa-gateway", "klyrow-gateway",
    "kyqra-gateway", "postly-adapter", "provisioning-service",
    "monitoring-readonly",
]
EXACT = {
    ("sdk-intake", "middleware-api"): {"leads.write", "surveys.write"},
    ("alertmanager", "middleware-api"): {"alerts.write"},
    ("monitoring-readonly", "middleware-api"): {"health.read", "metrics.read"},
}
PROVIDERS = {
    "telnexa-gateway", "klyrow-gateway", "postly-adapter",
    "ai-provider-adapter", "marketing-provider-adapter",
}
WEBHOOK_PRODUCERS = {
    "odoo-integration", "n8n-automation", "vicidial-adapter",
    "telnexa-gateway", "klyrow-gateway", "kyqra-gateway", "postly-adapter",
}
SCOPE = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")
SECRET = re.compile(
    r"(?:secret|password|private[_-]?key|access[_-]?token|refresh[_-]?token|credential)",
    re.I,
)


class ContractError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ContractError(message)


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path}: root must be an object")
    return value


def no_secrets(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            here = (*path, str(key))
            if SECRET.search(str(key)) and child not in ("", None, False, [], {}):
                fail(f"committed secret-bearing field: {'.'.join(here)}")
            no_secrets(child, here)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            no_secrets(child, (*path, str(index)))


def machine_ok(machine: dict[str, Any]) -> None:
    if machine.get("issuer") != ISSUER:
        fail("machine issuer drift")
    if machine.get("grantType") != "client_credentials":
        fail("machine grant type drift")
    if machine.get("secretStorage") != "external-secret-store-only":
        fail("machine secret-storage drift")
    ttl = machine.get("maximumAccessTokenLifetimeSeconds")
    if not isinstance(ttl, int) or not 1 <= ttl <= 300:
        fail("machine token TTL must be 1..300")
    clients = machine.get("clients")
    if not isinstance(clients, list):
        fail("machine clients missing")
    ids = [item.get("clientId") for item in clients if isinstance(item, dict)]
    if ids != MACHINE_IDS or len(ids) != len(set(ids)):
        fail(f"machine membership/order drift: {ids}")
    for item in clients:
        cid = item["clientId"]
        if item.get("clientType") != "confidential":
            fail(f"{cid}: not confidential")
        if item.get("serviceAccountsEnabled") is not True:
            fail(f"{cid}: service account disabled")
        for field in ("standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled"):
            if item.get(field) is not False:
                fail(f"{cid}: prohibited flow enabled")
        if item.get("audience") != cid or item.get("scopes") != [f"{cid}.access"]:
            fail(f"{cid}: registry audience/scope drift")


def access_ok(access: dict[str, Any]) -> dict[tuple[str, str], set[str]]:
    if access.get("schemaVersion") != 1 or access.get("issuer") != ISSUER:
        fail("access issuer/schema drift")
    policy = access.get("tokenPolicy")
    if not isinstance(policy, dict):
        fail("token policy missing")
    if policy.get("grantType") != "client_credentials":
        fail("access grant type drift")
    if policy.get("refreshTokensAllowed") is not False or policy.get("fullScopeAllowed") is not False:
        fail("refresh/full scope prohibited")
    ttl = policy.get("maximumAccessTokenLifetimeSeconds")
    if not isinstance(ttl, int) or not 1 <= ttl <= 300:
        fail("access token TTL must be 1..300")
    if policy.get("secretStorage") != "external-secret-store-only":
        fail("access secret-storage drift")

    services = access.get("services")
    if not isinstance(services, list):
        fail("services missing")
    ids = [item.get("clientId") for item in services if isinstance(item, dict)]
    if ids != MACHINE_IDS:
        fail(f"service membership/order drift: {ids}")
    by_id = {item["clientId"]: item for item in services}
    for cid, item in by_id.items():
        if item.get("audience") != cid or not isinstance(item.get("resourceServer"), bool):
            fail(f"{cid}: invalid service shape")
        if item["resourceServer"] and not str(item.get("baseUrlEnvironment", "")).endswith("_BASE_URL"):
            fail(f"{cid}: resource server base URL variable missing")
        if not item["resourceServer"] and "baseUrlEnvironment" in item:
            fail(f"{cid}: non-resource service has base URL")

    grants: dict[tuple[str, str], set[str]] = {}
    for raw in access.get("grants", []):
        if set(raw) != {"callerClientId", "targetClientId", "audience", "scopes"}:
            fail("grant keys drift")
        caller, target = raw["callerClientId"], raw["targetClientId"]
        if caller not in by_id or target not in by_id or caller == target:
            fail("grant identity invalid")
        if raw["audience"] != target or not by_id[target]["resourceServer"]:
            fail(f"{caller}->{target}: audience/target invalid")
        scopes = raw["scopes"]
        if (
            not isinstance(scopes, list) or not scopes
            or scopes != sorted(scopes) or len(scopes) != len(set(scopes))
            or not all(isinstance(scope, str) and SCOPE.fullmatch(scope) for scope in scopes)
            or "*" in scopes
        ):
            fail(f"{caller}->{target}: scope set invalid")
        key = (caller, target)
        if key in grants:
            fail(f"duplicate grant: {key}")
        grants[key] = set(scopes)

    for key, scopes in EXACT.items():
        if grants.get(key) != scopes:
            fail(f"exact grant drift: {key}")
    if {k: v for k, v in grants.items() if k[0] == "sdk-intake"} != {
        ("sdk-intake", "middleware-api"): {"leads.write", "surveys.write"}
    }:
        fail("sdk-intake authority expansion")
    if {k: v for k, v in grants.items() if k[0] == "alertmanager"} != {
        ("alertmanager", "middleware-api"): {"alerts.write"}
    }:
        fail("alertmanager must remain write-only")
    for caller, target in grants:
        if target in PROVIDERS and caller != "middleware-worker":
            fail(f"provider bypass: {caller}->{target}")
    for target in access.get("prohibitedDirectTargets", {}).get("n8n-automation", []):
        if ("n8n-automation", target) in grants:
            fail(f"n8n provider bypass: {target}")
    return grants


def client_ok(cid: str, document: dict[str, Any], scopes: set[str] | None = None) -> None:
    if document.get("clientId") != cid or document.get("protocol") != "openid-connect":
        fail(f"{cid}: client identity/protocol drift")
    if document.get("publicClient") is not False or document.get("serviceAccountsEnabled") is not True:
        fail(f"{cid}: machine client shape drift")
    if document.get("fullScopeAllowed") is not False:
        fail(f"{cid}: full scope enabled")
    for field in (
        "standardFlowEnabled", "implicitFlowEnabled",
        "directAccessGrantsEnabled", "authorizationServicesEnabled",
    ):
        if document.get(field) is not False:
            fail(f"{cid}: prohibited flow/service enabled")
    if document.get("redirectUris") != [] or document.get("webOrigins") != []:
        fail(f"{cid}: browser redirect/origin prohibited")
    attrs = document.get("attributes", {})
    try:
        ttl = int(attrs.get("access.token.lifespan", "0"))
    except (TypeError, ValueError):
        fail(f"{cid}: invalid token TTL")
    if not 1 <= ttl <= 300:
        fail(f"{cid}: token TTL above 300")
    if attrs.get("oauth2.device.authorization.grant.enabled") != "false":
        fail(f"{cid}: device flow enabled")
    if attrs.get("oidc.ciba.grant.enabled" != "false":
        fail(f"{cid}: CIBA enabled")
    no_secrets(document)

    serialized = json.dumps(document, sort_keys=True)
    if re.search(r'"tenant[_-]?id"\s*:', serialized, re.I):
        fail(f"{cid}: static tenant mapper prohibited")
    mappers = document.get("protocolMappers", [])
    aud = [m for m in mappers if m.get("protocolMapper") == "oidc-audience-mapper"]
    claims = [m for m in mappers if m.get("name") == "reviewed-service-scopes"]
    if len(aud) != 1 or aud[0].get("config", {}).get("included.custom.audience") != "middleware-api":
        fail(f"{cid}: middleware audience mapper drift")
    if len(claims) != 1:
        fail(f"{cid}: reviewed scope mapper missing")
    actual = set(str(claims[0].get("config", {}).get("claim.value", "")).split())
    if scopes is not None and actual != scopes:
        fail(f"{cid}: configured scope drift: {actual}")


# Public validation helpers used by focused negative-contract tests.
validate_machine_contract = machine_ok
validate_access_matrix = access_ok
validate_client_document = client_ok


def webhooks_ok(webhooks: dict[str, Any], grants: dict[tuple[str, str], set[str]]) -> None:
    if webhooks.get("schemaVersion") != 1 or webhooks.get("issuer") != ISSUER:
        fail("webhook issuer/schema drift")
    if webhooks.get("consumerClientId") != "middleware-api":
        fail("webhook consumer drift")
    producers, ids, paths, events = set(), set(), set(), set()
    for hook in webhooks.get("webhooks", []):
        hid, producer, path = hook.get("id"), hook.get("producerClientId"), hook.get("path")
        if not hid or hid in ids or not path or path in paths or not path.startswith("/api/v1/"):
            fail("webhook id/path invalid")
        if hook.get("consumerClientId") != "middleware-api" or hook.get("audience") != "middleware-api":
            fail(f"{hid}: webhook consumer/audience drift")
        if hook.get("requiredScope") not in grants.get((producer, "middleware-api"), set()):
            fail(f"{hid}: webhook scope not granted")
        if hook.get("delivery") != "at_least_once":
            fail(f"{hid}: webhook delivery drift")
        for event in hook.get("eventTypes", []):
            if event in events or not re.fullmatch(r"[a-z][a-z0-9]*(?:\.[a-z0-9]+){2,}", event):
                fail(f"{hid}: webhook event invalid")
            events.add(event)
        ids.add(hid); paths.add(path); producers.add(producer)
    if producers != WEBHOOK_PRODUCERS:
        fail("webhook producer coverage drift")


def validate(
    machine: dict[str, Any] | None = None,
    access: dict[str, Any] | None = None,
    webhooks: dict[str, Any] | None = None,
) -> None:
    machine = machine or load(CONTRACTS / "machine-clients.json")
    access = access or load(CONTRACTS / "service-access-matrix.json")
    webhooks = webhooks or load(CONTRACTS / "webhook-contracts.json")
    machine_ok(machine)
    grants = access_ok(access)
    webhooks_ok(webhooks, grants)

    managed = load(CONFIG / "policy/managed-clients.json").get("clients")
    creatable = load(CONFIG / "policy/creatable-clients.json").get("clients")
    if not isinstance(managed, list) or managed != creatable or len(managed) != len(set(managed)):
        fail("managed/creatable policy drift")
    clients = {
        load(path)["clientId"]: load(path)
        for path in sorted((CONFIG / "clients").glob("*.json"))
    }
    if set(clients) != set(managed):
        fail("configured clients do not match policy")
    for cid, scopes in {
        "sdk-intake": {"leads.write", "surveys.write"},
        "alertmanager": {"alerts.write"},
    }.items():
        client_ok(cid, clients[cid], scopes)
        allow = load(CONFIG / "export-allowlists" / f"{cid}.json")
        if set(allow.get("topLevelFields", [])) != set(clients[cid]):
            fail(f"{cid}: top-level allowlist drift")
        if set(allow.get("attributeFields", [])) != set(clients[cid]["attributes"]):
            fail(f"{cid}: attribute allowlist drift")
    for cid in ("kong-gateway", "n8n-automation"):
        if re.search(r'"tenant[_-]?id"\s*:', json.dumps(clients[cid], sort_keys=True), re.I):
            fail(f"{cid}: static tenant mapper prohibited")

    print(f"SERVICE_CLIENTS={len(access['services'])}")
    print(f"SERVICE_GRANTS={len(grants)}")
    print(f"WEBHOOK_CONTRACTS={len(webhooks['webhooks'])}")
    print("SDK_INTAKE_SCOPES=leads.write,surveys.write")
    print("ALERTMANAGER_SCOPES=alerts.write")
    print("STATIC_SHARED_TENANT_MAPPERS=0")
    print("SERVICE_ACCESS_POLICY=PASS")
    print("WEBHOOK_CONTRACT_POLICY=PASS")
    print("SERVICE_INTEGRATION_VALIDATION=PASS")


def main() -> int:
    try:
        validate()
    except ContractError as exc:
        print(f"SERVICE_INTEGRATION_ERROR={exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
