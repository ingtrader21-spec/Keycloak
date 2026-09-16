#!/usr/bin/env python3
"""Validate and deterministically render the TEST_SYN edge-certification desired state.

The desired state under ``config/desired-state/edge-integration-certification/``
declares the three shared-edge ingress scopes, five isolated staging service
identities, and the pinned Middleware edge-contract SHA-256 that Caddy, Kong,
Keycloak, and Middleware must all reference. It is repository-only: nothing
here reads runtime state, mints tokens, or authorizes a live apply.

The identities deliberately live outside ``config/clients/`` and the protected
managed/creatable policies. Repository CI fails if a certification identity or
an ingress scope leaks into those live-capable sets, or if any client anywhere
in the repository is granted ``odoo.campaign.control.write``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DESIRED_ROOT = ROOT / "config" / "desired-state" / "edge-integration-certification"
CONTRACT_PATH = DESIRED_ROOT / "contract.json"
STAGING_ENDPOINTS = ROOT / "config" / "endpoints" / "codestra-staging.json"
MANAGED_POLICY = ROOT / "config" / "policy" / "managed-clients.json"
CREATABLE_POLICY = ROOT / "config" / "policy" / "creatable-clients.json"
MACHINE_CONTRACT = ROOT / "config" / "contracts" / "machine-clients.json"
ACCESS_MATRIX = ROOT / "config" / "contracts" / "service-access-matrix.json"
REALM_PATH = ROOT / "config" / "realms" / "codestra.json"
LIVE_CLIENTS_DIR = ROOT / "config" / "clients"
LIVE_SCOPES_DIR = ROOT / "config" / "client-scopes"
OUTPUT_DIR = ROOT / "release" / "edge-integration-certification"
PLAN_PATH = OUTPUT_DIR / "keycloak-edge-certification-desired-state-plan.json"
CHECKSUM_PATH = OUTPUT_DIR / "keycloak-edge-certification-desired-state-plan.sha256"

ENVIRONMENT = "staging"
CAMPAIGN = "TEST_SYN"
INGRESS_SCOPES = ("n8n.results.submit", "n8n.results.read", "odoo.campaigns.read")
FORBIDDEN_SCOPES = ("odoo.campaign.control.write",)
OUTBOUND_SCOPE = "odoo.campaign.control.read"
CLASSIFICATIONS = frozenset({"shared_edge", "private_only", "denied"})
RETIRED_MARKERS = ("campaign-actions", "campaign-commands")
CANONICAL_ROUTES = (
    ("POST", "/api/v1/integrations/n8n/results", "n8n.results.submit"),
    ("GET", "/api/v1/integrations/n8n/results/{event_id}", "n8n.results.read"),
    ("GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}", "odoo.campaigns.read"),
    ("GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}/desired-state", "odoo.campaigns.read"),
)
# role -> (scopes, audience is the Middleware audience, tenant, business units, campaigns)
IDENTITY_ROLES: dict[str, dict[str, Any]] = {
    "n8n_submit": {"scopes": ["n8n.results.submit"], "middleware_audience": True, "tenant": "TEST_SYN_TENANT", "units": ["TEST_SYN"], "campaigns": ["TEST_SYN"]},
    "n8n_read": {"scopes": ["n8n.results.read"], "middleware_audience": True, "tenant": "TEST_SYN_TENANT", "units": ["TEST_SYN"], "campaigns": ["TEST_SYN"]},
    "odoo_reader": {"scopes": ["odoo.campaigns.read"], "middleware_audience": True, "tenant": "TEST_SYN_TENANT", "units": ["TEST_SYN"], "campaigns": ["TEST_SYN"]},
    "wrong_audience": {"scopes": [], "middleware_audience": False, "tenant": "TEST_SYN_TENANT", "units": ["TEST_SYN"], "campaigns": ["TEST_SYN"]},
    "wrong_tenant": {"scopes": ["n8n.results.read", "odoo.campaigns.read"], "middleware_audience": True, "tenant": "TEST_SYN_OTHER_TENANT", "units": ["TEST_SYN_OTHER"], "campaigns": ["TEST_SYN_OTHER"]},
}
CLIENT_ID_PATTERN = re.compile(r"^test-syn-[a-z0-9-]{3,40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SENSITIVE_KEY = re.compile(
    r"^(secret|clientsecret|client_secret|password|privatekey|private_key|"
    r"access_token|accesstoken|refresh_token|refreshtoken|credential|credentials)$",
    re.IGNORECASE,
)
MAPPER_CLAIMS = {
    "claim-environment": ("environment", "String"),
    "claim-tenant-id": ("tenant_id", "String"),
    "claim-business-units": ("business_units", "JSON"),
    "claim-campaigns": ("campaigns", "JSON"),
}


class DesiredStateError(ValueError):
    """The checked-in desired state violates the certification contract."""


def relative(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DesiredStateError(f"cannot parse {relative(path)}: {exc}") from exc
    if not isinstance(value, dict):
        raise DesiredStateError(f"{relative(path)} must contain a JSON object")
    return value


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def edge_contract_sha256(document: Any) -> str:
    """Middleware's hash rule for deploy/public-api-route-contract.json."""
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def assert_no_secret(value: Any, location: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE_KEY.fullmatch(str(key)) and child not in (None, "", [], {}):
                raise DesiredStateError(f"secret-bearing value at {location}.{key}")
            assert_no_secret(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_secret(child, f"{location}[{index}]")


# --- contract ------------------------------------------------------------------


def validate_contract(contract: dict[str, Any]) -> None:
    assert_no_secret(contract, "contract")
    staging = load_json(STAGING_ENDPOINTS)
    exact = {
        "schemaVersion": 1,
        "kind": "CodestraKeycloakEdgeIntegrationCertificationContract",
        "environment": ENVIRONMENT,
        "realm": staging["realm"],
        "issuer": staging["issuer"],
        "tokenEndpoint": staging["tokenEndpoint"],
        "jwksUri": staging["jwksUri"],
        "campaign": CAMPAIGN,
        "tenant": "TEST_SYN_TENANT",
        "businessUnit": CAMPAIGN,
        "ingressScopes": list(INGRESS_SCOPES),
        "forbiddenScopes": list(FORBIDDEN_SCOPES),
        "canonicalMiddlewareAudience": "middleware-api",
    }
    for field, required in exact.items():
        if contract.get(field) != required:
            raise DesiredStateError(f"contract: invalid {field}")
    audience = contract.get("audience")
    if not isinstance(audience, str) or not audience or " " in audience:
        raise DesiredStateError("contract: audience must be a single audience string")
    if audience != contract["canonicalMiddlewareAudience"] and not contract.get("audienceDivergence"):
        raise DesiredStateError("contract: audience divergence from middleware-api must be documented")
    outbound = contract.get("outboundScope") or {}
    if outbound.get("name") != OUTBOUND_SCOPE or outbound.get("direction") != "middleware_to_odoo":
        raise DesiredStateError("contract: outbound scope must remain the separate middleware_to_odoo direction")
    if OUTBOUND_SCOPE in contract["ingressScopes"] or set(FORBIDDEN_SCOPES) & set(contract["ingressScopes"]):
        raise DesiredStateError("contract: ingress scopes must not include outbound or forbidden scopes")

    edge = contract.get("edgeContract") or {}
    if edge.get("repository") != "appolon1908-hue/Middleware-" or edge.get("path") != "deploy/public-api-route-contract.json":
        raise DesiredStateError("contract: edgeContract must reference the Middleware public API route contract")
    if not isinstance(edge.get("sha256"), str) or not SHA256_PATTERN.fullmatch(edge["sha256"]):
        raise DesiredStateError("contract: edgeContract.sha256 must be a lowercase SHA-256 digest")

    routes = contract.get("routes")
    if not isinstance(routes, list):
        raise DesiredStateError("contract: routes must be a list")
    seen: set[tuple[str, str]] = set()
    for route in routes:
        if not isinstance(route, dict):
            raise DesiredStateError("contract: route rows must be objects")
        key = (str(route.get("method")), str(route.get("path")))
        if key in seen:
            raise DesiredStateError(f"contract: duplicate route {key}")
        seen.add(key)
        if route.get("classification") not in CLASSIFICATIONS:
            raise DesiredStateError(f"contract: route {key} lacks a shared_edge/private_only/denied classification")
        if any(marker in key[1] for marker in RETIRED_MARKERS):
            raise DesiredStateError(f"contract: retired surface listed as a route: {key}")
        if route.get("classification") == "shared_edge" and route.get("scope") not in INGRESS_SCOPES:
            raise DesiredStateError(f"contract: shared_edge route {key} must require an ingress scope")
    declared = {(r["method"], r["path"], r.get("scope")) for r in routes if r.get("classification") == "shared_edge"}
    if declared != set(CANONICAL_ROUTES):
        raise DesiredStateError("contract: shared_edge routes must be exactly the four canonical routes with their scopes")

    retired = contract.get("retiredPaths")
    if not isinstance(retired, list) or not retired:
        raise DesiredStateError("contract: retiredPaths must list the retired campaign surfaces")
    for entry in retired:
        if entry.get("classification") != "denied" or not any(m in str(entry.get("path")) for m in RETIRED_MARKERS):
            raise DesiredStateError("contract: every retired path must be a denied campaign-actions/campaign-commands surface")

    policy = contract.get("tokenPolicy") or {}
    if (
        policy.get("grantType") != "client_credentials"
        or policy.get("scopeParameterRequired") is not False
        or policy.get("maximumAccessTokenLifetimeSeconds") != 300
        or policy.get("refreshTokensAllowed") is not False
        or policy.get("fullScopeAllowed") is not False
        or policy.get("secretStorage") != "external-secret-store-only"
        or policy.get("environmentClaim") != ENVIRONMENT
    ):
        raise DesiredStateError("contract: tokenPolicy is not the reviewed machine-token policy")
    for claim in ("iss", "sub", "aud", "azp", "iat", "exp", "jti", "scope", "environment", "tenant_id", "business_units", "campaigns"):
        if claim not in (policy.get("requiredClaims") or []):
            raise DesiredStateError(f"contract: tokenPolicy.requiredClaims must include {claim}")

    boundary = contract.get("boundary") or {}
    for flag in (
        "productionActivationAuthorized",
        "managedClientPolicyMembership",
        "liveApplyFromRepositoryCi",
        "providerWritesEnabled",
        "odooWritesEnabled",
        "tokensOrSecretsCommitted",
    ):
        if boundary.get(flag) is not False:
            raise DesiredStateError(f"contract: boundary.{flag} must be false")

    identities = contract.get("identities")
    if not isinstance(identities, list):
        raise DesiredStateError("contract: identities must be a list")
    roles = [identity.get("role") for identity in identities]
    if sorted(roles) != sorted(IDENTITY_ROLES):
        raise DesiredStateError("contract: identities must declare exactly the five certification roles")
    client_ids = [identity.get("clientId") for identity in identities]
    if len(set(client_ids)) != len(client_ids):
        raise DesiredStateError("contract: identity client IDs must be unique")
    for identity in identities:
        validate_identity_declaration(identity, audience)


def validate_identity_declaration(identity: dict[str, Any], audience: str) -> None:
    client_id = identity.get("clientId")
    if not isinstance(client_id, str) or not CLIENT_ID_PATTERN.fullmatch(client_id):
        raise DesiredStateError(f"contract: identity client ID is not an isolated test-syn identity: {client_id!r}")
    expected = IDENTITY_ROLES[identity["role"]]
    if identity.get("scopes") != expected["scopes"]:
        raise DesiredStateError(f"{client_id}: scopes must be exactly {expected['scopes']}")
    if set(identity["scopes"]) - set(INGRESS_SCOPES):
        raise DesiredStateError(f"{client_id}: only ingress scopes may be granted")
    if OUTBOUND_SCOPE in identity["scopes"] or set(FORBIDDEN_SCOPES) & set(identity["scopes"]):
        raise DesiredStateError(f"{client_id}: outbound or forbidden scope granted")
    if expected["middleware_audience"]:
        if identity.get("audience") != audience:
            raise DesiredStateError(f"{client_id}: audience must be {audience}")
    elif identity.get("audience") in {audience, "middleware-api"} or not identity.get("audience"):
        raise DesiredStateError(f"{client_id}: wrong-audience identity must not carry a Middleware audience")
    if (
        identity.get("tenant") != expected["tenant"]
        or identity.get("businessUnits") != expected["units"]
        or identity.get("campaigns") != expected["campaigns"]
    ):
        raise DesiredStateError(f"{client_id}: tenant, business-unit, or campaign binding is not exact")
    reference = identity.get("secretReference")
    if not isinstance(reference, str) or not reference.startswith("secret://staging/keycloak/edge-certification/"):
        raise DesiredStateError(f"{client_id}: secretReference must point at the staging secret store")


# --- client scopes and clients --------------------------------------------------


def validate_client_scope(name: str, scope: dict[str, Any]) -> None:
    assert_no_secret(scope, name)
    if name not in INGRESS_SCOPES or scope.get("name") != name:
        raise DesiredStateError(f"client scope {name} is not an approved ingress scope")
    if scope.get("protocol") != "openid-connect":
        raise DesiredStateError(f"{name}: client scope must use OpenID Connect")
    if scope.get("protocolMappers") != []:
        raise DesiredStateError(f"{name}: ingress scope must not add claims or audiences")
    if scope.get("attributes") != {
        "display.on.consent.screen": "false",
        "include.in.token.scope": "true",
    }:
        raise DesiredStateError(f"{name}: client-scope attributes are not exact")
    if not str(scope.get("description", "")).strip():
        raise DesiredStateError(f"{name}: client scope needs a description")


def validate_client(identity: dict[str, Any], client: dict[str, Any]) -> None:
    client_id = identity["clientId"]
    assert_no_secret(client, client_id)
    if client.get("clientId") != client_id:
        raise DesiredStateError(f"{client_id}: clientId mismatch")
    exact_values = {
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "bearerOnly": False,
        "consentRequired": False,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "authorizationServicesEnabled": False,
        "frontchannelLogout": False,
        "fullScopeAllowed": False,
        "redirectUris": [],
        "webOrigins": [],
        "optionalClientScopes": [],
        "defaultClientScopes": ["basic"] + list(identity["scopes"]),
        "attributes": {
            "access.token.lifespan": "300",
            "oauth2.device.authorization.grant.enabled": "false",
            "oidc.ciba.grant.enabled": "false",
        },
    }
    for field, required in exact_values.items():
        if client.get(field) != required:
            raise DesiredStateError(f"{client_id}: invalid {field}")
    unexpected = set(client) - set(exact_values) - {"clientId", "name", "description", "protocolMappers"}
    if unexpected:
        raise DesiredStateError(f"{client_id}: unexpected client fields {sorted(unexpected)}")
    mappers = client.get("protocolMappers")
    if not isinstance(mappers, list) or [m.get("name") for m in mappers] != [
        f"audience-{identity['audience']}",
        *MAPPER_CLAIMS,
    ]:
        raise DesiredStateError(f"{client_id}: protocol mappers must be the audience mapper plus the four hardcoded claims")
    audience = mappers[0]
    if (
        audience.get("protocolMapper") != "oidc-audience-mapper"
        or audience.get("consentRequired") is not False
        or audience.get("config") != {
            "included.custom.audience": identity["audience"],
            "id.token.claim": "false",
            "access.token.claim": "true",
        }
    ):
        raise DesiredStateError(f"{client_id}: audience mapper is not exact")
    expected_claims = {
        "environment": ("String", ENVIRONMENT),
        "tenant_id": ("String", identity["tenant"]),
        "business_units": ("JSON", json.dumps(identity["businessUnits"], separators=(",", ":"))),
        "campaigns": ("JSON", json.dumps(identity["campaigns"], separators=(",", ":"))),
    }
    for mapper in mappers[1:]:
        claim, json_type = MAPPER_CLAIMS[mapper["name"]]
        expected_type, expected_value = expected_claims[claim]
        if (
            mapper.get("protocolMapper") != "oidc-hardcoded-claim-mapper"
            or mapper.get("consentRequired") is not False
            or json_type != expected_type
            or mapper.get("config") != {
                "claim.name": claim,
                "claim.value": expected_value,
                "jsonType.label": expected_type,
                "id.token.claim": "false",
                "access.token.claim": "true",
                "userinfo.token.claim": "false",
                "access.tokenResponse.claim": "false",
            }
        ):
            raise DesiredStateError(f"{client_id}: hardcoded claim {claim} is not exact")


# --- isolation from the live-capable sets ----------------------------------------


def granted_scope_claims(client: dict[str, Any]) -> set[str]:
    granted: set[str] = set(client.get("defaultClientScopes") or [])
    granted |= set(client.get("optionalClientScopes") or [])
    for mapper in client.get("protocolMappers") or []:
        config = mapper.get("config") or {}
        if config.get("claim.name") == "scope":
            granted |= set(str(config.get("claim.value", "")).split())
    return granted


def validate_isolation(contract: dict[str, Any]) -> None:
    certification_ids = {identity["clientId"] for identity in contract["identities"]}
    for policy_path in (MANAGED_POLICY, CREATABLE_POLICY):
        listed = set(load_json(policy_path).get("clients") or [])
        if listed & certification_ids:
            raise DesiredStateError(f"certification identity leaked into {relative(policy_path)}")
    machine_ids = {c.get("clientId") for c in load_json(MACHINE_CONTRACT).get("clients") or []}
    if machine_ids & certification_ids:
        raise DesiredStateError("certification identity leaked into the machine-client contract")
    matrix = load_json(ACCESS_MATRIX)
    for grant in matrix.get("grants") or []:
        if set(grant.get("scopes") or []) & set(INGRESS_SCOPES):
            raise DesiredStateError("ingress scope granted in the production service-access matrix")
        if grant.get("callerClientId") in certification_ids or grant.get("targetClientId") in certification_ids:
            raise DesiredStateError("certification identity leaked into the service-access matrix")
    for path in sorted(LIVE_CLIENTS_DIR.glob("*.json")):
        client = load_json(path)
        if client.get("clientId") in certification_ids:
            raise DesiredStateError(f"certification identity leaked into live-capable {relative(path)}")
        granted = granted_scope_claims(client)
        if granted & set(INGRESS_SCOPES):
            raise DesiredStateError(f"ingress scope granted to production client {relative(path)}")
        if granted & set(FORBIDDEN_SCOPES):
            raise DesiredStateError(f"forbidden scope {FORBIDDEN_SCOPES[0]} granted in {relative(path)}")
    for path in sorted(LIVE_SCOPES_DIR.glob("*.json")):
        if load_json(path).get("name") in INGRESS_SCOPES:
            raise DesiredStateError(f"ingress scope leaked into live-capable {relative(path)}")
    realm = load_json(REALM_PATH)
    realm_defaults = set(realm.get("defaultDefaultClientScopes") or []) | set(
        realm.get("defaultOptionalClientScopes") or []
    )
    if realm_defaults & set(INGRESS_SCOPES):
        raise DesiredStateError("ingress scope granted realm-wide through a realm default client scope")


# --- cross-repository edge-contract check -----------------------------------------


def middleware_repository(explicit: str | None) -> Path | None:
    candidates = [explicit, os.environ.get("CERTIFY_MIDDLEWARE_REPO")]
    candidates.append(str(ROOT.parent / "Middleware-"))
    for candidate in candidates:
        if candidate and (Path(candidate) / "deploy" / "public-api-route-contract.json").is_file():
            return Path(candidate)
    return None


def cross_check_edge_contract(contract: dict[str, Any], repo: Path) -> dict[str, Any]:
    """Recompute the Middleware contract hash and compare routes and scopes."""
    contract_path = repo / "deploy" / "public-api-route-contract.json"
    pin_path = repo / "deploy" / "public-api-route-contract.sha256"
    document = json.loads(contract_path.read_text(encoding="utf-8"))
    computed = edge_contract_sha256(document)
    pinned = pin_path.read_text(encoding="utf-8").strip() if pin_path.is_file() else None
    keycloak_pin = contract["edgeContract"]["sha256"]
    middleware_routes = {
        (row.get("method"), row.get("path"), row.get("scope"))
        for row in document.get("routes", [])
        if row.get("scope") in INGRESS_SCOPES
    }
    keycloak_routes = {
        (row["method"], row["path"], row.get("scope"))
        for row in contract["routes"]
        if row.get("classification") == "shared_edge"
    }
    result = {
        "middlewareRepository": str(repo),
        "computedSha256": computed,
        "middlewarePinnedSha256": pinned,
        "keycloakPinnedSha256": keycloak_pin,
        "hashesIdentical": computed == pinned == keycloak_pin,
        "routesIdentical": middleware_routes == keycloak_routes,
        "routesOnlyInMiddleware": sorted(map(list, middleware_routes - keycloak_routes)),
        "routesOnlyInKeycloak": sorted(map(list, keycloak_routes - middleware_routes)),
    }
    if not result["hashesIdentical"]:
        raise DesiredStateError(
            f"edge-contract hash mismatch: keycloak {keycloak_pin} middleware-pin {pinned} computed {computed}"
        )
    if not result["routesIdentical"]:
        raise DesiredStateError(f"edge-contract route/scope mismatch: {result}")
    return result


# --- plan -----------------------------------------------------------------------


def validate() -> tuple[dict[str, Any], list[tuple[Path, dict[str, Any]]]]:
    contract = load_json(CONTRACT_PATH)
    validate_contract(contract)
    documents: list[tuple[Path, dict[str, Any]]] = [(CONTRACT_PATH, contract)]
    scope_dir = DESIRED_ROOT / "client-scopes"
    for name in INGRESS_SCOPES:
        path = scope_dir / f"{name}.json"
        scope = load_json(path)
        validate_client_scope(name, scope)
        documents.append((path, scope))
    if {p.name for p in scope_dir.glob("*.json")} != {f"{name}.json" for name in INGRESS_SCOPES}:
        raise DesiredStateError("client-scopes directory must contain exactly the three ingress scopes")
    client_dir = DESIRED_ROOT / "clients"
    for identity in contract["identities"]:
        path = client_dir / f"{identity['clientId']}.json"
        client = load_json(path)
        validate_client(identity, client)
        documents.append((path, client))
    expected_files = {f"{identity['clientId']}.json" for identity in contract["identities"]}
    if {p.name for p in client_dir.glob("*.json")} != expected_files:
        raise DesiredStateError("clients directory must contain exactly the declared certification identities")
    validate_isolation(contract)
    return contract, documents


def build_plan() -> dict[str, Any]:
    contract, documents = validate()
    source_files = []
    checksum_input = bytearray()
    for path, value in sorted(documents, key=lambda item: relative(item[0])):
        payload = canonical(value)
        checksum_input.extend(relative(path).encode() + b"\0" + payload)
        source_files.append({"path": relative(path), "sha256": hashlib.sha256(payload).hexdigest()})
    operations = []
    for name in INGRESS_SCOPES:
        desired = load_json(DESIRED_ROOT / "client-scopes" / f"{name}.json")
        operations.append({
            "resourceType": "client-scope",
            "resourceId": name,
            "action": "RECONCILE_IN_STAGING_ONLY_AUTHORIZED_MISSION",
            "desiredSha256": hashlib.sha256(canonical(desired)).hexdigest(),
        })
    for identity in contract["identities"]:
        desired = load_json(DESIRED_ROOT / "clients" / f"{identity['clientId']}.json")
        operations.append({
            "resourceType": "client",
            "resourceId": identity["clientId"],
            "action": "RECONCILE_IN_STAGING_ONLY_AUTHORIZED_MISSION",
            "desiredSha256": hashlib.sha256(canonical(desired)).hexdigest(),
        })
        operations.append({
            "resourceType": "client-default-scope-links",
            "resourceId": identity["clientId"],
            "action": "RECONCILE_IN_STAGING_ONLY_AUTHORIZED_MISSION",
            "desiredSha256": hashlib.sha256(canonical(desired["defaultClientScopes"])).hexdigest(),
        })
    return {
        "schemaVersion": 1,
        "kind": "CodestraKeycloakEdgeCertificationDesiredStatePlan",
        "environment": ENVIRONMENT,
        "campaign": CAMPAIGN,
        "realm": contract["realm"],
        "issuer": contract["issuer"],
        "audience": contract["audience"],
        "ingressScopes": list(INGRESS_SCOPES),
        "edgeContract": contract["edgeContract"],
        "configurationChecksum": hashlib.sha256(checksum_input).hexdigest(),
        "sourceFiles": source_files,
        "operations": operations,
        "repositoryBoundary": {
            "runtimeStateRead": False,
            "liveApplyAuthorized": False,
            "liveApplyPerformed": False,
            "secretsGenerated": False,
            "tokensMinted": False,
            "productionTargetAllowed": False,
        },
        "activationPreconditions": [
            "protected merge SHA recorded",
            "identical edge-contract SHA-256 pinned by Middleware, Kong, Caddy, and Keycloak",
            "staging-only reconciliation with the protected staging administrator credential",
            "client secrets handed to the certification runner only through 0600 secret files",
            "Odoo and provider writes disabled for the whole certification",
        ],
        "rollback": {
            "newClientSequence": ["disable", "verify no active use", "separately approve deletion"],
            "newClientScopeSequence": ["unlink from every client", "verify zero links", "separately approve deletion"],
        },
    }


def rendered_bytes(plan: dict[str, Any]) -> bytes:
    return (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode()


def write_artifacts(plan: dict[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = rendered_bytes(plan)
    PLAN_PATH.write_bytes(payload)
    CHECKSUM_PATH.write_text(
        f"{hashlib.sha256(payload).hexdigest()}  {PLAN_PATH.name}\n",
        encoding="utf-8",
    )


def check_artifacts(plan: dict[str, Any]) -> None:
    expected = rendered_bytes(plan)
    try:
        actual = PLAN_PATH.read_bytes()
        checksum = CHECKSUM_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise DesiredStateError(f"rendered plan artifact missing: {exc}") from exc
    if actual.replace(b"\r\n", b"\n") != expected:
        raise DesiredStateError("rendered plan is stale; run with --write")
    expected_checksum = f"{hashlib.sha256(expected).hexdigest()}  {PLAN_PATH.name}\n"
    if checksum.replace("\r\n", "\n") != expected_checksum:
        raise DesiredStateError("rendered plan checksum is stale or malformed")


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true", help="write the deterministic source plan")
    group.add_argument("--check", action="store_true", help="validate source and committed artifacts")
    parser.add_argument("--middleware-repo", help="Middleware checkout for the edge-contract cross-check")
    parser.add_argument(
        "--require-cross-check",
        action="store_true",
        help="fail when the Middleware checkout is unavailable instead of skipping the cross-check",
    )
    args = parser.parse_args()
    try:
        plan = build_plan()
        if args.write:
            write_artifacts(plan)
        else:
            check_artifacts(plan)
        repo = middleware_repository(args.middleware_repo)
        if repo is None:
            if args.require_cross_check:
                raise DesiredStateError("Middleware checkout is required for the edge-contract cross-check")
            cross = None
        else:
            cross = cross_check_edge_contract(plan_contract(plan), repo)
    except DesiredStateError as exc:
        print(f"EDGE_CERTIFICATION_DESIRED_STATE_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
    print("KEYCLOAK_EDGE_CERTIFICATION_DESIRED_STATE=PASS")
    print(f"KEYCLOAK_EDGE_CERTIFICATION_IDENTITIES={len([o for o in plan['operations'] if o['resourceType'] == 'client'])}")
    print(f"KEYCLOAK_EDGE_CERTIFICATION_INGRESS_SCOPES={','.join(INGRESS_SCOPES)}")
    print(f"KEYCLOAK_EDGE_CONTRACT_SHA256={plan['edgeContract']['sha256']}")
    print(f"KEYCLOAK_EDGE_CERTIFICATION_CONFIGURATION_CHECKSUM={plan['configurationChecksum']}")
    print(f"EDGE_CONTRACT_CROSS_CHECK={'PASS' if cross else 'SKIPPED_NO_MIDDLEWARE_CHECKOUT'}")
    print("KEYCLOAK_LIVE_APPLY=PROHIBITED")


def plan_contract(plan: dict[str, Any]) -> dict[str, Any]:
    """The contract view the cross-check needs, taken from the validated plan inputs."""
    contract = load_json(CONTRACT_PATH)
    if contract["edgeContract"] != plan["edgeContract"]:
        raise DesiredStateError("plan edge-contract pin drifted from the contract")
    return contract


if __name__ == "__main__":
    main()
