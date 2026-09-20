#!/usr/bin/env python3
"""Validate the Keycloak desired state that lets workloads authenticate to OpenBao.

``config/desired-state/openbao-workload-identity/`` holds the ``openbao.workload``
optional client scope (audience ``openbao`` plus the ``codestra_environment``
claim), the new monitoring-plane confidential clients, the bindings of already
managed clients, and a vendored, pinned copy of the OpenBao workload authority.
This validator proves, without touching a live realm, that every OpenBao role
resolves to exactly one confidential service-account client of the same
``clientId`` (or is explicitly listed as unresolved), that no browser client or
``monitoring-readonly`` can ever obtain the scope, that the scope is never a
realm default, and, with ``--require-cross-check``, that the vendored authority
is byte-for-byte the OpenBao repository's and that OpenBao's roles bind the same
issuers, audience and claims this contract promises.
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
DESIRED_ROOT = ROOT / "config" / "desired-state" / "openbao-workload-identity"
CONTRACT_PATH = DESIRED_ROOT / "contract.json"
SCOPE_PATH = DESIRED_ROOT / "client-scopes" / "openbao.workload.json"
CLIENT_DIR = DESIRED_ROOT / "clients"
VENDORED_AUTHORITY = DESIRED_ROOT / "openbao-workload-secret-authority.v1.json"
VENDORED_PIN = DESIRED_ROOT / "openbao-workload-secret-authority.sha256"
MANAGED_POLICY = ROOT / "config" / "policy" / "managed-clients.json"
LIVE_CLIENTS_DIR = ROOT / "config" / "clients"
REALM_PATH = ROOT / "config" / "realms" / "codestra.json"
STAGING_ENDPOINTS = ROOT / "config" / "endpoints" / "codestra-staging.json"
PRODUCTION_ENDPOINTS = ROOT / "config" / "endpoints" / "codestra.json"

SCOPE_NAME = "openbao.workload"
AUDIENCE = "openbao"
CLAIM = "codestra_environment"
PLACEHOLDER = "${CODESTRA_ENVIRONMENT}"
CLIENT_ID = re.compile(r"^[a-z][a-z0-9-]{2,62}$")
SENSITIVE_KEY = re.compile(r"(secret|password|token|private[_-]?key|credential)$", re.IGNORECASE)
SECRET_SHAPED = re.compile(r"(hvs\.[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|[A-Za-z0-9+/]{40,}={0,2})")
NEVER_SECRET_SCOPES = re.compile(r"^(secret\.read|provider\.write|odoo\.write|sms\.write|email\.write|telephony\.write|production\.command)")


class DesiredStateError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DesiredStateError(f"{path.relative_to(ROOT).as_posix()}: {exc}") from exc
    if not isinstance(value, dict):
        raise DesiredStateError(f"{path.relative_to(ROOT).as_posix()}: must be an object")
    return value


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def assert_no_secret(value: Any, location: str = "root") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if SENSITIVE_KEY.search(str(key)) and key not in ("secretReference", "secretStorage", "secretsCommitted", "tokensOrSecretsCommitted", "secretReadingScopesOnMonitoringReadonly"):
                if isinstance(item, str) and item and not item.startswith("secret://") and item != "external-secret-store-only":
                    raise DesiredStateError(f"{location}.{key}: secret-bearing key")
            assert_no_secret(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_no_secret(item, f"{location}[{index}]")
    elif isinstance(value, str) and (value.startswith("hvs.") or "PRIVATE KEY" in value):
        raise DesiredStateError(f"{location}: secret-shaped value")


# --- contract ------------------------------------------------------------------------


def validate_contract(contract: dict[str, Any]) -> None:
    assert_no_secret(contract, "contract")
    if contract.get("kind") != "CodestraKeycloakOpenBaoWorkloadIdentityContract" or contract.get("schemaVersion") != 1:
        raise DesiredStateError("contract kind or schema is wrong")
    if contract.get("realm") != "codestra" or contract.get("audience") != AUDIENCE or contract.get("scope") != SCOPE_NAME:
        raise DesiredStateError("contract realm, audience or scope drifted")
    if contract.get("environmentClaim") != CLAIM or contract.get("environmentClaimPlaceholder") != PLACEHOLDER:
        raise DesiredStateError("environment claim contract drifted")
    if contract.get("reconcilerEnvironments") != ["staging"]:
        raise DesiredStateError("the reconciler may target staging only")
    staging = load_json(STAGING_ENDPOINTS)["issuer"]
    production = load_json(PRODUCTION_ENDPOINTS)["issuer"]
    if contract.get("issuers") != {"staging": staging, "production": production}:
        raise DesiredStateError("contract issuers must equal the reviewed endpoint documents")
    policy = contract.get("tokenPolicy") or {}
    if (
        policy.get("grantType") != "client_credentials"
        or policy.get("scopeParameterRequired") is not True
        or policy.get("maximumAccessTokenLifetimeSeconds") != 300
        or policy.get("refreshTokensAllowed") is not False
        or policy.get("fullScopeAllowed") is not False
        or policy.get("secretStorage") != "external-secret-store-only"
        or policy.get("requiredClaims") != ["iss", "sub", "aud", "azp", "iat", "exp", "jti", CLAIM]
    ):
        raise DesiredStateError("token policy drifted")
    boundary = contract.get("boundary") or {}
    for key in (
        "productionActivationAuthorized", "managedClientPolicyMembership", "liveApplyFromRepositoryCi",
        "realmDefaultScope", "browserClientsBound", "secretReadingScopesOnMonitoringReadonly",
        "tokensOrSecretsCommitted",
    ):
        if boundary.get(key) is not False:
            raise DesiredStateError(f"boundary.{key} must be false")
    authority = contract.get("openbaoAuthority") or {}
    if authority.get("repository") != "appolon1908-hue/Codestra-OpenBao" or authority.get("path") != "config/workload-secret-authority.v1.json":
        raise DesiredStateError("OpenBao authority pointer drifted")
    if not re.fullmatch(r"[0-9a-f]{64}", str(authority.get("sha256", ""))):
        raise DesiredStateError("OpenBao authority sha256 is malformed")
    if authority.get("maximumTokenLifetimeSeconds") != 300 or authority.get("requiredClaims") != policy["requiredClaims"]:
        raise DesiredStateError("OpenBao authority token bounds drifted from the token policy")


def validate_vendored_authority(contract: dict[str, Any]) -> dict[str, Any]:
    authority = load_json(VENDORED_AUTHORITY)
    actual = digest(authority)
    pinned = VENDORED_PIN.read_text(encoding="utf-8").strip()
    expected = contract["openbaoAuthority"]["sha256"]
    if actual != expected or pinned != expected:
        raise DesiredStateError("vendored OpenBao authority does not match the pinned sha256")
    if authority.get("audience") != AUDIENCE or authority.get("authMethod") != "jwt":
        raise DesiredStateError("vendored authority is not the JWT/openbao authority")
    if authority.get("issuersByEnvironment", {}).get("staging") != contract["issuers"]["staging"]:
        raise DesiredStateError("OpenBao staging issuer differs from the Keycloak staging issuer")
    if authority.get("issuersByEnvironment", {}).get("production") != contract["issuers"]["production"]:
        raise DesiredStateError("OpenBao production issuer differs from the Keycloak production issuer")
    if authority.get("runtimeApplyAuthorized") is not False:
        raise DesiredStateError("vendored authority must not authorize runtime apply")
    return authority


# --- scope and clients ----------------------------------------------------------------


def validate_scope(scope: dict[str, Any]) -> None:
    assert_no_secret(scope, "scope")
    if scope.get("name") != SCOPE_NAME or scope.get("protocol") != "openid-connect":
        raise DesiredStateError("scope name or protocol drifted")
    attributes = scope.get("attributes") or {}
    if attributes.get("include.in.token.scope") != "true" or attributes.get("display.on.consent.screen") != "false":
        raise DesiredStateError("scope attributes drifted")
    mappers = {m.get("name"): m for m in scope.get("protocolMappers") or []}
    if set(mappers) != {"audience-openbao", "claim-codestra-environment"}:
        raise DesiredStateError("scope must carry exactly the audience and environment mappers")
    audience = mappers["audience-openbao"]
    if (
        audience.get("protocolMapper") != "oidc-audience-mapper"
        or audience.get("config", {}).get("included.custom.audience") != AUDIENCE
        or audience.get("config", {}).get("access.token.claim") != "true"
        or audience.get("config", {}).get("id.token.claim") != "false"
    ):
        raise DesiredStateError("audience mapper must emit the openbao access-token audience only")
    claim = mappers["claim-codestra-environment"]
    config = claim.get("config", {})
    if (
        claim.get("protocolMapper") != "oidc-hardcoded-claim-mapper"
        or config.get("claim.name") != CLAIM
        or config.get("claim.value") != PLACEHOLDER
        or config.get("jsonType.label") != "String"
        or config.get("access.token.claim") != "true"
        or config.get("id.token.claim") != "false"
    ):
        raise DesiredStateError("environment claim mapper must emit the per-environment placeholder in the access token only")


def validate_confidential_client(client: dict[str, Any], client_id: str) -> None:
    assert_no_secret(client, f"clients.{client_id}")
    if client.get("clientId") != client_id or not CLIENT_ID.fullmatch(client_id):
        raise DesiredStateError(f"{client_id}: clientId mismatch")
    expected = {
        "enabled": True, "protocol": "openid-connect", "publicClient": False, "bearerOnly": False,
        "consentRequired": False, "standardFlowEnabled": False, "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False, "serviceAccountsEnabled": True,
        "authorizationServicesEnabled": False, "frontchannelLogout": False, "fullScopeAllowed": False,
        "redirectUris": [], "webOrigins": [],
    }
    for key, value in expected.items():
        if client.get(key) != value:
            raise DesiredStateError(f"{client_id}: {key} must be {value!r}")
    attributes = client.get("attributes") or {}
    if attributes.get("access.token.lifespan") != "300":
        raise DesiredStateError(f"{client_id}: access token lifespan must be 300")
    if client.get("defaultClientScopes") != ["basic"]:
        raise DesiredStateError(f"{client_id}: default scopes must be exactly ['basic']")
    if client.get("optionalClientScopes") != [SCOPE_NAME]:
        raise DesiredStateError(f"{client_id}: optional scopes must be exactly ['{SCOPE_NAME}']")
    for mapper in client.get("protocolMappers") or []:
        config = mapper.get("config", {})
        if mapper.get("protocolMapper") == "oidc-audience-mapper" and config.get("included.custom.audience") == AUDIENCE:
            raise DesiredStateError(f"{client_id}: the openbao audience must come from the optional scope, never a client mapper")
        if config.get("claim.name") == CLAIM:
            raise DesiredStateError(f"{client_id}: the environment claim must come from the optional scope, never a client mapper")
        if config.get("claim.name") == "scope" and NEVER_SECRET_SCOPES.search(str(config.get("claim.value", ""))):
            raise DesiredStateError(f"{client_id}: carries a forbidden scope")


def validate_new_clients(contract: dict[str, Any], authority: dict[str, Any], managed: list[str]) -> list[tuple[Path, dict[str, Any]]]:
    roles: dict[str, dict[str, list[str]]] = {}
    environments: dict[str, list[str]] = {}
    for role in authority["roles"]:
        roles.setdefault(role["serviceIdentity"], {})[role["environment"]] = role["pathPrefixes"]
        environments.setdefault(role["serviceIdentity"], []).append(role["environment"])
    documents: list[tuple[Path, dict[str, Any]]] = []
    declared = contract.get("newClients") or []
    if not declared:
        raise DesiredStateError("no new clients declared")
    seen: set[str] = set()
    for entry in declared:
        client_id = entry.get("clientId")
        if client_id in seen:
            raise DesiredStateError(f"duplicate new client {client_id}")
        seen.add(client_id)
        if entry.get("openbaoIdentity") != client_id:
            raise DesiredStateError(f"{client_id}: clientId must equal the OpenBao identity (azp binding)")
        if client_id in managed:
            raise DesiredStateError(f"{client_id}: a new client must not already be a protected managed client")
        if client_id not in roles:
            raise DesiredStateError(f"{client_id}: not an admitted OpenBao identity")
        if entry.get("environments") != environments[client_id] or entry.get("pathPrefixes") != roles[client_id]:
            raise DesiredStateError(f"{client_id}: environments or prefixes drifted from the OpenBao authority")
        if not str(entry.get("secretReference", "")).startswith("secret://staging/keycloak/openbao-workload-identity/"):
            raise DesiredStateError(f"{client_id}: secret reference must be an external staging store pointer")
        path = CLIENT_DIR / f"{client_id}.json"
        client = load_json(path)
        validate_confidential_client(client, client_id)
        has_middleware = any(
            m.get("config", {}).get("included.custom.audience") == "middleware-api" for m in client.get("protocolMappers") or []
        )
        if has_middleware != bool(entry.get("middlewareAudience")):
            raise DesiredStateError(f"{client_id}: middlewareAudience declaration differs from the client mappers")
        documents.append((path, client))
    expected_files = {f"{entry['clientId']}.json" for entry in declared}
    if {p.name for p in CLIENT_DIR.glob("*.json")} != expected_files:
        raise DesiredStateError("clients directory must contain exactly the declared new clients")
    return documents


def validate_existing_bindings(contract: dict[str, Any], authority: dict[str, Any], managed: list[str]) -> None:
    identities = {role["serviceIdentity"] for role in authority["roles"]}
    for entry in contract.get("existingClientBindings") or []:
        client_id = entry.get("clientId")
        if entry.get("openbaoIdentity") != client_id or client_id not in identities:
            raise DesiredStateError(f"{client_id}: existing binding must name an admitted OpenBao identity of the same clientId")
        if entry.get("managedByProtectedPolicy") is not True or client_id not in managed:
            raise DesiredStateError(f"{client_id}: existing binding must be a protected managed client")
        live = load_json(LIVE_CLIENTS_DIR / f"{client_id}.json")
        if live.get("serviceAccountsEnabled") is not True or live.get("publicClient") is not False:
            raise DesiredStateError(f"{client_id}: only confidential service-account clients may bind to OpenBao")
        if live.get("fullScopeAllowed") is not False:
            raise DesiredStateError(f"{client_id}: fullScopeAllowed must be false")
        if SCOPE_NAME in (live.get("defaultClientScopes") or []):
            raise DesiredStateError(f"{client_id}: {SCOPE_NAME} must never be a default client scope")


def validate_resolution(contract: dict[str, Any], authority: dict[str, Any]) -> None:
    identities = {role["serviceIdentity"] for role in authority["roles"]}
    resolved = {e["clientId"] for e in contract["newClients"]} | {e["clientId"] for e in contract["existingClientBindings"]}
    unresolved = {e["openbaoIdentity"] for e in contract.get("unresolvedOpenBaoIdentities") or []}
    if resolved & unresolved:
        raise DesiredStateError("an identity cannot be both resolved and unresolved")
    missing = identities - resolved - unresolved
    if missing:
        raise DesiredStateError(f"OpenBao identities without a Keycloak resolution or an explicit unresolved entry: {sorted(missing)}")
    extra = (resolved | unresolved) - identities
    if extra:
        raise DesiredStateError(f"contract names identities OpenBao does not admit: {sorted(extra)}")
    monitoring_plane = {
        "prometheus-openbao", "grafana-runtime", "alertmanager", "alloy-collector", "otel-gateway",
        "loki-runtime", "tempo-runtime", "redis-exporter", "postgres-exporter", "superset-analytics",
        "middleware-api", "middleware-worker", "n8n-automation", "odoo-integration", "kong-gateway",
    }
    if not monitoring_plane <= resolved:
        raise DesiredStateError(f"monitoring-plane identities must resolve: {sorted(monitoring_plane - resolved)}")


def validate_never_bound(contract: dict[str, Any]) -> None:
    never = {e["clientId"] for e in contract.get("neverBound") or []}
    for required in ("monitoring-readonly", "odoo-web", "n8n-editor-gateway"):
        if required not in never:
            raise DesiredStateError(f"{required} must be declared never bound")
    bound = {e["clientId"] for e in contract["newClients"]} | {e["clientId"] for e in contract["existingClientBindings"]}
    if bound & never:
        raise DesiredStateError("a never-bound client is bound")
    for path in sorted(LIVE_CLIENTS_DIR.glob("*.json")):
        live = load_json(path)
        client_id = live.get("clientId")
        scopes = set(live.get("defaultClientScopes") or []) | set(live.get("optionalClientScopes") or [])
        if live.get("publicClient") is True and SCOPE_NAME in scopes:
            raise DesiredStateError(f"{client_id}: browser client carries {SCOPE_NAME}")
        if client_id == "monitoring-readonly":
            if scopes != {"health.read", "metrics.read"} or live.get("defaultClientScopes") != []:
                raise DesiredStateError("monitoring-readonly must carry exactly the optional health.read and metrics.read scopes")
            for mapper in live.get("protocolMappers") or []:
                value = str(mapper.get("config", {}).get("claim.value", ""))
                if NEVER_SECRET_SCOPES.search(value):
                    raise DesiredStateError("monitoring-readonly carries a forbidden scope")
    realm = load_json(REALM_PATH)
    for key in ("defaultDefaultClientScopes", "defaultOptionalClientScopes"):
        if SCOPE_NAME in (realm.get(key) or []):
            raise DesiredStateError(f"{SCOPE_NAME} must not be a realm {key}")


# --- cross-check ------------------------------------------------------------------------


def openbao_repository(explicit: str | None) -> Path | None:
    candidates = [explicit, os.environ.get("OPENBAO_REPO")]
    for candidate in candidates:
        if candidate:
            path = Path(candidate)
            if (path / "config" / "workload-secret-authority.v1.json").is_file():
                return path
            raise DesiredStateError(f"OpenBao checkout is not usable: {candidate}")
    return None


def cross_check(contract: dict[str, Any], repo: Path) -> dict[str, Any]:
    authority = load_json(repo / "config" / "workload-secret-authority.v1.json")
    if digest(authority) != contract["openbaoAuthority"]["sha256"]:
        raise DesiredStateError("OpenBao checkout authority differs from the vendored, pinned copy")
    roles = load_json(repo / "openbao" / "auth" / "jwt-roles.v1.json")
    mounts = roles.get("mountConfigurationByEnvironment") or {}
    for environment, issuer in contract["issuers"].items():
        if mounts.get(environment, {}).get("bound_issuer") != issuer:
            raise DesiredStateError(f"OpenBao {environment} mount does not bind the Keycloak {environment} issuer")
    for role in roles.get("roles") or []:
        expression = role["payload"]["cel_program"]["expression"]
        if role["payload"].get("bound_audiences") != [AUDIENCE] or f"'{AUDIENCE}' in claims.aud" not in expression:
            raise DesiredStateError(f"OpenBao role {role['name']} does not bind the openbao audience")
        if f"'{CLAIM}' in claims" not in expression:
            raise DesiredStateError(f"OpenBao role {role['name']} does not require {CLAIM}")
    if roles.get("requiredClaims") != contract["tokenPolicy"]["requiredClaims"]:
        raise DesiredStateError("OpenBao required claims differ from the Keycloak token policy")
    return {"authoritySha256": contract["openbaoAuthority"]["sha256"], "roles": len(roles.get("roles") or [])}


def validate() -> tuple[dict[str, Any], dict[str, Any], list[tuple[Path, dict[str, Any]]]]:
    contract = load_json(CONTRACT_PATH)
    validate_contract(contract)
    authority = validate_vendored_authority(contract)
    scope = load_json(SCOPE_PATH)
    validate_scope(scope)
    if {p.name for p in SCOPE_PATH.parent.glob("*.json")} != {SCOPE_PATH.name}:
        raise DesiredStateError("client-scopes directory must contain exactly openbao.workload")
    managed = load_json(MANAGED_POLICY)["clients"]
    documents = [(CONTRACT_PATH, contract), (SCOPE_PATH, scope)]
    documents.extend(validate_new_clients(contract, authority, managed))
    validate_existing_bindings(contract, authority, managed)
    validate_resolution(contract, authority)
    validate_never_bound(contract)
    return contract, authority, documents


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", required=True)
    parser.add_argument("--openbao-repo", help="Codestra-OpenBao checkout for the authority cross-check")
    parser.add_argument("--require-cross-check", action="store_true")
    args = parser.parse_args()
    try:
        contract, authority, documents = validate()
        repo = openbao_repository(args.openbao_repo)
        if repo is None:
            if args.require_cross_check:
                raise DesiredStateError("OpenBao checkout is required for the authority cross-check")
            cross = None
        else:
            cross = cross_check(contract, repo)
    except DesiredStateError as exc:
        print(f"OPENBAO_WORKLOAD_IDENTITY_DESIRED_STATE_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
    print("KEYCLOAK_OPENBAO_WORKLOAD_IDENTITY_DESIRED_STATE=PASS")
    print(f"KEYCLOAK_OPENBAO_NEW_CLIENTS={len(contract['newClients'])}")
    print(f"KEYCLOAK_OPENBAO_EXISTING_BINDINGS={len(contract['existingClientBindings'])}")
    print(f"KEYCLOAK_OPENBAO_UNRESOLVED_IDENTITIES={','.join(e['openbaoIdentity'] for e in contract['unresolvedOpenBaoIdentities']) or 'none'}")
    print(f"KEYCLOAK_OPENBAO_AUTHORITY_SHA256={contract['openbaoAuthority']['sha256']}")
    print(f"OPENBAO_AUTHORITY_CROSS_CHECK={'PASS' if cross else 'SKIPPED_NO_OPENBAO_CHECKOUT'}")
    print("KEYCLOAK_LIVE_APPLY=PROHIBITED")


if __name__ == "__main__":
    main()
