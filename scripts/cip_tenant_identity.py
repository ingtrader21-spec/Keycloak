#!/usr/bin/env python3
"""CIP tenant identity authority: contract validation and desired-state rendering.

``config/desired-state/cip-tenant-identity/contract.json`` is the single source
for the Codestra Integration Platform (CIP) tenant identity. It defines who the
caller is (human user or single-tenant service account), which tenant and
projects the caller acts for, and where those claims come from. This script
proves the contract is fail-closed and renders the Keycloak desired state from
it deterministically:

* ``client-scopes/cip.user.context.json``: human tenant/project/MFA claims read
  from admin-only user-profile attributes;
* ``user-profile/cip-tenant-attributes.json``: the admin-only attribute fragment;
* ``clients/<clientId>.json``: every rendered CIP client.

It never contacts Keycloak, never creates a secret and never authorizes an
apply. ``--check`` fails when a committed file differs from the rendering.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
DESIRED_ROOT = ROOT / "config" / "desired-state" / "cip-tenant-identity"
CONTRACT_PATH = DESIRED_ROOT / "contract.json"
PARITY_RECORD = ROOT / "config" / "certification" / "cip-f3-cross-repo-parity-recertification.v1.json"
ACCESS_V3 = ROOT / "config" / "contracts" / "middleware-api-access.v3.json"
CALLERS = ROOT / "config" / "contracts" / "middleware-caller-classification.v1.json"
MANAGED_POLICY = ROOT / "config" / "policy" / "managed-clients.json"
LIVE_CLIENTS_DIR = ROOT / "config" / "clients"
PRODUCTION_ENDPOINTS = ROOT / "config" / "endpoints" / "codestra.json"
STAGING_ENDPOINTS = ROOT / "config" / "endpoints" / "codestra-staging.json"

AUDIENCE = "middleware-api"
USER_CONTEXT_SCOPE = "cip.user.context"
TENANT_CLAIM = "tenant_id"
PROJECT_CLAIM = "project_ids"
ACTOR_CLAIM = "codestra_actor_kind"
ACTOR_KINDS = ("user", "service")
REQUIRED_CLAIMS = ["iss", "sub", "aud", "azp", "iat", "exp", "jti", "scope", TENANT_CLAIM, ACTOR_CLAIM]
PROHIBITED_TENANT_CLAIMS = ["tenant_ids", "tenant", "org_id", "tid", "organization"]
PRODUCT_SCOPES = [
    "cip.tenant.admin",
    "cip.connector.admin",
    "platform.command",
    "platform.command.read",
    "cip.usage.read",
    "cip.audit.read",
]
HUMAN_ONLY_SCOPES = {"cip.tenant.admin", "cip.connector.admin"}
FROZEN_KERNEL_SCOPES = {"platform.command", "platform.command.read"}
MUST_PROHIBIT_SCOPES = {"platform.command.replay", "platform.tenants.read", "identity.request", "middleware.request.forward"}
FROZEN_SCOPE_DIR = ROOT / "config" / "client-scopes"
ADMIN_ONLY = {"view": ["admin"], "edit": ["admin"]}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SECRET_SHAPED = re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.)")
SENSITIVE_KEY = re.compile(r"^(secret|clientsecret|client_secret|password|privatekey|private_key|access_token|refresh_token|credential)$", re.IGNORECASE)
LOCAL_ORIGIN = re.compile(r"^http://(localhost|127\.0\.0\.1)(:\d+)?(/.*)?$")
MAX_PROJECTS = 64


class IdentityError(ValueError):
    """The CIP tenant identity contract or its desired state is not fail-closed."""


def relative(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IdentityError(f"{relative(path)}: {exc}") from exc
    if not isinstance(value, dict):
        raise IdentityError(f"{relative(path)}: must contain a JSON object")
    return value


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_of(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def rendered_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def assert_no_secret(value: Any, location: str = "root") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if SENSITIVE_KEY.match(str(key)) and item not in (None, "", [], {}):
                raise IdentityError(f"{location}.{key}: secret-bearing field is populated")
            assert_no_secret(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_no_secret(item, f"{location}[{index}]")
    elif isinstance(value, str) and SECRET_SHAPED.search(value):
        raise IdentityError(f"{location}: secret- or token-shaped value")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IdentityError(message)


# --- contract ------------------------------------------------------------------------


def validate_contract(contract: dict[str, Any]) -> None:
    assert_no_secret(contract, "contract")
    _require(contract.get("schemaVersion") == 1, "contract schemaVersion must be 1")
    _require(contract.get("kind") == "CodestraKeycloakCipTenantIdentityContract", "contract kind is wrong")
    _require(contract.get("status") == "PREPARED_DISABLED", "contract must stay PREPARED_DISABLED")
    _require(contract.get("realm") == "codestra", "contract realm must be codestra")

    production = load_json(PRODUCTION_ENDPOINTS)
    staging = load_json(STAGING_ENDPOINTS)
    _require(
        contract.get("issuers") == {"production": production["issuer"], "staging": staging["issuer"]},
        "contract issuers must equal the reviewed endpoint documents",
    )
    _require(
        contract.get("jwksUris") == {"production": production["jwksUri"], "staging": staging["jwksUri"]},
        "contract JWKS URIs must equal the reviewed endpoint documents",
    )

    # The audience and route contract are frozen by PAS-8 and re-certified in step 1.
    _require(contract.get("audience") == AUDIENCE, "CIP audience is frozen to middleware-api")
    access = load_json(ACCESS_V3)
    callers = load_json(CALLERS)
    parity = load_json(PARITY_RECORD)
    route = contract.get("middlewareRouteContract") or {}
    _require(access.get("targetAudience") == AUDIENCE, "access v3 audience drifted from middleware-api")
    _require(callers["middleware"]["canonicalAudience"] == AUDIENCE, "caller authority audience drifted")
    _require(route.get("sha256") == access["source"]["sha256"], "route contract digest differs from access v3")
    _require(route.get("sha256") == parity["frozen"]["routeContractSha256"], "route digest differs from parity record")
    _require(route.get("routeCount") == access["source"]["routeCount"], "route count differs from access v3")
    _require(route.get("parityEvidence") == relative(PARITY_RECORD), "parity evidence pointer drifted")
    _require(parity["results"]["missionHeads"]["verdict"] == "PASS", "parity re-certification is not PASS")

    policy = contract.get("tokenPolicy") or {}
    _require(policy.get("signingAlgorithms") == ["RS256"], "only RS256 access tokens are accepted")
    _require(policy.get("maximumAccessTokenLifetimeSeconds") == 300, "access tokens must live at most 300 seconds")
    _require(policy.get("requiredClaims") == REQUIRED_CLAIMS, "required claims drifted")
    for flag in (
        "wildcardScopesAllowed",
        "refreshTokensForServiceAccounts",
        "tokenExchangeAllowed",
        "passwordGrantAllowed",
        "implicitGrantAllowed",
    ):
        _require(policy.get(flag) is False, f"tokenPolicy.{flag} must be false")

    actors = contract.get("actorKinds") or {}
    _require(sorted(actors) == sorted(ACTOR_KINDS), "actor kinds must be exactly user and service")
    user, service = actors["user"], actors["service"]
    _require(
        user.get("grantType") == "authorization_code" and user.get("pkceMethod") == "S256",
        "human actors must use Authorization Code + PKCE S256",
    )
    _require(
        user.get("mfaRequired") is True and user.get("mfaEvidence") == {"claim": "amr", "mustContain": "mfa"},
        "human actors must prove MFA through amr=mfa",
    )
    _require(user.get("tenantSource") == "user-profile-attribute", "human tenant must come from the admin-only attribute")
    _require(
        service.get("grantType") == "client_credentials" and service.get("pkceMethod") is None,
        "service actors must use client_credentials only",
    )
    _require(service.get("mfaRequired") is False and service.get("mustNotCarryClaims") == ["amr"], "service actors must not carry amr")
    _require(
        service.get("tenantSource") == "dedicated-client-hardcoded-claim",
        "service tenant must come from a dedicated single-tenant client",
    )
    service_pattern = re.compile(str(service.get("clientIdPattern")))

    claims = contract.get("claims") or {}
    _require(sorted(claims) == sorted([TENANT_CLAIM, PROJECT_CLAIM, ACTOR_CLAIM, "amr"]), "claim set drifted")
    tenant = claims[TENANT_CLAIM]
    _require(tenant.get("required") is True and tenant.get("cardinality") == "exactly-one", "tenant_id must be exactly one required value")
    _require(tenant.get("pattern") == IDENTIFIER.pattern, "tenant_id pattern drifted")
    _require(not any(IDENTIFIER.match(value) for value in ("*", "", " ", "a*")), "tenant_id pattern must not admit a wildcard")
    project = claims[PROJECT_CLAIM]
    _require(project.get("required") is False and project.get("maximumItems") == MAX_PROJECTS, "project_ids bounds drifted")
    _require(project.get("pattern") == IDENTIFIER.pattern, "project_ids pattern drifted")
    for claim_name in (TENANT_CLAIM, PROJECT_CLAIM):
        sources = claims[claim_name]["sources"]
        _require(
            sources["user"] == {
                "keycloakMapper": "oidc-usermodel-attribute-mapper",
                "userAttribute": "codestra_tenant_id" if claim_name == TENANT_CLAIM else "codestra_project_ids",
                "clientScope": USER_CONTEXT_SCOPE,
                "attributePermissions": ADMIN_ONLY,
            },
            f"{claim_name}: the human source must be an admin-only user attribute",
        )
        _require(
            sources["service"].get("keycloakMapper") == "oidc-hardcoded-claim-mapper",
            f"{claim_name}: the service source must be a hardcoded mapper on the dedicated client",
        )
    _require(claims[ACTOR_CLAIM].get("enum") == ["user", "service"], "codestra_actor_kind enum drifted")

    _require(contract.get("prohibitedTenantClaims") == PROHIBITED_TENANT_CLAIMS, "prohibited tenant claims drifted")
    for selectors, claim_name in (("tenantSelectors", TENANT_CLAIM), ("projectSelectors", PROJECT_CLAIM)):
        block = contract.get(selectors) or {}
        _require("selector only" in str(block.get("rule")), f"{selectors} must be selector-only")
        for key in ("headers", "bodyFields", "queryParameters", "pathParameters"):
            _require(isinstance(block.get(key), list) and block[key], f"{selectors}.{key} must be a non-empty list")
    _require("X-Tenant-ID" in contract["tenantSelectors"]["headers"], "X-Tenant-ID must be a declared tenant selector")
    _require("tenant_id" in contract["tenantSelectors"]["bodyFields"], "body tenant_id must be a declared selector")

    profile = contract.get("userProfile") or {}
    _require(profile.get("unmanagedAttributePolicy") in {"ADMIN_VIEW", "ADMIN_EDIT"}, "users must not edit unmanaged attributes")
    _require(
        [a.get("name") for a in profile.get("attributes") or []] == ["codestra_tenant_id", "codestra_project_ids"],
        "user-profile attributes drifted",
    )

    shared = set(contract.get("sharedIdentitiesWithoutTenantAuthority") or [])
    _require({"kong-gateway", "n8n-automation"} <= shared, "shared gateway identities must be listed as tenant-less")
    protected = set(contract.get("protectedUngrantableClientIds") or [])
    _require(protected == set(callers["tokenPolicy"]["protectedUngrantableClientIds"]), "protected clients drifted from caller authority")

    managed = set(load_json(MANAGED_POLICY)["clients"])
    live = {path.stem for path in LIVE_CLIENTS_DIR.glob("*.json")}
    seen: set[str] = set()
    for entry in contract.get("clients") or []:
        client_id = str(entry.get("clientId"))
        _require(client_id not in seen, f"duplicate CIP client {client_id}")
        seen.add(client_id)
        _require(client_id not in managed and client_id not in live, f"{client_id}: CIP clients stay outside the managed-client policy")
        _require(client_id not in shared | protected, f"{client_id}: shared or protected identity cannot be a CIP client")
        kind = entry.get("actorKind")
        _require(kind in ACTOR_KINDS, f"{client_id}: actorKind must be user or service")
        if entry.get("rendered") is not True:
            _require(str(entry.get("status", "")).startswith("BLOCKED_"), f"{client_id}: an unrendered client must be BLOCKED")
            continue
        _require(entry.get("environment") == "staging", f"{client_id}: only staging CIP clients may be rendered")
        _require(entry.get("status") == "PREPARED_STAGING_ONLY", f"{client_id}: rendered clients are staging-only")
        _require(client_id.startswith("test-syn-cip-"), f"{client_id}: staging CIP clients must be test-syn-cip-*")
        if kind == "user":
            _require("tenant" not in entry and "projects" not in entry, f"{client_id}: a browser client must not bind a tenant")
            for uri in entry.get("redirectUris", []) + entry.get("webOrigins", []) + entry.get("postLogoutRedirectUris", []):
                _require(bool(LOCAL_ORIGIN.match(uri)) or uri.startswith("https://"), f"{client_id}: unsafe origin {uri}")
                _require("*" not in uri and uri not in {"+", "/"}, f"{client_id}: wildcard origin {uri}")
            _require(entry.get("redirectUris"), f"{client_id}: a browser client needs an exact redirect URI")
        else:
            _require(bool(service_pattern.match(client_id)), f"{client_id}: service client ID does not match the pattern")
            _require(bool(IDENTIFIER.match(str(entry.get("tenant", "")))), f"{client_id}: service client needs one tenant")
            projects = entry.get("projects")
            _require(isinstance(projects, list) and len(projects) <= MAX_PROJECTS, f"{client_id}: projects must be a bounded list")
            _require(all(IDENTIFIER.match(str(p)) for p in projects), f"{client_id}: invalid project identifier")
            _require(len(set(projects)) == len(projects), f"{client_id}: duplicate project")
            _require(
                str(entry.get("secretReference", "")) == f"secret://staging/keycloak/cip-tenant-identity/{client_id}",
                f"{client_id}: secretReference must point at the staging secret store",
            )

    validate_product_scopes(contract, access)
    validate_realm_roles(contract)
    validate_client_grants(contract, callers)

    boundary = contract.get("boundary") or {}
    for key in (
        "managedClientPolicyMembership",
        "liveApplyFromRepositoryCi",
        "productionActivationAuthorized",
        "realmDefaultScopes",
        "tokensOrSecretsCommitted",
        "frozenArtifactsModified",
    ):
        _require(boundary.get(key) is False, f"boundary.{key} must be false")
    _require(contract.get("reconcilerEnvironments") == ["staging"], "the CIP reconciler may target staging only")


# --- product scopes, roles and grants (least privilege) ----------------------------------


def product_scopes(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {scope["name"]: scope for scope in contract.get("productScopes") or []}


def roles_by_name(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {role["name"]: role for role in contract.get("realmRoles") or []}


def scope_role_mappings(contract: dict[str, Any]) -> dict[str, list[str]]:
    mappings: dict[str, list[str]] = {name: [] for name in PRODUCT_SCOPES}
    for role in contract.get("realmRoles") or []:
        for scope in role["grantsScopes"]:
            mappings[scope].append(role["name"])
    return {scope: sorted(roles) for scope, roles in mappings.items()}


def bound_routes(access: dict[str, Any], scope: str) -> list[dict[str, str]]:
    return sorted(
        (
            {
                "method": route["method"],
                "path": route["path"],
                "operationId": route["operationId"],
                "callingClient": route["callingClient"],
            }
            for route in access["routes"]
            if route.get("requiredScope") == scope
        ),
        key=lambda route: (route["path"], route["method"]),
    )


def validate_product_scopes(contract: dict[str, Any], access: dict[str, Any]) -> None:
    scopes = contract.get("productScopes") or []
    _require([scope.get("name") for scope in scopes] == PRODUCT_SCOPES, "product scopes must be exactly the six CIP capabilities")
    prohibited = set((contract.get("prohibitedOnCipPrincipals") or {}).get("scopes") or [])
    _require(MUST_PROHIBIT_SCOPES <= prohibited, "replay, cross-tenant, provisioning and gateway scopes must be prohibited")
    _require(not prohibited & set(PRODUCT_SCOPES), "a product scope cannot also be prohibited")
    _require(
        (contract.get("prohibitedOnCipPrincipals") or {}).get("realmRoles") == ["platform-operator"],
        "platform-operator must be prohibited on CIP principals",
    )
    required_by_middleware = set(access.get("requiredScopes") or [])
    for scope in scopes:
        name = scope["name"]
        kinds = scope.get("actorKinds")
        _require(isinstance(kinds, list) and kinds and set(kinds) <= set(ACTOR_KINDS), f"{name}: invalid actorKinds")
        if name in HUMAN_ONLY_SCOPES:
            _require(kinds == ["user"], f"{name}: administration scopes are human-only")
        _require(isinstance(scope.get("write"), bool), f"{name}: write must be declared")
        binding = scope.get("routeBinding") or {}
        if name in FROZEN_KERNEL_SCOPES:
            _require(scope.get("definitionOwner") == "frozen-platform-kernel", f"{name}: must reuse the frozen kernel scope")
            _require(scope.get("keycloakDefinition") == relative(FROZEN_SCOPE_DIR / f"{name}.json"), f"{name}: definition path drifted")
            _require(load_json(FROZEN_SCOPE_DIR / f"{name}.json").get("name") == name, f"{name}: frozen definition missing")
            _require(binding.get("status") == "BOUND", f"{name}: kernel scope must be route-bound")
            _require(binding.get("routes") == bound_routes(access, name), f"{name}: bound routes drifted from access v3")
            _require(binding["routes"], f"{name}: a bound scope needs at least one route")
        else:
            _require(scope.get("definitionOwner") == "cip-tenant-identity", f"{name}: new product scopes are owned here")
            _require(
                scope.get("keycloakDefinition") == relative(DESIRED_ROOT / "client-scopes" / f"{name}.json"),
                f"{name}: definition path drifted",
            )
            _require(name.startswith("cip."), f"{name}: new product scopes live in the cip namespace")
            _require(binding.get("status") == "UNBOUND_PENDING_MIDDLEWARE_ROUTE", f"{name}: no Middleware route binds it yet")
            _require(binding.get("routes") == [], f"{name}: an unbound scope lists no routes")
            _require(name not in required_by_middleware, f"{name}: Middleware now requires it; bind it explicitly")


def validate_realm_roles(contract: dict[str, Any]) -> None:
    scopes = product_scopes(contract)
    roles = contract.get("realmRoles") or []
    names = [role.get("name") for role in roles]
    _require(len(names) == len(set(names)), "duplicate CIP realm role")
    prohibited = set(contract["prohibitedOnCipPrincipals"]["scopes"])
    for role in roles:
        name, kind = role["name"], role.get("actorKind")
        _require(kind in ACTOR_KINDS, f"{name}: invalid actorKind")
        _require(name.startswith("cip-svc-" if kind == "service" else "cip-"), f"{name}: role prefix does not match its actor kind")
        _require(not (kind == "user" and name.startswith("cip-svc-")), f"{name}: human role uses the service prefix")
        _require(name not in contract["prohibitedOnCipPrincipals"]["realmRoles"], f"{name}: prohibited role")
        grants = role.get("grantsScopes") or []
        _require(grants and len(grants) == len(set(grants)), f"{name}: grantsScopes must be a non-empty unique list")
        for scope in grants:
            _require(scope in scopes, f"{name}: grants unknown scope {scope}")
            _require(scope not in prohibited, f"{name}: grants prohibited scope {scope}")
            _require(kind in scopes[scope]["actorKinds"], f"{name}: {kind} role cannot grant {scope}")
        for pair in contract.get("separationOfDuties") or []:
            _require(not set(pair) <= set(grants), f"{name}: violates separation of duties {pair}")
    mappings = scope_role_mappings(contract)
    for scope_name, scope in scopes.items():
        for kind in scope["actorKinds"]:
            _require(
                any(roles_by_name(contract)[role]["actorKind"] == kind for role in mappings[scope_name]),
                f"{scope_name}: no {kind} role can obtain it",
            )
    sod = contract.get("separationOfDuties") or []
    _require(["cip.tenant.admin", "cip.connector.admin"] in sod, "tenant and connector administration must stay separated")
    _require(["cip.tenant.admin", "cip.audit.read"] in sod, "tenant administration and audit read must stay separated")


def validate_client_grants(contract: dict[str, Any], callers: dict[str, Any]) -> None:
    scopes = product_scopes(contract)
    roles = roles_by_name(contract)
    for entry in rendered_clients(contract):
        client_id, kind = entry["clientId"], entry["actorKind"]
        optional = entry.get("optionalClientScopes")
        _require(isinstance(optional, list) and optional == sorted(set(optional)), f"{client_id}: optional scopes must be sorted and unique")
        _require(optional, f"{client_id}: a CIP client needs at least one product scope")
        for scope in optional:
            _require(scope in scopes, f"{client_id}: {scope} is not a CIP product scope")
            _require(kind in scopes[scope]["actorKinds"], f"{client_id}: a {kind} client cannot hold {scope}")
        if kind == "user":
            _require("serviceAccountRealmRoles" not in entry, f"{client_id}: a browser client has no service account")
            continue
        assigned = entry.get("serviceAccountRealmRoles")
        _require(isinstance(assigned, list) and assigned == sorted(set(assigned)), f"{client_id}: service roles must be sorted and unique")
        for role in assigned:
            _require(role in roles and roles[role]["actorKind"] == "service", f"{client_id}: {role} is not a CIP service role")
        obtainable = {scope for role in assigned for scope in roles[role]["grantsScopes"]}
        _require(obtainable == set(optional), f"{client_id}: service roles must grant exactly the client's optional scopes")
        for pair in contract.get("separationOfDuties") or []:
            _require(not set(pair) <= set(optional), f"{client_id}: violates separation of duties {pair}")

    family = contract.get("platformCommandClientFamily") or {}
    _require(family.get("status") == "PROPOSED_PENDING_MIDDLEWARE_REGISTRY", "platform-command-client membership is proposed only")
    frozen_family = callers["callers"]["platform-command-client"]
    _require(
        frozen_family.get("class") == "CLIENT_FAMILY" and "members" not in frozen_family,
        "the frozen caller authority must keep platform-command-client unresolved",
    )
    rendered = {entry["clientId"]: entry for entry in rendered_clients(contract)}
    expected = sorted(
        client_id
        for client_id, entry in rendered.items()
        if FROZEN_KERNEL_SCOPES & set(entry["optionalClientScopes"])
    )
    _require(sorted(family.get("proposedMembers") or []) == expected, "proposed family members must be exactly the command-capable CIP clients")


# --- rendering -------------------------------------------------------------------------


def _hardcoded(name: str, claim: str, value: str, json_type: str) -> dict[str, Any]:
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "consentRequired": False,
        "config": {
            "claim.name": claim,
            "claim.value": value,
            "jsonType.label": json_type,
            "id.token.claim": "false",
            "access.token.claim": "true",
            "userinfo.token.claim": "false",
            "access.tokenResponse.claim": "false",
        },
    }


def _audience_mapper() -> dict[str, Any]:
    return {
        "name": f"audience-{AUDIENCE}",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "consentRequired": False,
        "config": {
            "included.custom.audience": AUDIENCE,
            "id.token.claim": "false",
            "access.token.claim": "true",
        },
    }


def _attribute_mapper(name: str, attribute: str, claim: str, multivalued: bool) -> dict[str, Any]:
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": attribute,
            "claim.name": claim,
            "jsonType.label": "String",
            "id.token.claim": "false",
            "access.token.claim": "true",
            "userinfo.token.claim": "false",
            "multivalued": "true" if multivalued else "false",
            "aggregate.attrs": "false",
        },
    }


def render_user_context_scope(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": USER_CONTEXT_SCOPE,
        "description": (
            "Codestra CIP human tenant context managed by protected Keycloak GitOps. Emits tenant_id and "
            "project_ids from the admin-only codestra_tenant_id / codestra_project_ids user-profile attributes "
            "and the amr MFA evidence. Default scope of CIP browser clients only; never a realm default, never "
            "on a service client, and not an authorization scope (excluded from the scope claim)."
        ),
        "protocol": "openid-connect",
        "attributes": {
            "display.on.consent.screen": "false",
            "include.in.token.scope": "false",
        },
        "protocolMappers": [
            _attribute_mapper("tenant-id-from-admin-attribute", "codestra_tenant_id", TENANT_CLAIM, False),
            _attribute_mapper("project-ids-from-admin-attribute", "codestra_project_ids", PROJECT_CLAIM, True),
            {
                "name": "amr",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-amr-mapper",
                "consentRequired": False,
                "config": {
                    "id.token.claim": "false",
                    "access.token.claim": "true",
                    "userinfo.token.claim": "false",
                },
            },
        ],
    }


def render_user_profile(contract: dict[str, Any]) -> dict[str, Any]:
    attributes = []
    for entry in contract["userProfile"]["attributes"]:
        validations: dict[str, Any] = {
            "pattern": {
                "pattern": IDENTIFIER.pattern,
                "error-message": "codestraInvalidTenantIdentifier",
            },
            "length": {"min": 1, "max": 128},
        }
        if entry["multivalued"]:
            validations["multivalued"] = {"min": "0", "max": str(entry["maximumValues"])}
        attributes.append(
            {
                "name": entry["name"],
                "displayName": "Codestra tenant" if entry["claim"] == TENANT_CLAIM else "Codestra projects",
                "multivalued": entry["multivalued"],
                "permissions": {"view": ["admin"], "edit": ["admin"]},
                "validations": validations,
                "annotations": {"codestra.claim": entry["claim"]},
            }
        )
    return {
        "kind": "CodestraKeycloakUserProfileFragment",
        "merge": "append-attributes; existing realm user-profile attributes are left unchanged",
        "unmanagedAttributePolicy": contract["userProfile"]["unmanagedAttributePolicy"],
        "attributes": attributes,
    }


def optional_scopes_for(contract: dict[str, Any], entry: dict[str, Any]) -> list[str]:
    """Product scopes a client may request; never defaults, so every token asks for them explicitly."""
    return list(entry.get("optionalClientScopes") or [])


def render_product_scope(scope: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": scope["name"],
        "description": (
            f"Codestra CIP optional product scope ({scope['capability']}) managed by protected Keycloak GitOps. "
            f"{scope['description']} Requested explicitly per short-lived token, issued only to holders of its "
            "mapped CIP realm roles, bound to the token tenant_id, and never a realm or client default."
        ),
        "protocol": "openid-connect",
        "attributes": {
            "display.on.consent.screen": "false",
            "include.in.token.scope": "true",
        },
        "protocolMappers": [],
    }


def render_realm_role(role: dict[str, Any]) -> dict[str, Any]:
    kind = role["actorKind"]
    holder = "human user" if kind == "user" else "dedicated single-tenant CIP service account"
    return {
        "name": role["name"],
        "description": (
            f"Codestra CIP {holder} role: lets its holder obtain {', '.join(role['grantsScopes'])} for the "
            "holder's own tenant only. Non-composite, never a default role, never copied into the access token; "
            "prepared only and assigned by no planner."
        ),
        "composite": False,
        "clientRole": False,
        "attributes": {
            "codestra.role.family": ["cip-product"],
            "codestra.actor.kind": [kind],
            "codestra.grants.scopes": list(role["grantsScopes"]),
            "codestra.tenant.bound": ["true"],
            "codestra.mfa.required": ["true" if kind == "user" else "false"],
            "codestra.default_role": ["false"],
            "codestra.cross_family_grant": ["false"],
            "codestra.activation": ["PREPARED_DISABLED"],
        },
    }


def render_scope_role_mappings(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "CodestraKeycloakClientScopeRoleMappings",
        "rule": contract["scopeIssuanceRule"],
        "scopeMappings": [
            {"clientScope": scope, "roles": roles} for scope, roles in scope_role_mappings(contract).items()
        ],
    }


def render_client(contract: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    client_id = entry["clientId"]
    kind = entry["actorKind"]
    common = {
        "clientId": client_id,
        "name": f"Codestra CIP identity: {client_id}",
        "description": entry["purpose"] + " Staging-only desired state outside the protected managed-client policy.",
        "enabled": True,
        "protocol": "openid-connect",
        "bearerOnly": False,
        "consentRequired": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "authorizationServicesEnabled": False,
        "fullScopeAllowed": False,
    }
    attributes = {
        "access.token.lifespan": "300",
        "oauth2.device.authorization.grant.enabled": "false",
        "oidc.ciba.grant.enabled": "false",
        "standard.token.exchange.enabled": "false",
    }
    mappers = [_audience_mapper(), _hardcoded("claim-codestra-actor-kind", ACTOR_CLAIM, kind, "String")]
    if kind == "user":
        attributes["pkce.code.challenge.method"] = "S256"
        attributes["post.logout.redirect.uris"] = "##".join(entry.get("postLogoutRedirectUris") or [])
        client = {
            **common,
            "publicClient": bool(entry.get("publicClient")),
            "standardFlowEnabled": True,
            "serviceAccountsEnabled": False,
            "frontchannelLogout": True,
            "redirectUris": list(entry["redirectUris"]),
            "webOrigins": list(entry["webOrigins"]),
            "defaultClientScopes": ["basic", USER_CONTEXT_SCOPE],
        }
    else:
        attributes["client_credentials.use_refresh_token"] = "false"
        mappers.append(_hardcoded("claim-tenant-id", TENANT_CLAIM, entry["tenant"], "String"))
        if entry["projects"]:
            mappers.append(
                _hardcoded("claim-project-ids", PROJECT_CLAIM, json.dumps(entry["projects"], separators=(",", ":")), "JSON")
            )
        client = {
            **common,
            "publicClient": False,
            "standardFlowEnabled": False,
            "serviceAccountsEnabled": True,
            "frontchannelLogout": False,
            "redirectUris": [],
            "webOrigins": [],
            "defaultClientScopes": ["basic"],
        }
    client["optionalClientScopes"] = optional_scopes_for(contract, entry)
    client["attributes"] = dict(sorted(attributes.items()))
    client["protocolMappers"] = mappers
    return client


def rendered_clients(contract: dict[str, Any]) -> list[dict[str, Any]]:
    return [entry for entry in contract["clients"] if entry.get("rendered") is True]


def render_desired_state(contract: dict[str, Any]) -> dict[Path, dict[str, Any]]:
    rendered: dict[Path, dict[str, Any]] = {
        DESIRED_ROOT / "client-scopes" / f"{USER_CONTEXT_SCOPE}.json": render_user_context_scope(contract),
        DESIRED_ROOT / "user-profile" / "cip-tenant-attributes.json": render_user_profile(contract),
    }
    for scope in contract["productScopes"]:
        if scope["definitionOwner"] == "cip-tenant-identity":
            rendered[DESIRED_ROOT / "client-scopes" / f"{scope['name']}.json"] = render_product_scope(scope)
    for role in contract["realmRoles"]:
        rendered[DESIRED_ROOT / "realm-roles" / f"{role['name']}.json"] = render_realm_role(role)
    rendered[DESIRED_ROOT / "scope-role-mappings" / "cip-product-scopes.json"] = render_scope_role_mappings(contract)
    for entry in rendered_clients(contract):
        rendered[DESIRED_ROOT / "clients" / f"{entry['clientId']}.json"] = render_client(contract, entry)
    return rendered


# --- rendered-state invariants ----------------------------------------------------------


def _mapper_claims(client: dict[str, Any]) -> dict[str, dict[str, Any]]:
    claims: dict[str, dict[str, Any]] = {}
    for mapper in client.get("protocolMappers") or []:
        claim = (mapper.get("config") or {}).get("claim.name")
        if claim:
            _require(claim not in claims, f"{client.get('clientId')}: claim {claim} is mapped twice")
            claims[claim] = mapper
    return claims


def validate_client_document(contract: dict[str, Any], entry: dict[str, Any], client: dict[str, Any]) -> None:
    """Independent invariants for a CIP client, even if the renderer were wrong."""
    client_id = entry["clientId"]
    assert_no_secret(client, client_id)
    _require(client.get("clientId") == client_id, f"{client_id}: clientId mismatch")
    _require(client.get("fullScopeAllowed") is False, f"{client_id}: fullScopeAllowed must be false")
    _require(client.get("implicitFlowEnabled") is False, f"{client_id}: implicit flow is prohibited")
    _require(client.get("directAccessGrantsEnabled") is False, f"{client_id}: password grant is prohibited")
    attributes = client.get("attributes") or {}
    _require(int(attributes.get("access.token.lifespan", "0")) <= 300, f"{client_id}: token lifetime exceeds 300 seconds")
    _require(attributes.get("standard.token.exchange.enabled") == "false", f"{client_id}: token exchange must be disabled")
    for flag in ("oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled"):
        _require(attributes.get(flag) == "false", f"{client_id}: {flag} must be false")

    claims = _mapper_claims(client)
    for prohibited in PROHIBITED_TENANT_CLAIMS:
        _require(prohibited not in claims, f"{client_id}: prohibited tenant claim {prohibited}")
    actor = claims.get(ACTOR_CLAIM)
    _require(
        actor is not None
        and actor.get("protocolMapper") == "oidc-hardcoded-claim-mapper"
        and actor["config"].get("claim.value") == entry["actorKind"],
        f"{client_id}: codestra_actor_kind must be hardcoded to {entry['actorKind']}",
    )
    audiences = [
        m for m in client.get("protocolMappers") or [] if m.get("protocolMapper") == "oidc-audience-mapper"
    ]
    _require(
        [m["config"].get("included.custom.audience") for m in audiences] == [AUDIENCE],
        f"{client_id}: the only emitted audience must be middleware-api",
    )
    defaults = client.get("defaultClientScopes") or []
    optional = client.get("optionalClientScopes") or []
    _require(not set(defaults) & set(optional), f"{client_id}: a scope is both default and optional")
    _require(not any("*" in scope for scope in defaults + optional), f"{client_id}: wildcard scope")
    prohibited = set(contract["prohibitedOnCipPrincipals"]["scopes"])
    _require(not prohibited & set(defaults + optional), f"{client_id}: prohibited platform scope attached")
    _require(not set(PRODUCT_SCOPES) & set(defaults), f"{client_id}: product scopes are optional-only, never defaults")
    _require("roles" not in defaults + optional, f"{client_id}: the roles scope would copy CIP roles into the token")
    _require(set(optional) <= set(PRODUCT_SCOPES), f"{client_id}: only CIP product scopes may be optional")
    if entry["actorKind"] == "service":
        _require(not HUMAN_ONLY_SCOPES & set(optional), f"{client_id}: administration scopes are human-only")

    if entry["actorKind"] == "user":
        _require(
            client.get("standardFlowEnabled") is True and client.get("serviceAccountsEnabled") is False,
            f"{client_id}: a browser client must be Authorization Code only",
        )
        _require(attributes.get("pkce.code.challenge.method") == "S256", f"{client_id}: PKCE S256 is required")
        _require(defaults == ["basic", USER_CONTEXT_SCOPE], f"{client_id}: browser default scopes must be basic + cip.user.context")
        _require(TENANT_CLAIM not in claims and PROJECT_CLAIM not in claims, f"{client_id}: a browser client must not hardcode a tenant or project")
        _require(client.get("redirectUris") == entry["redirectUris"], f"{client_id}: redirect URIs drifted")
    else:
        _require(
            client.get("serviceAccountsEnabled") is True
            and client.get("standardFlowEnabled") is False
            and client.get("publicClient") is False,
            f"{client_id}: a service client must be confidential client_credentials only",
        )
        _require(client.get("redirectUris") == [] and client.get("webOrigins") == [], f"{client_id}: a service client has no origins")
        _require(attributes.get("client_credentials.use_refresh_token") == "false", f"{client_id}: service refresh tokens are prohibited")
        _require(USER_CONTEXT_SCOPE not in defaults + optional, f"{client_id}: a service client must not read user attributes")
        _require(defaults == ["basic"], f"{client_id}: service default scopes must be basic only")
        tenant = claims.get(TENANT_CLAIM)
        _require(
            tenant is not None
            and tenant.get("protocolMapper") == "oidc-hardcoded-claim-mapper"
            and tenant["config"].get("claim.value") == entry["tenant"]
            and tenant["config"].get("jsonType.label") == "String",
            f"{client_id}: tenant_id must be hardcoded to exactly {entry['tenant']}",
        )
        project = claims.get(PROJECT_CLAIM)
        if entry["projects"]:
            _require(
                project is not None
                and json.loads(project["config"].get("claim.value", "null")) == entry["projects"],
                f"{client_id}: project_ids must be hardcoded to the reviewed projects",
            )
        else:
            _require(project is None, f"{client_id}: a client without projects must not emit project_ids")


def validate_user_context_scope(scope: dict[str, Any]) -> None:
    _require(scope.get("name") == USER_CONTEXT_SCOPE, "user context scope name drifted")
    _require(scope.get("attributes", {}).get("include.in.token.scope") == "false", "cip.user.context must not appear in the scope claim")
    mappers = {m["name"]: m for m in scope.get("protocolMappers") or []}
    _require(sorted(mappers) == ["amr", "project-ids-from-admin-attribute", "tenant-id-from-admin-attribute"], "user context mappers drifted")
    for name, attribute, claim, multivalued in (
        ("tenant-id-from-admin-attribute", "codestra_tenant_id", TENANT_CLAIM, "false"),
        ("project-ids-from-admin-attribute", "codestra_project_ids", PROJECT_CLAIM, "true"),
    ):
        config = mappers[name]["config"]
        _require(
            mappers[name]["protocolMapper"] == "oidc-usermodel-attribute-mapper"
            and config.get("user.attribute") == attribute
            and config.get("claim.name") == claim
            and config.get("multivalued") == multivalued
            and config.get("aggregate.attrs") == "false",
            f"{name}: attribute mapper drifted",
        )
    _require(mappers["amr"]["protocolMapper"] == "oidc-amr-mapper", "amr mapper drifted")


def validate_user_profile(profile: dict[str, Any]) -> None:
    _require(profile.get("unmanagedAttributePolicy") in {"ADMIN_VIEW", "ADMIN_EDIT"}, "users must not edit unmanaged attributes")
    for attribute in profile.get("attributes") or []:
        name = attribute.get("name")
        _require(attribute.get("permissions") == ADMIN_ONLY, f"{name}: user-profile permissions must be admin-only")
        _require("required" not in attribute, f"{name}: the attribute must not be collected at registration")
        _require(attribute.get("validations", {}).get("pattern", {}).get("pattern") == IDENTIFIER.pattern, f"{name}: pattern drifted")


def validate_rendered(contract: dict[str, Any], rendered: dict[Path, dict[str, Any]]) -> None:
    validate_user_context_scope(rendered[DESIRED_ROOT / "client-scopes" / f"{USER_CONTEXT_SCOPE}.json"])
    validate_user_profile(rendered[DESIRED_ROOT / "user-profile" / "cip-tenant-attributes.json"])
    for entry in rendered_clients(contract):
        validate_client_document(contract, entry, rendered[DESIRED_ROOT / "clients" / f"{entry['clientId']}.json"])
    tenants_by_client = {
        entry["clientId"]: entry["tenant"] for entry in rendered_clients(contract) if entry["actorKind"] == "service"
    }
    _require(len(set(tenants_by_client.values())) >= 2, "certification needs service clients in at least two tenants")

    for scope in contract["productScopes"]:
        if scope["definitionOwner"] != "cip-tenant-identity":
            continue
        document = rendered[DESIRED_ROOT / "client-scopes" / f"{scope['name']}.json"]
        _require(document.get("protocolMappers") == [], f"{scope['name']}: a product scope must not add claims or audiences")
        _require(document["attributes"].get("include.in.token.scope") == "true", f"{scope['name']}: must appear in the scope claim")
    for role in contract["realmRoles"]:
        document = rendered[DESIRED_ROOT / "realm-roles" / f"{role['name']}.json"]
        _require(document.get("composite") is False and document.get("clientRole") is False, f"{role['name']}: roles are non-composite realm roles")
        _require(document["attributes"]["codestra.default_role"] == ["false"], f"{role['name']}: never a default role")
    mappings = rendered[DESIRED_ROOT / "scope-role-mappings" / "cip-product-scopes.json"]["scopeMappings"]
    _require([m["clientScope"] for m in mappings] == PRODUCT_SCOPES, "every product scope needs role scope-mappings")
    _require(all(m["roles"] for m in mappings), "an unmapped product scope would be issued to every principal")


# --- write / check ---------------------------------------------------------------------


def managed_paths() -> set[Path]:
    paths: set[Path] = set()
    for folder in ("client-scopes", "user-profile", "realm-roles", "scope-role-mappings", "clients"):
        paths.update((DESIRED_ROOT / folder).glob("*.json"))
    return paths


def write_desired_state(rendered: dict[Path, dict[str, Any]]) -> None:
    for stale in managed_paths() - set(rendered):
        stale.unlink()
    for path, document in sorted(rendered.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(rendered_bytes(document))


def check_desired_state(rendered: dict[Path, dict[str, Any]]) -> None:
    extra = sorted(relative(path) for path in managed_paths() - set(rendered))
    _require(not extra, f"unrendered desired-state files: {extra}")
    for path, document in sorted(rendered.items()):
        _require(path.is_file(), f"{relative(path)} is missing; run with --write")
        _require(
            path.read_bytes().replace(b"\r\n", b"\n") == rendered_bytes(document),
            f"{relative(path)} is stale; run with --write",
        )


# --- release evidence for gateway consumption --------------------------------------------

RELEASE_DIR = ROOT / "release" / "cip-tenant-identity"
PLAN_PATH = RELEASE_DIR / "keycloak-cip-tenant-identity-desired-state-plan.json"
GATEWAY_PATH = RELEASE_DIR / "keycloak-cip-gateway-identity-contract.v1.json"
MATRIX_PATH = ROOT / "config" / "certification" / "cip-tenant-token-matrix.v1.json"
STAGING_ACTION = "RECONCILE_IN_STAGING_ONLY_AUTHORIZED_MISSION"
FAILURE_CODES = {
    "algorithm": (401, "algorithm_or_kid_denied"),
    "issuer": (401, "invalid_token"),
    "audience": (401, "invalid_token"),
    "claims": (401, "invalid_token"),
    "expiry": (401, "invalid_token"),
    "azp": (403, "authorized_party_denied"),
    "actor": (403, "actor_kind_denied"),
    "mfa": (403, "mfa_required"),
    "scope": (403, "insufficient_scope"),
    "privilege": (403, "scope_denied"),
    "tenant": (403, "cross_tenant_denied"),
    "project": (403, "cross_project_denied"),
}


def checksum_path(path: Path) -> Path:
    return path.with_suffix(".sha256")


def release_bytes(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_plan(contract: dict[str, Any], rendered: dict[Path, dict[str, Any]]) -> dict[str, Any]:
    documents = dict(rendered)
    documents[CONTRACT_PATH] = contract
    source_files = []
    checksum_input = bytearray()
    for path, value in sorted(documents.items(), key=lambda item: relative(item[0])):
        payload = canonical(value)
        checksum_input.extend(relative(path).encode() + b"\0" + payload)
        source_files.append({"path": relative(path), "sha256": hashlib.sha256(payload).hexdigest()})

    def op(resource_type: str, resource_id: str, desired: Any, action: str = STAGING_ACTION) -> dict[str, Any]:
        return {"resourceType": resource_type, "resourceId": resource_id, "action": action, "desiredSha256": sha256_of(desired)}

    profile = rendered[DESIRED_ROOT / "user-profile" / "cip-tenant-attributes.json"]
    operations = [op("user-profile-attributes", "cip-tenant-attributes", profile)]
    operations.append(op("client-scope", USER_CONTEXT_SCOPE, rendered[DESIRED_ROOT / "client-scopes" / f"{USER_CONTEXT_SCOPE}.json"]))
    for scope in contract["productScopes"]:
        if scope["definitionOwner"] == "cip-tenant-identity":
            operations.append(op("client-scope", scope["name"], rendered[DESIRED_ROOT / "client-scopes" / f"{scope['name']}.json"]))
        else:
            frozen = load_json(ROOT / scope["keycloakDefinition"])
            operations.append(op("client-scope", scope["name"], frozen, "REFERENCE_FROZEN_DEFINITION_UNCHANGED"))
    for role in contract["realmRoles"]:
        operations.append(op("realm-role", role["name"], rendered[DESIRED_ROOT / "realm-roles" / f"{role['name']}.json"]))
    for mapping in rendered[DESIRED_ROOT / "scope-role-mappings" / "cip-product-scopes.json"]["scopeMappings"]:
        operations.append(op("client-scope-role-mappings", mapping["clientScope"], mapping["roles"]))
    for entry in rendered_clients(contract):
        client = rendered[DESIRED_ROOT / "clients" / f"{entry['clientId']}.json"]
        operations.append(op("client", entry["clientId"], client))
        operations.append(op("client-default-scope-links", entry["clientId"], client["defaultClientScopes"]))
        operations.append(op("client-optional-scope-links", entry["clientId"], client["optionalClientScopes"]))
        if entry["actorKind"] == "service":
            operations.append(op("service-account-realm-roles", entry["clientId"], entry["serviceAccountRealmRoles"]))
    for entry in contract["clients"]:
        if entry.get("rendered") is not True:
            operations.append(
                {"resourceType": "client", "resourceId": entry["clientId"], "action": entry["status"], "desiredSha256": None}
            )

    return {
        "schemaVersion": 1,
        "kind": "CodestraKeycloakCipTenantIdentityDesiredStatePlan",
        "environment": "staging",
        "realm": contract["realm"],
        "issuer": contract["issuers"]["staging"],
        "audience": contract["audience"],
        "middlewareRouteContract": contract["middlewareRouteContract"],
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
            "managedClientPolicyChanged": False,
            "frozenArtifactsModified": False,
        },
        "activationPreconditions": activation_preconditions(),
        "rollback": {
            "newClientSequence": ["disable", "verify no active use", "separately approve deletion"],
            "newClientScopeSequence": ["unlink from every client", "verify zero links", "separately approve deletion"],
            "roleScopeMappingSequence": [
                "remove the CIP role mappings from the client scope",
                "verify platform.command and platform.command.read definitions are byte-identical to the frozen files",
            ],
            "userProfileSequence": ["remove the two appended attributes only", "leave every other user-profile attribute unchanged"],
        },
    }


def activation_preconditions() -> list[str]:
    return [
        "protected merge SHA recorded and the plan regenerated from it",
        "staging-only reconciliation with the protected staging administrator credential after independent plan review",
        "the realm OTP execution configured so the AMR mapper emits mfa; until then every human CIP token fails closed on mfa",
        "Middleware registers the proposed platform-command-client members in config/control-plane-callers.v1.json",
        "Kong consumes this gateway contract by digest and reproduces every token-matrix verdict and status",
        "service client secrets handed to runners only through 0600 secret files resolved from secretReference",
        "production cip-portal remains blocked until its origin is reviewed; unbound scopes stay unbound until Middleware routes exist",
    ]


def build_gateway_contract(contract: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    from scripts import cip_tenant_token_matrix as matrix_cert  # lazy: the matrix module imports this one

    matrix = load_json(MATRIX_PATH)
    report = matrix_cert.validate_matrix(contract, matrix)
    production = load_json(PRODUCTION_ENDPOINTS)
    staging = load_json(STAGING_ENDPOINTS)

    def registry(environment: str) -> dict[str, Any]:
        entries = {}
        for entry in rendered_clients(contract):
            if entry["environment"] != environment:
                continue
            record: dict[str, Any] = {"actorKind": entry["actorKind"], "allowedScopes": entry["optionalClientScopes"]}
            if entry["actorKind"] == "service":
                record["tenant"] = entry["tenant"]
                record["projects"] = entry["projects"]
            entries[entry["clientId"]] = record
        return entries

    return {
        "schema": "codestra.keycloak.cip-gateway-identity-contract.v1",
        "status": contract["status"],
        "authority": {
            "repository": "ingtrader21-spec/Keycloak",
            "contract": relative(CONTRACT_PATH),
            "contractSha256": sha256_of(contract),
            "desiredStatePlan": relative(PLAN_PATH),
            "desiredStatePlanSha256": hashlib.sha256(release_bytes(plan)).hexdigest(),
            "configurationChecksum": plan["configurationChecksum"],
            "tokenMatrix": relative(MATRIX_PATH),
            "tokenMatrixSha256": sha256_of(matrix),
            "parityEvidence": contract["middlewareRouteContract"]["parityEvidence"],
            "parityEvidenceSha256": sha256_of(load_json(PARITY_RECORD)),
            "hashRule": (
                "contractSha256, tokenMatrixSha256 and parityEvidenceSha256 are sha256 over json.dumps(document, "
                "sort_keys=True, separators=(',', ':')).encode('utf-8'); desiredStatePlanSha256 is sha256 over the "
                "committed plan file bytes, as recorded in its .sha256 file"
            ),
            "consumptionRule": "Kong imports this file as data only, pins it by sha256 and never edits Keycloak desired state.",
        },
        "middlewareRouteContract": {
            key: contract["middlewareRouteContract"][key] for key in ("repository", "path", "sha256", "routeCount")
        },
        "environments": {
            "production": {
                "issuer": production["issuer"],
                "discoveryUrl": production["discoveryUrl"],
                "jwksUri": production["jwksUri"],
                "azpRegistry": registry("production"),
                "note": "No CIP client is active in production: every production CIP token is rejected authorized_party_denied.",
            },
            "staging": {
                "issuer": staging["issuer"],
                "discoveryUrl": staging["discoveryUrl"],
                "jwksUri": staging["jwksUri"],
                "azpRegistry": registry("staging"),
            },
        },
        "token": {
            "signingAlgorithms": contract["tokenPolicy"]["signingAlgorithms"],
            "audience": contract["audience"],
            "audienceRule": contract["tokenPolicy"]["audienceRule"],
            "maximumAccessTokenLifetimeSeconds": contract["tokenPolicy"]["maximumAccessTokenLifetimeSeconds"],
            "requiredClaims": contract["tokenPolicy"]["requiredClaims"],
            "scopeClaim": {"name": "scope", "format": contract["tokenPolicy"]["scopeClaimFormat"]},
            "consumerClaim": "azp",
            "subjectClaim": "sub",
            "tenantClaim": TENANT_CLAIM,
            "projectClaim": PROJECT_CLAIM,
            "actorKindClaim": ACTOR_CLAIM,
            "userMfaEvidence": contract["actorKinds"]["user"]["mfaEvidence"],
            "serviceMustNotCarryClaims": contract["actorKinds"]["service"]["mustNotCarryClaims"],
            "prohibitedTenantClaims": contract["prohibitedTenantClaims"],
            "prohibitedScopes": contract["prohibitedOnCipPrincipals"]["scopes"],
            "prohibitedRealmRoles": contract["prohibitedOnCipPrincipals"]["realmRoles"],
        },
        "tenantSelectors": contract["tenantSelectors"],
        "projectSelectors": contract["projectSelectors"],
        "productScopes": [
            {
                "name": scope["name"],
                "capability": scope["capability"],
                "actorKinds": scope["actorKinds"],
                "write": scope["write"],
                "routeBinding": {
                    "status": scope["routeBinding"]["status"],
                    "routes": [
                        {key: route[key] for key in ("method", "path", "operationId")}
                        for route in scope["routeBinding"]["routes"]
                    ],
                },
            }
            for scope in contract["productScopes"]
        ],
        "enforcementOrder": [
            "signature against the environment JWKS with an allowed algorithm (401 algorithm_or_kid_denied)",
            "exact issuer, audience contains middleware-api, iat <= now < exp, exp - iat <= 300, nbf <= now (401 invalid_token)",
            "azp is in the environment CIP azpRegistry (403 authorized_party_denied)",
            "codestra_actor_kind equals the registry actorKind; service tokens carry no amr (403 actor_kind_denied)",
            "user tokens carry amr containing mfa (403 mfa_required)",
            "no prohibited scope or role, and every token scope is in the registry allowedScopes (403 scope_denied)",
            "the route's required scope is present in the scope claim (403 insufficient_scope)",
            "exactly one valid tenant_id, no prohibited tenant claim, equal to the registry tenant for service accounts, and every tenant selector equals it (403 cross_tenant_denied)",
            "every project selector is in a non-empty project_ids; service project_ids equal the registry projects (403 cross_project_denied)",
            "forward the original bearer token; Middleware re-validates it and applies business entitlements",
        ],
        "routeRules": {
            "boundScopes": "On a BOUND route, keep the frozen per-route scope/azp checks from the Middleware authority and, when azp is a CIP registry client, add the CIP tenant/project/actor/MFA checks above.",
            "unboundScopes": "An UNBOUND product scope satisfies no route. Kong must not accept it anywhere until Middleware publishes a route and Keycloak repins this contract.",
            "platformCommandFamily": contract["platformCommandClientFamily"]["rule"],
        },
        "rateLimitKeys": {
            "primary": TENANT_CLAIM,
            "secondary": "the validated project selector, else the literal '-' (never an unvalidated header)",
            "rule": "Coarse per-tenant/project abuse limits only; business quotas and entitlements stay in Middleware.",
        },
        "failureCodes": {name: {"status": status, "error": error} for name, (status, error) in FAILURE_CODES.items()},
        "conformance": {
            "matrix": relative(MATRIX_PATH),
            "positiveCases": report["positiveCases"],
            "negativeCases": report["negativeCases"],
            "requiredDimensions": matrix["requiredDimensions"],
            "rule": "Kong must reproduce the verdict and HTTP status of every request-level and issued-token case; refused-issuance cases are enforced by Keycloak.",
        },
        "knownConsumerDrift": [
            {
                "owner": "Kong (I2)",
                "finding": "deploy/kong/scope-policy.lua and deploy/kong/control-plane.yml read claims.tenant; the codestra-authz plugin schema allows tenant_claim tenant or org_id.",
                "requiredChange": "Read tenant_id only for CIP routes and treat tenant, org_id, tid, organization and tenant_ids as prohibited on CIP tokens.",
            },
            {
                "owner": "Middleware (K1)",
                "finding": "authorize_tenant and tenants_from_claims also accept tenant_ids (up to 64 tenants); there is no project dimension and no MFA check.",
                "requiredChange": "None required for safety (CIP tokens never carry tenant_ids); project and MFA enforcement stay at the gateway until Middleware adopts them.",
            },
        ],
        "boundary": {
            "liveApplyAuthorized": False,
            "productionActivationAuthorized": False,
            "secretsIncluded": False,
            "tokensIncluded": False,
        },
        "activationPreconditions": activation_preconditions(),
    }


def build_release(contract: dict[str, Any], rendered: dict[Path, dict[str, Any]]) -> dict[Path, dict[str, Any]]:
    plan = build_plan(contract, rendered)
    return {PLAN_PATH: plan, GATEWAY_PATH: build_gateway_contract(contract, plan)}


def write_release(release: dict[Path, dict[str, Any]]) -> None:
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    for path, document in release.items():
        payload = release_bytes(document)
        path.write_bytes(payload)
        checksum_path(path).write_text(f"{hashlib.sha256(payload).hexdigest()}  {path.name}\n", encoding="utf-8")


def check_release(release: dict[Path, dict[str, Any]]) -> None:
    for path, document in release.items():
        expected = release_bytes(document)
        _require(path.is_file() and checksum_path(path).is_file(), f"{relative(path)} is missing; run with --write")
        _require(path.read_bytes().replace(b"\r\n", b"\n") == expected, f"{relative(path)} is stale; run with --write")
        checksum = checksum_path(path).read_text(encoding="utf-8").replace("\r\n", "\n")
        _require(checksum == f"{hashlib.sha256(expected).hexdigest()}  {path.name}\n", f"{relative(checksum_path(path))} is stale")


def build(contract_path: Path = CONTRACT_PATH) -> tuple[dict[str, Any], dict[Path, dict[str, Any]]]:
    contract = load_json(contract_path)
    validate_contract(contract)
    rendered = render_desired_state(contract)
    validate_rendered(contract, rendered)
    return contract, rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true", help="render the desired state from the contract")
    group.add_argument("--check", action="store_true", help="validate the contract and the committed desired state")
    args = parser.parse_args(argv)
    try:
        contract, rendered = build()
        if args.write:
            write_desired_state(rendered)
        check_desired_state(rendered)
        release = build_release(contract, rendered)
        if args.write:
            write_release(release)
        check_release(release)
    except (IdentityError, ValueError) as exc:
        print("CIP_TENANT_IDENTITY=FAIL")
        print(f"ERROR={exc}")
        return 1
    gateway = release[GATEWAY_PATH]
    clients = rendered_clients(contract)
    print("CIP_TENANT_IDENTITY=PASS")
    print(f"CIP_AUDIENCE={contract['audience']}")
    print(f"CIP_ROUTE_CONTRACT_SHA256={contract['middlewareRouteContract']['sha256']}")
    print(f"CIP_TENANT_CLAIM={TENANT_CLAIM}")
    print(f"CIP_RENDERED_CLIENTS={len(clients)}")
    print(f"CIP_USER_CLIENTS={sum(1 for c in clients if c['actorKind'] == 'user')}")
    print(f"CIP_SERVICE_CLIENTS={sum(1 for c in clients if c['actorKind'] == 'service')}")
    print(f"CIP_PRODUCT_SCOPES={len(contract['productScopes'])}")
    print(f"CIP_REALM_ROLES={len(contract['realmRoles'])}")
    print("CIP_UNMAPPED_PRODUCT_SCOPES=0")
    print(f"CIP_PLAN_OPERATIONS={len(release[PLAN_PATH]['operations'])}")
    print(f"CIP_CONFIGURATION_CHECKSUM={release[PLAN_PATH]['configurationChecksum']}")
    print(f"CIP_GATEWAY_CONTRACT_SHA256={hashlib.sha256(release_bytes(gateway)).hexdigest()}")
    print(f"CIP_TOKEN_MATRIX_CASES={gateway['conformance']['positiveCases']}+/{gateway['conformance']['negativeCases']}-")
    print("CIP_TENANT_BODY_SELF_ASSERTION=PROHIBITED")
    print("KEYCLOAK_LIVE_APPLY=PROHIBITED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
