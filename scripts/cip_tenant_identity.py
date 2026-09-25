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
    """Product scopes a client may request. Step 3 of the mission defines them."""
    return list(entry.get("optionalClientScopes") or [])


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


# --- write / check ---------------------------------------------------------------------


def managed_paths() -> set[Path]:
    paths: set[Path] = set()
    for folder in ("client-scopes", "user-profile", "clients"):
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
        _require(path.read_bytes() == rendered_bytes(document), f"{relative(path)} is stale; run with --write")


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
    except IdentityError as exc:
        print("CIP_TENANT_IDENTITY=FAIL")
        print(f"ERROR={exc}")
        return 1
    clients = rendered_clients(contract)
    print("CIP_TENANT_IDENTITY=PASS")
    print(f"CIP_AUDIENCE={contract['audience']}")
    print(f"CIP_ROUTE_CONTRACT_SHA256={contract['middlewareRouteContract']['sha256']}")
    print(f"CIP_TENANT_CLAIM={TENANT_CLAIM}")
    print(f"CIP_RENDERED_CLIENTS={len(clients)}")
    print(f"CIP_USER_CLIENTS={sum(1 for c in clients if c['actorKind'] == 'user')}")
    print(f"CIP_SERVICE_CLIENTS={sum(1 for c in clients if c['actorKind'] == 'service')}")
    print("CIP_TENANT_BODY_SELF_ASSERTION=PROHIBITED")
    print("KEYCLOAK_LIVE_APPLY=PROHIBITED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
