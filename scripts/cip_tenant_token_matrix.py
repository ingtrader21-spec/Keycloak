#!/usr/bin/env python3
"""CIP tenant token matrix: offline positive/negative certification of the CIP identity contract.

Two models, both derived only from ``config/desired-state/cip-tenant-identity``:

* ``issue_token`` simulates what Keycloak issues for a principal, client, grant
  and requested scopes (optional client scopes, role-gated scope issuance,
  admin-only tenant attributes, hardcoded service tenant).
* ``verify_request`` applies the checks a gateway and Middleware must make on
  every CIP request: signature algorithm, issuer, audience, expiry, azp
  registry, actor kind and MFA, scope, privilege, tenant and project, with
  body/header/query/path tenant values treated as selectors only.

The matrix in ``config/certification/cip-tenant-token-matrix.v1.json`` is
synthetic. It never mints a real token or contacts Keycloak. It is exported
unchanged for Kong so the gateway can run the same cases against its own
enforcement.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import cip_tenant_identity as cip  # noqa: E402

MATRIX_PATH = ROOT / "config" / "certification" / "cip-tenant-token-matrix.v1.json"
REQUIRED_DIMENSIONS = [
    "issuer",
    "audience",
    "azp",
    "scope",
    "tenant",
    "expiry",
    "service-account-misuse",
    "privilege-escalation",
]
EXTRA_DIMENSIONS = ["project", "mfa", "algorithm"]
FAILURES = {
    "algorithm",
    "issuer",
    "audience",
    "expiry",
    "claims",
    "azp",
    "actor",
    "mfa",
    "scope",
    "privilege",
    "tenant",
    "project",
    "grant",
}
UNAUTHENTICATED = {"algorithm", "issuer", "audience", "expiry", "claims"}
MINIMUM_NEGATIVES_PER_REQUIRED_DIMENSION = 3
DELETE = {"$delete": True}


class MatrixError(ValueError):
    """The matrix is malformed or a case does not produce its expected verdict."""


# --- desired state views -------------------------------------------------------------


def registry(contract: dict[str, Any], environment: str) -> dict[str, dict[str, Any]]:
    """The CIP azp registry for one environment: only rendered clients of that environment."""
    return {
        entry["clientId"]: entry
        for entry in cip.rendered_clients(contract)
        if entry["environment"] == environment
    }


def access_routes() -> dict[tuple[str, str], dict[str, Any]]:
    access = cip.load_json(cip.ACCESS_V3)
    return {(route["method"], route["path"]): route for route in access["routes"]}


def _scopes(value: Any) -> list[str] | None:
    if not isinstance(value, str):
        return None
    return [part for part in value.split(" ") if part]


def _audiences(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def _dig(document: Any, dotted: str) -> Any:
    node = document
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


# --- Keycloak issuance model -----------------------------------------------------------


def issue_token(contract: dict[str, Any], fixture: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str], str | None]:
    """Return (claims, issuedScopes, refusal). A refusal means Keycloak issues no token."""
    environment = fixture["environment"]
    clients = registry(contract, environment)
    client = clients.get(fixture["clientId"])
    if client is None:
        return None, [], "azp"
    principal = fixture["principal"]
    grant = fixture.get("grant") or {}
    kind = client["actorKind"]
    if principal.get("actorKind") != kind:
        return None, [], "grant"

    if kind == "service":
        if grant.get("type") != "client_credentials":
            return None, [], "grant"
        roles = set(client["serviceAccountRealmRoles"])
        tenant = client["tenant"]
        projects = list(client["projects"])
        amr = None
    else:
        if grant.get("type") != "authorization_code" or grant.get("pkce") != "S256":
            return None, [], "grant"
        roles = set(principal.get("realmRoles") or [])
        attributes = principal.get("attributes") or {}

        def admin_value(name: str) -> Any:
            # The user profile makes these attributes admin-edit only: a value a user tries to set
            # is refused by Keycloak and never stored, so it can never reach a token.
            entry = attributes.get(name)
            if isinstance(entry, dict) and entry.get("setBy") == "admin":
                return entry.get("value")
            return None

        tenant = admin_value("codestra_tenant_id")
        projects = admin_value("codestra_project_ids")
        amr = list(principal.get("authenticationMethods") or [])

    mappings = cip.scope_role_mappings(contract)
    issued: list[str] = []
    for scope in fixture.get("requestedScopes") or []:
        if scope not in client["optionalClientScopes"]:
            continue  # not linked to the client: Keycloak ignores it
        permitted = mappings.get(scope) or []
        if permitted and not roles & set(permitted):
            continue  # role-gated client scope: the principal holds none of its roles
        if scope not in issued:
            issued.append(scope)

    now = fixture["now"]
    claims: dict[str, Any] = {
        "iss": contract["issuers"][environment],
        "sub": principal.get("subject") or f"service-account-{client['clientId']}",
        "aud": contract["audience"],
        "azp": client["clientId"],
        "iat": now,
        "exp": now + contract["tokenPolicy"]["maximumAccessTokenLifetimeSeconds"],
        "jti": f"synthetic-{fixture['clientId']}-{now}",
        "scope": " ".join(issued),
        cip.ACTOR_CLAIM: kind,
    }
    if tenant is not None:
        claims[cip.TENANT_CLAIM] = tenant
    if projects:
        claims[cip.PROJECT_CLAIM] = list(projects)
    if amr is not None:
        claims["amr"] = amr
    return claims, issued, None


# --- gateway / Middleware verification model ---------------------------------------------


def _header(headers: dict[str, Any], name: str) -> Any:
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return value
    return None


def _selector_values(block: dict[str, Any], request: dict[str, Any]) -> list[Any]:
    values: list[Any] = []
    for name in block["headers"]:
        value = _header(request.get("headers") or {}, name)
        if value is not None:
            values.append(value)
    for dotted in block["bodyFields"]:
        value = _dig(request.get("body") or {}, dotted)
        if value is not None:
            values.append(value)
    for key, source in (("queryParameters", "query"), ("pathParameters", "pathParams")):
        for name in block[key]:
            value = (request.get(source) or {}).get(name)
            if value is not None:
                values.append(value)
    return values


def verify_request(contract: dict[str, Any], fixture: dict[str, Any]) -> list[str]:
    """Return the sorted failure categories for one request; empty means ACCEPT."""
    failures: set[str] = set()
    environment = fixture["environment"]
    header = (fixture.get("token") or {}).get("header") or {}
    claims = (fixture.get("token") or {}).get("claims") or {}
    request = fixture.get("request") or {}
    now = fixture["now"]
    policy = contract["tokenPolicy"]

    if header.get("alg") not in policy["signingAlgorithms"]:
        failures.add("algorithm")
    if claims.get("iss") != contract["issuers"].get(environment):
        failures.add("issuer")
    if contract["audience"] not in _audiences(claims.get("aud")):
        failures.add("audience")

    iat, exp, nbf = claims.get("iat"), claims.get("exp"), claims.get("nbf")
    if (
        not isinstance(iat, int)
        or not isinstance(exp, int)
        or isinstance(iat, bool)
        or isinstance(exp, bool)
        or iat > now
        or exp <= now
        or exp <= iat
        or exp - iat > policy["maximumAccessTokenLifetimeSeconds"]
        or (nbf is not None and (not isinstance(nbf, int) or nbf > now))
    ):
        failures.add("expiry")
    for claim in ("sub", "jti"):
        if not isinstance(claims.get(claim), str) or not claims[claim]:
            failures.add("claims")

    # azp registry and actor kind
    clients = registry(contract, environment)
    azp = claims.get("azp")
    client = clients.get(azp) if isinstance(azp, str) else None
    if client is None:
        failures.add("azp")
    actor = claims.get(cip.ACTOR_CLAIM)
    if actor not in cip.ACTOR_KINDS:
        failures.add("actor")
    if client is not None:
        if actor != client["actorKind"]:
            failures.add("actor")
        if client["actorKind"] == "service" and "amr" in claims:
            failures.add("actor")
        if client["actorKind"] == "user" and actor == "user":
            amr = claims.get("amr")
            if not isinstance(amr, list) or contract["actorKinds"]["user"]["mfaEvidence"]["mustContain"] not in amr:
                failures.add("mfa")

    # scope and privilege
    scopes = _scopes(claims.get("scope"))
    required = request.get("requiredScope")
    if scopes is None or any("*" in scope for scope in scopes) or required not in (scopes or []):
        failures.add("scope")
    prohibited = set(contract["prohibitedOnCipPrincipals"]["scopes"])
    if scopes and set(scopes) & prohibited:
        failures.add("privilege")
    if client is not None and scopes and not set(scopes) <= set(client["optionalClientScopes"]):
        failures.add("privilege")
    roles = set(_dig(claims, "realm_access.roles") or []) | set(claims.get("roles") or [])
    if roles & set(contract["prohibitedOnCipPrincipals"]["realmRoles"]):
        failures.add("privilege")

    # tenant: exactly one authoritative claim; request values are selectors only
    tenant = claims.get(cip.TENANT_CLAIM)
    if any(name in claims for name in contract["prohibitedTenantClaims"]):
        failures.add("tenant")
    if not isinstance(tenant, str) or not cip.IDENTIFIER.match(tenant):
        failures.add("tenant")
        tenant = None
    if client is not None and client["actorKind"] == "service" and tenant != client["tenant"]:
        failures.add("tenant")
    for selector in _selector_values(contract["tenantSelectors"], request):
        if selector != tenant:
            failures.add("tenant")

    # project: narrowing only
    projects = claims.get(cip.PROJECT_CLAIM)
    if projects is not None and (
        not isinstance(projects, list)
        or len(projects) > cip.MAX_PROJECTS
        or not all(isinstance(p, str) and cip.IDENTIFIER.match(p) for p in projects)
    ):
        failures.add("project")
        projects = None
    if client is not None and client["actorKind"] == "service" and (projects or []) != client["projects"]:
        failures.add("project")
    for selector in _selector_values(contract["projectSelectors"], request):
        if not projects or selector not in projects:
            failures.add("project")

    return sorted(failures)


def http_status(failures: list[str]) -> int:
    if not failures:
        return 200
    return 401 if UNAUTHENTICATED & set(failures) else 403


# --- matrix ----------------------------------------------------------------------------


def _apply_mutation(target: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    node: Any = target
    for part in parts[:-1]:
        if not isinstance(node, dict):
            raise MatrixError(f"mutation path is not writable: {dotted}")
        node = node.setdefault(part, {})
    if not isinstance(node, dict):
        raise MatrixError(f"mutation path is not writable: {dotted}")
    if value == DELETE:
        if parts[-1] not in node:
            raise MatrixError(f"mutation deletes a missing key: {dotted}")
        del node[parts[-1]]
    else:
        node[parts[-1]] = copy.deepcopy(value)


def validate_request_route(contract: dict[str, Any], request: dict[str, Any], routes: dict[tuple[str, str], dict[str, Any]], case_id: str) -> None:
    """A fixture may only exercise real Middleware routes or declared unbound product capabilities."""
    method, path, required = request.get("method"), request.get("path"), request.get("requiredScope")
    if isinstance(path, str) and path.startswith("unbound:"):
        unbound = {
            scope["name"]
            for scope in contract["productScopes"]
            if scope["routeBinding"]["status"] == "UNBOUND_PENDING_MIDDLEWARE_ROUTE"
        }
        if path != f"unbound:{required}" or required not in unbound:
            raise MatrixError(f"{case_id}: unbound request must name an unbound product scope")
        return
    route = routes.get((method, path))
    if route is None:
        raise MatrixError(f"{case_id}: {method} {path} is not a Middleware route")
    if route.get("requiredScope") != required:
        raise MatrixError(f"{case_id}: {method} {path} requires {route.get('requiredScope')}, not {required}")


def run_case(contract: dict[str, Any], matrix: dict[str, Any], case: dict[str, Any], routes: dict[tuple[str, str], dict[str, Any]]) -> dict[str, Any]:
    case_id = str(case.get("id") or "")
    fixture_name = case.get("fixture")
    fixtures = matrix["fixtures"]
    if fixture_name not in fixtures:
        raise MatrixError(f"{case_id}: missing fixture {fixture_name}")
    fixture = copy.deepcopy(fixtures[fixture_name])
    for dotted, value in (case.get("mutations") or {}).items():
        _apply_mutation(fixture, str(dotted), value)
    validate_request_route(contract, fixture.get("request") or {}, routes, case_id)

    issued: list[str] | None = None
    if fixture.get("kind") == "issuance":
        claims, issued, refusal = issue_token(contract, fixture)
        if refusal is not None:
            return {"id": case_id, "verdict": "REJECT", "failures": [refusal], "status": None, "tokenIssued": False, "issuedScopes": []}
        fixture["token"] = {"header": {"alg": "RS256", "typ": "JWT"}, "claims": claims}
        for dotted, value in (case.get("requestMutations") or {}).items():
            _apply_mutation(fixture, str(dotted), value)
    elif fixture.get("kind") != "request":
        raise MatrixError(f"{case_id}: fixture kind must be request or issuance")

    failures = verify_request(contract, fixture)
    return {
        "id": case_id,
        "verdict": "REJECT" if failures else "ACCEPT",
        "failures": failures,
        "status": http_status(failures),
        "tokenIssued": True,
        "issuedScopes": issued,
    }


def validate_matrix(contract: dict[str, Any], matrix: dict[str, Any]) -> dict[str, Any]:
    if matrix.get("schemaVersion") != 1 or matrix.get("kind") != "CodestraCipTenantTokenMatrix":
        raise MatrixError("matrix kind or schemaVersion is wrong")
    if matrix.get("requiredDimensions") != REQUIRED_DIMENSIONS:
        raise MatrixError(f"requiredDimensions must be {REQUIRED_DIMENSIONS}")
    if matrix.get("contract") != cip.relative(cip.CONTRACT_PATH):
        raise MatrixError("matrix must point at the CIP tenant identity contract")
    cip.assert_no_secret(matrix, "matrix")
    dimensions = REQUIRED_DIMENSIONS + EXTRA_DIMENSIONS
    routes = access_routes()
    seen = {dimension: {"ACCEPT": 0, "REJECT": 0} for dimension in dimensions}
    ids: set[str] = set()
    results = []
    for case in matrix.get("cases") or []:
        case_id = str(case.get("id") or "")
        if not case_id or case_id in ids:
            raise MatrixError(f"case id is empty or duplicated: {case_id!r}")
        ids.add(case_id)
        dimension = case.get("dimension")
        if dimension not in seen:
            raise MatrixError(f"{case_id}: unknown dimension {dimension}")
        expect = case.get("expect")
        if expect not in {"ACCEPT", "REJECT"}:
            raise MatrixError(f"{case_id}: expect must be ACCEPT or REJECT")
        result = run_case(contract, matrix, case, routes)
        if result["verdict"] != expect:
            raise MatrixError(f"{case_id}: expected {expect}, got {result['verdict']} {result['failures']}")
        if expect == "REJECT":
            must_fail = case.get("mustFail")
            if must_fail not in FAILURES or must_fail not in result["failures"]:
                raise MatrixError(f"{case_id}: must fail {must_fail!r}, got {result['failures']}")
        if "expectedStatus" in case and case["expectedStatus"] != result["status"]:
            raise MatrixError(f"{case_id}: expected HTTP {case['expectedStatus']}, got {result['status']}")
        if "expectTokenIssued" in case and case["expectTokenIssued"] != result["tokenIssued"]:
            raise MatrixError(f"{case_id}: token issuance expectation failed")
        if "expectIssuedScopes" in case and case["expectIssuedScopes"] != result["issuedScopes"]:
            raise MatrixError(f"{case_id}: expected issued scopes {case['expectIssuedScopes']}, got {result['issuedScopes']}")
        seen[dimension][expect] += 1
        results.append({**result, "dimension": dimension, "expectedStatus": case.get("expectedStatus")})

    for dimension in dimensions:
        if not seen[dimension]["ACCEPT"] or not seen[dimension]["REJECT"]:
            raise MatrixError(f"dimension {dimension} lacks positive and negative coverage")
    for dimension in REQUIRED_DIMENSIONS:
        if seen[dimension]["REJECT"] < MINIMUM_NEGATIVES_PER_REQUIRED_DIMENSION:
            raise MatrixError(f"dimension {dimension} needs at least {MINIMUM_NEGATIVES_PER_REQUIRED_DIMENSION} negative cases")
    return {
        "verdict": "PASS",
        "dimensions": seen,
        "positiveCases": sum(d["ACCEPT"] for d in seen.values()),
        "negativeCases": sum(d["REJECT"] for d in seen.values()),
        "cases": results,
    }


def certify(matrix_path: Path = MATRIX_PATH) -> dict[str, Any]:
    contract, _rendered = cip.build()
    matrix = cip.load_json(matrix_path)
    return validate_matrix(contract, matrix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--matrix", type=Path, default=MATRIX_PATH)
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    try:
        report = certify(args.matrix.resolve())
    except (MatrixError, cip.IdentityError) as exc:
        print("CIP_TENANT_TOKEN_MATRIX=FAIL")
        print(f"ERROR={exc}")
        return 1
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    print("CIP_TENANT_TOKEN_MATRIX=PASS")
    print(f"CIP_TOKEN_MATRIX_POSITIVE={report['positiveCases']}")
    print(f"CIP_TOKEN_MATRIX_NEGATIVE={report['negativeCases']}")
    for dimension, counts in report["dimensions"].items():
        print(f"CIP_TOKEN_MATRIX_{dimension.upper().replace('-', '_')}={counts['ACCEPT']}+/{counts['REJECT']}-")
    print("CIP_TENANT_BODY_SELF_ASSERTION=REJECTED")
    print("KEYCLOAK_LIVE_APPLY=PROHIBITED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
