#!/usr/bin/env python3
"""PAS-157 caller classification and offline token-policy certification.

This validator is intentionally repository-only. It does not create Keycloak
clients, mint tokens, call a realm, or authorize a live apply. It proves that
Middleware caller selectors have an explicit human/service boundary and that
the checked-in positive/negative token matrix covers the required rejection
dimensions.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DESIRED_ROOT = ROOT / "config" / "desired-state" / "caller-token-certification"
AUTHORITY_PATH = DESIRED_ROOT / "caller-identity-authority.v1.json"
MATRIX_PATH = DESIRED_ROOT / "token-certification-matrix.v1.json"
DEFAULT_ROUTE_CONTRACT = (
    ROOT
    / "config"
    / "desired-state"
    / "edge-integration-certification"
    / "middleware-public-api-route-contract.v2.json"
)

CALLER_CLASSES = {
    "concrete_service_client",
    "human_client",
    "client_family",
    "symbolic_selector",
}
ACTOR_KINDS = {"service", "user"}
EXPECTED_DIMENSIONS = {
    "issuer",
    "audience",
    "azp",
    "tenant",
    "scope",
    "role",
    "expiry",
    "replay",
}


class CertificationError(ValueError):
    """A checked-in authority or token case violates PAS-157."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CertificationError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CertificationError(f"{path} must contain a JSON object")
    return value


def canonical_route_digest(document: dict[str, Any]) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _as_string_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {part for part in value.split() if part}
    if isinstance(value, list):
        return {str(part) for part in value if str(part)}
    return {str(value)}


def route_callers(route_contract: dict[str, Any]) -> set[str]:
    callers: set[str] = set()
    routes = route_contract.get("routes")
    if not isinstance(routes, list):
        raise CertificationError("route contract routes must be a list")
    for index, row in enumerate(routes):
        if not isinstance(row, dict):
            raise CertificationError(f"route row {index} must be an object")
        raw = row.get("calling_client")
        if isinstance(raw, list):
            callers.update(str(value) for value in raw if str(value))
        elif raw is not None and str(raw):
            callers.add(str(raw))
        extra = row.get("calling_clients")
        if isinstance(extra, list):
            callers.update(str(value) for value in extra if str(value))
    return callers


def canonical_caller(authority: dict[str, Any], caller: str) -> str:
    aliases = authority.get("aliases") or {}
    if not isinstance(aliases, dict):
        raise CertificationError("authority aliases must be an object")
    return str(aliases.get(caller, caller))


def _validate_no_wildcards(values: Iterable[Any], location: str) -> None:
    for value in values:
        text = str(value)
        if "*" in text:
            raise CertificationError(f"wildcard is prohibited at {location}: {text}")


def validate_authority_shape(authority: dict[str, Any]) -> None:
    if authority.get("schemaVersion") != 1:
        raise CertificationError("authority schemaVersion must be 1")
    if authority.get("kind") != "CodestraKeycloakCallerIdentityAuthority":
        raise CertificationError("authority kind is invalid")

    policy = authority.get("tokenPolicy")
    if not isinstance(policy, dict):
        raise CertificationError("authority tokenPolicy must be an object")
    if policy.get("dirtyDesktopAutoGrantAuthorized") is not False:
        raise CertificationError("dirty desktop client auto-grant must remain prohibited")
    if policy.get("wildcardCallerSelectorsAllowed") is not False:
        raise CertificationError("wildcard caller selectors must remain prohibited")
    if policy.get("wildcardScopesAllowed") is not False:
        raise CertificationError("wildcard scopes must remain prohibited")
    if policy.get("serviceGrantType") != "client_credentials":
        raise CertificationError("service grant must be client_credentials")
    if policy.get("humanGrantType") != "authorization_code":
        raise CertificationError("human grant must be authorization_code")
    if policy.get("humanPkceRequired") is not True:
        raise CertificationError("human PKCE must be required")
    if policy.get("privilegedHumanMfaRequired") is not True:
        raise CertificationError("privileged human MFA must be required")
    maximum = policy.get("maximumAccessTokenLifetimeSeconds")
    if not isinstance(maximum, int) or maximum <= 0 or maximum > 300:
        raise CertificationError("maximum access-token lifetime must be <= 300 seconds")

    protected = set(policy.get("protectedUngrantableClientIds") or [])
    if "codestra-agent-desktop" not in protected:
        raise CertificationError("codestra-agent-desktop must remain protected from automatic grant")

    privileged_scopes = policy.get("privilegedScopes") or []
    privileged_roles = policy.get("privilegedRoles") or []
    _validate_no_wildcards(privileged_scopes, "tokenPolicy.privilegedScopes")
    _validate_no_wildcards(privileged_roles, "tokenPolicy.privilegedRoles")

    callers = authority.get("callers")
    if not isinstance(callers, dict) or not callers:
        raise CertificationError("authority callers must be a non-empty object")

    required = set(authority.get("requiredKnownCallers") or [])
    missing_required = sorted(required - set(callers))
    if missing_required:
        raise CertificationError(f"known caller vocabulary is unresolved: {missing_required}")

    aliases = authority.get("aliases") or {}
    if aliases.get("platform-command-family") != "platform-command-client":
        raise CertificationError("platform-command-family must resolve to platform-command-client")

    for caller, rule in sorted(callers.items()):
        if not isinstance(rule, dict):
            raise CertificationError(f"caller {caller} rule must be an object")
        klass = rule.get("class")
        if klass not in CALLER_CLASSES:
            raise CertificationError(f"caller {caller} has invalid class {klass!r}")
        actors = rule.get("actorKinds")
        grants = rule.get("grantTypes")
        auth_modes = rule.get("authModes")
        audiences = rule.get("audiences")
        if not isinstance(actors, list) or any(actor not in ACTOR_KINDS for actor in actors):
            raise CertificationError(f"caller {caller} has invalid actorKinds")
        if not isinstance(grants, list) or not isinstance(auth_modes, list) or not isinstance(audiences, list):
            raise CertificationError(f"caller {caller} grants/authModes/audiences must be lists")
        _validate_no_wildcards(grants, f"callers.{caller}.grantTypes")
        _validate_no_wildcards(auth_modes, f"callers.{caller}.authModes")
        _validate_no_wildcards(audiences, f"callers.{caller}.audiences")
        if rule.get("wildcardsAllowed") is not False:
            raise CertificationError(f"caller {caller} must explicitly prohibit wildcards")
        if caller == "none":
            if actors or grants or auth_modes != ["deny"]:
                raise CertificationError("none must remain a deny-only symbolic selector")
            continue

        lifetime = rule.get("maxAccessTokenLifetimeSeconds")
        if not isinstance(lifetime, int) or lifetime <= 0 or lifetime > maximum:
            raise CertificationError(f"caller {caller} access-token lifetime exceeds policy")

        if klass == "concrete_service_client":
            if actors != ["service"] or grants != ["client_credentials"]:
                raise CertificationError(
                    f"service client {caller} must be service + client_credentials only"
                )
        if klass == "human_client":
            if actors != ["user"] or grants != ["authorization_code"]:
                raise CertificationError(
                    f"human client {caller} must be user + authorization_code only"
                )
            if rule.get("humanPkceRequired") is not True:
                raise CertificationError(f"human client {caller} must require PKCE")
            if rule.get("humanMfaPolicy") not in {"required", "required-for-privileged"}:
                raise CertificationError(f"human client {caller} must define an MFA policy")
        if klass == "client_family" and rule.get("familyMembershipRequired") is not True:
            raise CertificationError(f"client family {caller} must require reviewed membership")

        if "service" in actors and "client_credentials" not in grants:
            raise CertificationError(f"service-capable caller {caller} lacks client_credentials")
        if "user" in actors:
            if "authorization_code" not in grants:
                raise CertificationError(f"user-capable caller {caller} lacks authorization_code")
            if rule.get("humanPkceRequired") is not True:
                raise CertificationError(f"user-capable caller {caller} must require PKCE")
            if rule.get("humanMfaPolicy") not in {"required", "required-for-privileged"}:
                raise CertificationError(f"user-capable caller {caller} must define MFA handling")

    for caller, rule in callers.items():
        members = set(rule.get("concreteMembers") or [])
        forbidden = protected & members
        if forbidden:
            raise CertificationError(
                f"protected desktop client must not be auto-enrolled in {caller}: {sorted(forbidden)}"
            )

    replay = callers["platform-command-client"].get("replayRequirements") or {}
    exact_replay = {
        "scope": "platform.command.replay",
        "role": "platform-operator",
        "mfaRequired": True,
        "actorKind": "user",
        "grantType": "authorization_code",
        "pkceRequired": True,
    }
    if replay != exact_replay:
        raise CertificationError("platform-command-client replay requirements are incomplete")


def validate_routes(
    authority: dict[str, Any], route_contract: dict[str, Any]
) -> dict[str, Any]:
    callers = authority["callers"]
    unknown: set[str] = set()
    service_or_user_service = 0
    service_or_user_human = 0
    service_or_user_routes = 0

    for index, row in enumerate(route_contract.get("routes") or []):
        raw = row.get("calling_client")
        row_callers = raw if isinstance(raw, list) else [raw]
        if isinstance(row.get("calling_clients"), list):
            row_callers = list(row_callers) + list(row["calling_clients"])

        for caller_value in row_callers:
            if caller_value is None:
                continue
            logical = str(caller_value)
            resolved = canonical_caller(authority, logical)
            rule = callers.get(resolved)
            if not isinstance(rule, dict):
                unknown.add(logical)
                continue

            auth = row.get("auth")
            audience = row.get("audience")
            if auth not in rule.get("authModes", []):
                raise CertificationError(
                    f"route {index} caller {logical} auth {auth!r} is outside caller authority"
                )
            if audience not in rule.get("audiences", []):
                raise CertificationError(
                    f"route {index} caller {logical} audience {audience!r} is outside caller authority"
                )

            if auth == "service-or-user-jwt":
                service_or_user_routes += 1
                actors = set(rule.get("actorKinds") or [])
                if "service" in actors:
                    service_or_user_service += 1
                if "user" in actors:
                    service_or_user_human += 1

    if unknown:
        raise CertificationError(
            "UNKNOWN_CALLER_IDENTITIES="
            + str(len(unknown))
            + " "
            + ",".join(sorted(unknown))
        )

    if service_or_user_routes and not (
        service_or_user_service > 0 and service_or_user_human > 0
    ):
        raise CertificationError(
            "service-or-user-jwt must have explicit service and human caller boundaries"
        )

    return {
        "uniqueCallerSelectors": len(route_callers(route_contract)),
        "unknownCallerIdentities": 0,
        "serviceOrUserRoutes": service_or_user_routes,
        "serviceOrUserServiceBindings": service_or_user_service,
        "serviceOrUserHumanBindings": service_or_user_human,
    }


def _walk_default_scopes(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"defaultClientScopes", "defaultDefaultClientScopes"}:
                if isinstance(child, list):
                    for item in child:
                        yield str(item)
            yield from _walk_default_scopes(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_default_scopes(child)


def privileged_default_scope_leaks(authority: dict[str, Any]) -> list[str]:
    privileged = set(authority["tokenPolicy"]["privilegedScopes"])
    leaks: list[str] = []
    config_root = ROOT / "config"
    for path in sorted(config_root.rglob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        leaked = sorted(privileged & set(_walk_default_scopes(document)))
        if leaked:
            leaks.append(f"{path.relative_to(ROOT).as_posix()}:{','.join(leaked)}")
    return leaks


def _set_dotted(target: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    node: Any = target
    for part in parts[:-1]:
        if not isinstance(node, dict) or part not in node:
            raise CertificationError(f"matrix mutation path not found: {dotted}")
        node = node[part]
    if not isinstance(node, dict):
        raise CertificationError(f"matrix mutation path not writable: {dotted}")
    node[parts[-1]] = copy.deepcopy(value)


def evaluate_token_fixture(
    authority: dict[str, Any], fixture: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    policy = authority["tokenPolicy"]
    caller = canonical_caller(authority, str(fixture.get("caller")))
    rule = authority["callers"].get(caller)
    if not isinstance(rule, dict):
        return ["azp"]

    claims = fixture.get("claims") or {}
    grant = fixture.get("grant") or {}
    actor = fixture.get("actorKind")
    now = fixture.get("now")
    maximum = int(policy["maximumAccessTokenLifetimeSeconds"])

    if claims.get("iss") != policy["stagingIssuer"]:
        failures.append("issuer")

    aud = _as_string_set(claims.get("aud"))
    if not aud or not aud.intersection(set(rule.get("audiences") or [])):
        failures.append("audience")

    azp = str(claims.get("azp") or "")
    resolved_azp = str(fixture.get("resolvedAzp") or "")
    klass = rule.get("class")
    if not azp or azp != resolved_azp:
        failures.append("azp")
    elif klass in {"client_family", "symbolic_selector"}:
        if rule.get("familyMembershipRequired") and fixture.get("familyMembershipVerified") is not True:
            failures.append("azp")
        if azp == caller:
            failures.append("azp")
    elif klass == "concrete_service_client" and azp != caller:
        failures.append("azp")

    if claims.get("tenant_id") != fixture.get("expectedTenant"):
        failures.append("tenant")

    scopes = _as_string_set(claims.get("scope"))
    required_scope = fixture.get("requiredScope")
    if required_scope and required_scope not in scopes:
        failures.append("scope")
    if any("*" in scope for scope in scopes):
        failures.append("scope")

    roles = set(((claims.get("realm_access") or {}).get("roles") or []))
    required_role = fixture.get("requiredRole")
    if required_role and required_role not in roles:
        failures.append("role")

    iat = claims.get("iat")
    exp = claims.get("exp")
    if (
        not isinstance(now, int)
        or not isinstance(iat, int)
        or not isinstance(exp, int)
        or iat > now
        or exp <= now
        or exp <= iat
        or exp - iat > maximum
    ):
        failures.append("expiry")

    actors = set(rule.get("actorKinds") or [])
    grants = set(rule.get("grantTypes") or [])
    grant_type = grant.get("type")
    if actor not in actors or grant_type not in grants:
        failures.append("grant")
    if actor == "service" and grant_type != "client_credentials":
        failures.append("grant")
    if actor == "user":
        if grant_type != "authorization_code":
            failures.append("grant")
        if rule.get("humanPkceRequired") and grant.get("pkce") is not True:
            failures.append("pkce")
        mfa_policy = rule.get("humanMfaPolicy")
        requires_mfa = mfa_policy == "required" or (
            mfa_policy == "required-for-privileged" and fixture.get("privileged") is True
        )
        if requires_mfa and "mfa" not in _as_string_set(claims.get("amr")):
            failures.append("mfa")

    if fixture.get("replay") is True:
        replay = rule.get("replayRequirements") or {}
        replay_ok = (
            caller == "platform-command-client"
            and actor == replay.get("actorKind") == "user"
            and grant_type == replay.get("grantType") == "authorization_code"
            and grant.get("pkce") is replay.get("pkceRequired") is True
            and replay.get("scope") in scopes
            and replay.get("role") in roles
            and (not replay.get("mfaRequired") or "mfa" in _as_string_set(claims.get("amr")))
        )
        if not replay_ok:
            failures.append("replay")

    return sorted(set(failures))


def validate_token_matrix(
    authority: dict[str, Any], matrix: dict[str, Any]
) -> dict[str, Any]:
    if matrix.get("schemaVersion") != 1:
        raise CertificationError("token matrix schemaVersion must be 1")
    if matrix.get("kind") != "CodestraCallerTokenCertificationMatrix":
        raise CertificationError("token matrix kind is invalid")

    required = set(matrix.get("requiredDimensions") or [])
    if required != EXPECTED_DIMENSIONS:
        raise CertificationError(
            f"token matrix dimensions must equal {sorted(EXPECTED_DIMENSIONS)}"
        )

    fixtures = matrix.get("fixtures")
    cases = matrix.get("cases")
    if not isinstance(fixtures, dict) or not isinstance(cases, list):
        raise CertificationError("token matrix fixtures/cases are invalid")

    seen: dict[str, set[str]] = {dimension: set() for dimension in EXPECTED_DIMENSIONS}
    accepted = 0
    rejected = 0
    results: list[dict[str, Any]] = []

    for case in cases:
        if not isinstance(case, dict):
            raise CertificationError("token matrix case must be an object")
        case_id = str(case.get("id") or "")
        dimension = str(case.get("dimension") or "")
        expect = str(case.get("expect") or "")
        fixture_name = str(case.get("fixture") or "")
        if dimension not in EXPECTED_DIMENSIONS:
            raise CertificationError(f"case {case_id} has unknown dimension {dimension}")
        if expect not in {"ACCEPT", "REJECT"}:
            raise CertificationError(f"case {case_id} has invalid expectation")
        if fixture_name not in fixtures:
            raise CertificationError(f"case {case_id} references missing fixture {fixture_name}")

        fixture = copy.deepcopy(fixtures[fixture_name])
        for dotted, value in (case.get("mutations") or {}).items():
            _set_dotted(fixture, str(dotted), value)

        failures = evaluate_token_fixture(authority, fixture)
        actual = "ACCEPT" if not failures else "REJECT"
        if actual != expect:
            raise CertificationError(
                f"case {case_id} expected {expect} but got {actual}: {failures}"
            )
        must_fail = case.get("mustFail")
        if expect == "REJECT" and must_fail not in failures:
            raise CertificationError(
                f"case {case_id} must fail {must_fail!r}, got {failures}"
            )

        seen[dimension].add(expect)
        accepted += int(actual == "ACCEPT")
        rejected += int(actual == "REJECT")
        results.append(
            {
                "id": case_id,
                "dimension": dimension,
                "verdict": actual,
                "failures": failures,
            }
        )

    incomplete = sorted(
        dimension
        for dimension, verdicts in seen.items()
        if verdicts != {"ACCEPT", "REJECT"}
    )
    if incomplete:
        raise CertificationError(
            f"token matrix lacks positive/negative coverage: {incomplete}"
        )

    return {
        "dimensions": len(EXPECTED_DIMENSIONS),
        "positiveCases": accepted,
        "negativeCases": rejected,
        "cases": results,
    }


def certify(
    *,
    authority_path: Path = AUTHORITY_PATH,
    matrix_path: Path = MATRIX_PATH,
    route_contract_path: Path = DEFAULT_ROUTE_CONTRACT,
    require_target_contract: bool = False,
) -> dict[str, Any]:
    authority = load_json(authority_path)
    matrix = load_json(matrix_path)
    route_contract = load_json(route_contract_path)

    validate_authority_shape(authority)
    route_report = validate_routes(authority, route_contract)
    token_report = validate_token_matrix(authority, matrix)

    leaks = privileged_default_scope_leaks(authority)
    if leaks:
        raise CertificationError(
            "privileged scopes are default-granted: " + "; ".join(leaks)
        )

    digest = canonical_route_digest(route_contract)
    target = authority["middleware"]["targetRouteContractSha256"]
    target_match = digest == target
    if require_target_contract and not target_match:
        raise CertificationError(
            f"target Middleware route contract mismatch: observed={digest} target={target}"
        )

    route_count = len(route_contract.get("routes") or [])
    if require_target_contract and route_count != authority["middleware"]["targetRouteCount"]:
        raise CertificationError(
            f"target Middleware route count mismatch: observed={route_count} "
            f"target={authority['middleware']['targetRouteCount']}"
        )

    return {
        "mission": "PAS-157",
        "verdict": "PASS",
        "routeContract": {
            "path": str(route_contract_path),
            "sha256": digest,
            "targetSha256": target,
            "targetMatch": target_match,
            "routeCount": route_count,
        },
        "callerAuthority": route_report,
        "tokenMatrix": token_report,
        "privilegedDefaultScopeLeaks": 0,
        "dirtyDesktopAutoGrantAuthorized": False,
        "liveApplyAuthorized": False,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority", type=Path, default=AUTHORITY_PATH)
    parser.add_argument("--matrix", type=Path, default=MATRIX_PATH)
    parser.add_argument("--route-contract", type=Path, default=DEFAULT_ROUTE_CONTRACT)
    parser.add_argument("--require-target-contract", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--check", action="store_true", help="Validate repository-only desired state.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = certify(
            authority_path=args.authority.resolve(),
            matrix_path=args.matrix.resolve(),
            route_contract_path=args.route_contract.resolve(),
            require_target_contract=args.require_target_contract,
        )
    except CertificationError as exc:
        print("PAS157_CALLER_TOKEN_CERTIFICATION=FAIL")
        print(f"ERROR={exc}")
        return 1

    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        route = report["routeContract"]
        caller = report["callerAuthority"]
        matrix = report["tokenMatrix"]
        print("PAS157_CALLER_TOKEN_CERTIFICATION=PASS")
        print(f"ROUTE_CONTRACT_SHA256={route['sha256']}")
        print(f"TARGET_ROUTE_CONTRACT_MATCH={'PASS' if route['targetMatch'] else 'PENDING_BASE_INTEGRATION'}")
        print(f"ROUTE_COUNT={route['routeCount']}")
        print(f"CALLER_SELECTORS={caller['uniqueCallerSelectors']}")
        print("UNKNOWN_CALLER_IDENTITIES=0")
        print(f"SERVICE_OR_USER_ROUTES={caller['serviceOrUserRoutes']}")
        print("HUMAN_SERVICE_BOUNDARY=PASS")
        print(f"TOKEN_MATRIX_DIMENSIONS={matrix['dimensions']}")
        print(f"TOKEN_MATRIX_POSITIVE={matrix['positiveCases']}")
        print(f"TOKEN_MATRIX_NEGATIVE={matrix['negativeCases']}")
        print("PRIVILEGED_DEFAULT_SCOPE_LEAKS=0")
        print("DIRTY_DESKTOP_AUTO_GRANT=PROHIBITED")
        print("KEYCLOAK_LIVE_APPLY=PROHIBITED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
