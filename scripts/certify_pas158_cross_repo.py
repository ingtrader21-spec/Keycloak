#!/usr/bin/env python3
"""PAS-158 exact-SHA Keycloak/Kong/Caddy/Middleware identity parity certification.

The certifier is read-only with respect to the four source repositories. It reads
immutable Git objects at the pinned SHAs and fails closed when route or identity
parity is incomplete. Production effects are never enabled.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

PINS = {
    "keycloak": "45a487d71a516ae3039b00c250752897469ffe7a",
    "kong": "5ac254c6fb04579615e4d60d25efcc911d42a2e3",
    "caddy": "84c2b7b3bce6d90764eac5eab362aed973f56056",
    "middleware": "2862af0aa97367b18cb360af69212abe4243a1ac",
}
EXPECTED_MIDDLEWARE_DIGEST = (
    "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
)
EXPECTED_AUDIENCE = "middleware-api"
EXPECTED_UPSTREAM = {"host": "middleware-integration-api", "port": 8095}


class CertificationError(RuntimeError):
    pass


def git_show(repo: Path, sha: str, path: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", "-c", f"safe.directory={repo}", "-C", str(repo), "show", f"{sha}:{path}"],
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as exc:
        raise CertificationError(f"cannot read {repo}@{sha}:{path}") from exc


def load_json(repo: Path, sha: str, path: str) -> dict[str, Any]:
    try:
        value = json.loads(git_show(repo, sha, path))
    except json.JSONDecodeError as exc:
        raise CertificationError(f"invalid JSON at {repo}@{sha}:{path}") from exc
    if not isinstance(value, dict):
        raise CertificationError(f"{path} must contain a JSON object")
    return value


def canonical_digest(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def route_key(row: dict[str, Any]) -> tuple[str, str]:
    return str(row.get("method")), str(row.get("path"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-repo", type=Path, required=True)
    parser.add_argument("--kong-repo", type=Path, required=True)
    parser.add_argument("--caddy-repo", type=Path, required=True)
    parser.add_argument("--middleware-repo", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-blocked", action="store_true")
    args = parser.parse_args(argv)

    mw = load_json(args.middleware_repo, PINS["middleware"], "deploy/public-api-route-contract.json")
    kc = load_json(args.keycloak_repo, PINS["keycloak"], "config/contracts/middleware-api-access.v3.json")
    caller = load_json(
        args.keycloak_repo,
        PINS["keycloak"],
        "config/contracts/middleware-caller-classification.v1.json",
    )
    kong = load_json(args.kong_repo, PINS["kong"], "config/kong-middleware-authority.v2.json")
    caddy = load_json(args.caddy_repo, PINS["caddy"], "config/caddy-kong-contract.v1.json")
    caddy_site = git_show(
        args.caddy_repo,
        PINS["caddy"],
        "sites/api.codestra.co.caddy",
    ).decode("utf-8")

    mw_routes = mw.get("routes")
    kc_routes = kc.get("routes")
    kong_routes = kong.get("routes")
    if not all(isinstance(v, list) for v in (mw_routes, kc_routes, kong_routes)):
        raise CertificationError("route contracts must expose route arrays")

    mw_by = {route_key(row): row for row in mw_routes}
    mw_shared = {
        key: row for key, row in mw_by.items() if row.get("classification") == "shared_edge"
    }
    kc_by = {route_key(row): row for row in kc_routes}
    kong_by = {route_key(row): row for row in kong_routes}

    middleware_digest = canonical_digest(mw)
    keycloak_source = kc.get("source") or {}
    caller_target = caller.get("middleware") or {}
    keycloak_route_missing = sorted(mw_by.keys() - kc_by.keys())
    keycloak_route_extra = sorted(kc_by.keys() - mw_by.keys())
    keycloak_pass = (
        middleware_digest == EXPECTED_MIDDLEWARE_DIGEST
        and keycloak_source.get("sha256") == EXPECTED_MIDDLEWARE_DIGEST
        and keycloak_source.get("routeCount") == len(mw_routes) == 117
        and caller_target.get("targetRouteContractSha256") == EXPECTED_MIDDLEWARE_DIGEST
        and caller_target.get("targetRouteCount") == 117
        and caller_target.get("canonicalAudience") == EXPECTED_AUDIENCE
        and kc.get("targetAudience") == EXPECTED_AUDIENCE
        and not keycloak_route_missing
        and not keycloak_route_extra
    )

    kong_field_mismatches: list[dict[str, Any]] = []
    field_map = {
        "audience": "audience",
        "scope": "scope",
        "auth": "authentication",
        "calling_client": "azp",
    }
    for key in sorted(set(mw_shared) & set(kong_by)):
        mw_row = mw_shared[key]
        kong_row = kong_by[key]
        for mw_field, kong_field in field_map.items():
            if mw_row.get(mw_field) != kong_row.get(kong_field):
                kong_field_mismatches.append(
                    {
                        "method": key[0],
                        "path": key[1],
                        "field": mw_field,
                        "middleware": mw_row.get(mw_field),
                        "kong": kong_row.get(kong_field),
                    }
                )

    kong_missing_keys = sorted(set(mw_shared) - set(kong_by))
    kong_extra_keys = sorted(set(kong_by) - set(mw_by))
    kong_missing = []
    for key in kong_missing_keys:
        row = mw_shared[key]
        kong_missing.append(
            {
                "method": key[0],
                "path": key[1],
                "audience": row.get("audience"),
                "scope": row.get("scope"),
                "auth": row.get("auth"),
                "callingClient": row.get("calling_client"),
            }
        )
    kong_pass = (
        kong.get("upstream") == EXPECTED_UPSTREAM
        and len(kong_routes) == len(mw_shared)
        and not kong_missing
        and not kong_extra_keys
        and not kong_field_mismatches
    )

    identity_boundary = caddy.get("identityBoundary") or {}
    prefixes = caddy.get("kongManagedPathPrefixes") or []
    platform_v1_routed = any(
        isinstance(prefix, str)
        and (prefix == "/platform/v1" or prefix.startswith("/platform/v1/"))
        for prefix in prefixes
    )
    site_platform_v1_routed = "/platform/v1" in caddy_site
    caddy_pass = (
        identity_boundary.get("caddyAuthenticatesUsersOrServices") is False
        and identity_boundary.get("authorizationHeaderForwardedToKong") is True
        and identity_boundary.get("caddyCreatesTrustedApplicationIdentityHeaders") is False
        and identity_boundary.get("kongPerformsOidcJwtAndScopePolicy") is True
        and identity_boundary.get("middlewareRevalidatesPrivilegedAuthorization") is True
        and platform_v1_routed
        and site_platform_v1_routed
    )

    mw_platform = [
        row
        for row in mw_routes
        if row.get("classification") == "shared_edge"
        and str(row.get("path", "")).startswith("/platform/v1/")
    ]
    kong_platform = [
        row for row in kong_routes if str(row.get("path", "")).startswith("/platform/v1/")
    ]

    blockers: list[str] = []
    if not keycloak_pass:
        blockers.append("KEYCLOAK_MIDDLEWARE_PARITY")
    if not kong_pass:
        blockers.append("KONG_MIDDLEWARE_ROUTE_COVERAGE")
    if not caddy_pass:
        blockers.append("CADDY_KONG_PLATFORM_V1_BOUNDARY")

    report = {
        "schema": "codestra.keycloak.pas158-cross-repo-certification.v1",
        "mission": "PAS-158",
        "pins": PINS,
        "expected": {
            "middlewareRouteDigest": EXPECTED_MIDDLEWARE_DIGEST,
            "audience": EXPECTED_AUDIENCE,
            "middlewareUpstream": "middleware-integration-api:8095",
        },
        "keycloakMiddleware": {
            "status": "PASS" if keycloak_pass else "FAIL",
            "middlewareDigest": middleware_digest,
            "middlewareRoutes": len(mw_routes),
            "keycloakRoutes": len(kc_routes),
            "missingRoutes": [
                {"method": method, "path": path}
                for method, path in keycloak_route_missing
            ],
            "extraRoutes": [
                {"method": method, "path": path}
                for method, path in keycloak_route_extra
            ],
        },
        "kongMiddleware": {
            "status": "PASS" if kong_pass else "BLOCKED",
            "middlewareSharedEdgeRoutes": len(mw_shared),
            "kongRoutes": len(kong_routes),
            "matchingRoutes": len(set(mw_shared) & set(kong_by)),
            "platformV1MiddlewareRoutes": len(mw_platform),
            "platformV1KongRoutes": len(kong_platform),
            "missingRouteCount": len(kong_missing),
            "missingRoutes": kong_missing,
            "fieldMismatchCount": len(kong_field_mismatches),
            "fieldMismatches": kong_field_mismatches,
            "extraRouteCount": len(kong_extra_keys),
            "extraRoutes": [
                {"method": method, "path": path}
                for method, path in kong_extra_keys
            ],
        },
        "caddyKong": {
            "status": "PASS" if caddy_pass else "BLOCKED",
            "kongManagedPathPrefixes": prefixes,
            "platformV1PrefixDeclared": platform_v1_routed,
            "platformV1MatcherPresent": site_platform_v1_routed,
            "identityBoundary": identity_boundary,
            "productionCutoverAuthorizedBySource": (
                (caddy.get("migration") or {}).get("productionCutoverAuthorizedBySource")
            ),
        },
        "releaseGovernance": {
            "status": "SEPARATE_BLOCKER",
            "lastKnownPreMergeTrustRoot": "BOOTSTRAP_REJECTED=missing-independent-approval",
            "note": (
                "Tracked separately from implementation parity. The merged code "
                "state does not by itself establish production certification."
            ),
        },
        "productionEffectsEnabled": False,
        "blockers": blockers,
        "verdict": "PASS" if not blockers else "BLOCKED_CROSS_REPO_PARITY",
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    print("PAS158_KEYCLOAK_MIDDLEWARE=" + report["keycloakMiddleware"]["status"])
    print("PAS158_KONG_MIDDLEWARE=" + report["kongMiddleware"]["status"])
    print("PAS158_CADDY_KONG=" + report["caddyKong"]["status"])
    print("MIDDLEWARE_ROUTE_COUNT=" + str(len(mw_routes)))
    print("MIDDLEWARE_SHARED_EDGE=" + str(len(mw_shared)))
    print("KONG_ROUTE_COUNT=" + str(len(kong_routes)))
    print("KONG_MISSING_SHARED_EDGE=" + str(len(kong_missing)))
    print("KONG_FIELD_MISMATCHES=" + str(len(kong_field_mismatches)))
    print("MIDDLEWARE_PLATFORM_V1=" + str(len(mw_platform)))
    print("KONG_PLATFORM_V1=" + str(len(kong_platform)))
    print("CADDY_PLATFORM_V1_TO_KONG=" + ("PASS" if caddy_pass else "FAIL"))
    print("PAS158_VERDICT=" + report["verdict"])

    if blockers and not args.allow_blocked:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
