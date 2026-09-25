#!/usr/bin/env python3
"""Read-only Keycloak -> Caddy -> Kong -> Middleware identity parity certifier (PAS-8).

Compares local snapshot files of the sibling repositories against this
repository's frozen Middleware V3 identity authority. It never fetches, never
writes to a sibling repository, and never contacts Keycloak.

Inputs are plain files, typically exported read-only with
``gh api repos/<owner>/<repo>/contents/<path>?ref=<sha> --jq .content | base64 -d``:

* ``--middleware-contract``  Middleware ``deploy/public-api-route-contract.json``
* ``--kong-authority``       Kong ``config/kong-middleware-authority.v2.json``
* ``--caddy-site``           Caddy ``sites/api.codestra.co.caddy``

Exits non-zero unless every check passes.
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
ACCESS_V3 = ROOT / "config" / "contracts" / "middleware-api-access.v3.json"
EDGE_CONTRACT = (
    ROOT
    / "config"
    / "desired-state"
    / "edge-integration-certification"
    / "middleware-public-api-route-contract.v2.json"
)
PRODUCTION_ISSUER = "https://auth.codestra.co/realms/codestra"
PATH_PARAMETER = re.compile(r"\{[^}]+\}")
CADDY_METHOD = re.compile(r"^\s*method\s+([A-Z]+)\s*$")
CADDY_PATH_REGEXP = re.compile(r"^\s*path_regexp\s+(\S+)\s*$")
CADDY_MATCHER_START = re.compile(r"^\s*@([A-Za-z0-9_-]+)\s*\{\s*$")
CADDY_HANDLE_START = re.compile(r"^\s*handle\s+@([A-Za-z0-9_-]+)\s*\{\s*$")
CADDY_KONG_PROXY = re.compile(
    r"^\s*reverse_proxy\s+\{\$CADDY_KONG_UPSTREAM\}\s*\{?\s*$"
)

KONG_FIELDS = (
    ("operation_id", "operation_id"),
    ("audience", "audience"),
    ("scope", "scope"),
    ("calling_client", "azp"),
    ("auth", "authentication"),
)
ACCESS_FIELDS = (
    ("operation_id", "operationId"),
    ("classification", "classification"),
    ("calling_client", "callingClient"),
    ("audience", "audience"),
    ("auth", "auth"),
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def contract_digest(document: Any) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def route_key(row: dict[str, Any]) -> tuple[str, str]:
    return row["method"], row["path"]


def compare_access(middleware: dict, access: dict) -> list[str]:
    problems = []
    if access["source"]["sha256"] != contract_digest(middleware):
        problems.append("keycloak access authority pins a different route contract digest")
    routes = {route_key(r): r for r in middleware["routes"]}
    rows = {route_key(r): r for r in access["routes"]}
    for key in sorted(set(routes) ^ set(rows)):
        problems.append(f"route present on one side only: {key}")
    for key in sorted(set(routes) & set(rows)):
        route, row = routes[key], rows[key]
        for m_field, a_field in ACCESS_FIELDS:
            if route.get(m_field) != row.get(a_field):
                problems.append(f"{key} {m_field}: middleware={route.get(m_field)!r} keycloak={row.get(a_field)!r}")
        expected_scope = None if route.get("scope") == "none" else route.get("scope")
        if row.get("requiredScope") != expected_scope:
            problems.append(f"{key} scope: middleware={route.get('scope')!r} keycloak={row.get('requiredScope')!r}")
    return problems


def compare_kong(middleware: dict, kong: dict) -> list[str]:
    problems = []
    if kong["contract"]["sha256"] != contract_digest(middleware):
        problems.append("kong pins a different route contract digest")
    shared = {
        route_key(r): r
        for r in middleware["routes"]
        if r["classification"] == "shared_edge"
    }
    keys = [route_key(r) for r in kong["routes"]]
    seen: set[tuple[str, str]] = set()
    for key in keys:
        if key in seen:
            problems.append(f"duplicate kong route declaration: {key}")
        seen.add(key)
    rows = {route_key(r): r for r in kong["routes"]}
    for key in sorted(set(shared) - set(rows)):
        problems.append(f"shared_edge route missing from kong: {key}")
    for key in sorted(set(rows) - set(shared)):
        problems.append(f"kong exposes a non-shared_edge route: {key}")
    for key in sorted(set(shared) & set(rows)):
        route, row = shared[key], rows[key]
        for m_field, k_field in KONG_FIELDS:
            if route.get(m_field) != row.get(k_field):
                problems.append(f"{key} {m_field}: middleware={route.get(m_field)!r} kong={row.get(k_field)!r}")
        if row.get("issuer") != PRODUCTION_ISSUER:
            problems.append(f"{key} kong issuer {row.get('issuer')!r}")
    return problems


def _caddy_block(lines: list[str], start: int) -> tuple[list[str], int]:
    depth = 0
    body: list[str] = []
    for index in range(start, len(lines)):
        line = lines[index]
        depth += line.count("{")
        depth -= line.count("}")
        if index > start:
            body.append(line)
        if depth == 0:
            return body[:-1], index
    raise ValueError(f"unterminated Caddy block at line {start + 1}")


def caddy_matchers(site: str) -> dict[str, re.Pattern[str]]:
    lines = site.splitlines()
    kong_handlers: set[str] = set()
    for index, line in enumerate(lines):
        handle = CADDY_HANDLE_START.match(line)
        if not handle:
            continue
        body, _end = _caddy_block(lines, index)
        if any(CADDY_KONG_PROXY.match(item) for item in body):
            kong_handlers.add(handle.group(1))

    matchers: dict[str, re.Pattern[str]] = {}
    for index, line in enumerate(lines):
        start = CADDY_MATCHER_START.match(line)
        if not start or start.group(1) not in kong_handlers:
            continue
        body, _end = _caddy_block(lines, index)
        methods = [
            match.group(1)
            for item in body
            if (match := CADDY_METHOD.match(item))
        ]
        patterns = [
            match.group(1)
            for item in body
            if (match := CADDY_PATH_REGEXP.match(item))
        ]
        if len(methods) != 1 or len(patterns) != 1:
            continue
        method = methods[0]
        if method in matchers:
            raise ValueError(f"duplicate Caddy canonical matcher for {method}")
        matchers[method] = re.compile(patterns[0])
    return matchers


def _route_samples(path: str) -> tuple[str, ...]:
    if not PATH_PARAMETER.search(path):
        return (path,)
    return tuple(
        PATH_PARAMETER.sub(value, path)
        for value in ("abc123", "123", "A_b-1.2:3")
    )


def compare_caddy(middleware: dict, site: str) -> list[str]:
    problems = []
    matchers = caddy_matchers(site)
    for route in middleware["routes"]:
        samples = _route_samples(route["path"])
        matcher = matchers.get(route["method"])
        results = [bool(matcher and matcher.fullmatch(sample)) for sample in samples]
        routed = all(results)
        exposed = any(results)
        if route["classification"] == "shared_edge" and not routed:
            problems.append(
                f"shared_edge route not routed to kong by caddy: {route_key(route)}"
            )
        if route["classification"] != "shared_edge" and exposed:
            problems.append(
                f"caddy routes a {route['classification']} route: {route_key(route)}"
            )
    return problems


def certify(middleware_path: Path, kong_path: Path, caddy_path: Path) -> dict[str, Any]:
    middleware = load_json(middleware_path)
    digest = contract_digest(middleware)
    edge_digest = contract_digest(load_json(EDGE_CONTRACT))
    checks = {
        "keycloakEdgeContract": [] if edge_digest == digest else [
            f"keycloak edge desired state pins {edge_digest}, middleware is {digest}"
        ],
        "keycloakAccessAuthority": compare_access(middleware, load_json(ACCESS_V3)),
        "kong": compare_kong(middleware, load_json(kong_path)),
        "caddy": compare_caddy(middleware, caddy_path.read_text(encoding="utf-8")),
    }
    shared = sum(1 for r in middleware["routes"] if r["classification"] == "shared_edge")
    return {
        "verdict": "PASS" if not any(checks.values()) else "FAIL",
        "routeContractSha256": digest,
        "routeCount": len(middleware["routes"]),
        "sharedEdgeRoutes": shared,
        "problems": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--middleware-contract", type=Path, required=True)
    parser.add_argument("--kong-authority", type=Path, required=True)
    parser.add_argument("--caddy-site", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = certify(args.middleware_contract, args.kong_authority, args.caddy_site)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"CROSS_REPO_IDENTITY_PARITY={report['verdict']}")
        print(f"ROUTE_CONTRACT_SHA256={report['routeContractSha256']}")
        print(f"ROUTE_COUNT={report['routeCount']}")
        print(f"SHARED_EDGE_ROUTES={report['sharedEdgeRoutes']}")
        for surface, problems in report["problems"].items():
            label = re.sub(r"(?<!^)(?=[A-Z])", "_", surface).upper()
            print(f"{label}_MISMATCHES={len(problems)}")
            for problem in problems[:20]:
                print(f"  {problem}")
        print("KEYCLOAK_LIVE_APPLY=PROHIBITED")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
