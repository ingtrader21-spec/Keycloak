#!/usr/bin/env python3
"""Generate the PAS-156 Keycloak identity projection from Middleware V3 routes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "config" / "contracts" / "middleware-api-access.v3.json"

PINNED_MIDDLEWARE_DIGEST = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
SOURCE_SCHEMA = "codestra.middleware.public-api-route-contract.v2"
OUTPUT_SCHEMA = "codestra.keycloak.middleware-api-access.v3"
ISSUER = "https://auth.codestra.co/realms/codestra"
MIDDLEWARE_AUDIENCE = "middleware-api"
SOURCE_REPOSITORY = "ingtrader21-spec/Middleware-"
SOURCE_PATH = "deploy/public-api-route-contract.json"

PLATFORM_SCOPE_FILES = {
    "platform.command": "config/client-scopes/platform.command.json",
    "platform.command.read": "config/client-scopes/platform.command.read.json",
    "platform.command.replay": "config/client-scopes/platform.command.replay.json",
}
PLATFORM_ROLE_FILE = "config/desired-state/platform-kernel/realm-roles/platform-operator.json"
RUNTIME_SCOPE_SELECTORS = {"resolved_from_command_prefix"}

KERNEL_ROUTE_POLICY = {
    ("POST", "/platform/v1/commands"): ("platform.command", None),
    ("GET", "/platform/v1/kernel/describe"): ("platform.command.read", None),
    ("GET", "/platform/v1/operations/{operation_id}"): ("platform.command.read", None),
    ("POST", "/platform/v1/operations/{operation_id}/cancel"): ("platform.command", None),
    (
        "POST",
        "/platform/v1/operations/{operation_id}/replay",
    ): ("platform.command.replay", "platform-operator"),
    (
        "GET",
        "/platform/v1/operations/{operation_id}/timeline",
    ): ("platform.command.read", None),
}


def canonical_digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def candidate_sources() -> list[Path]:
    configured = os.environ.get("MIDDLEWARE_V3_ROUTE_CONTRACT")
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser())

    github_root = ROOT.parents[1] if len(ROOT.parents) > 1 else ROOT.parent
    candidates.append(github_root / "Middleware-" / "deploy" / "public-api-route-contract.json")
    candidates.extend(
        sorted(
            (github_root / "Middleware-.worktrees").glob(
                "*/deploy/public-api-route-contract.json"
            )
        )
    )
    return candidates


def discover_source() -> Path:
    examined: list[str] = []
    for candidate in candidate_sources():
        if not candidate.is_file():
            continue
        try:
            digest = canonical_digest(load_json(candidate))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        examined.append(f"{candidate}={digest}")
        if digest == PINNED_MIDDLEWARE_DIGEST:
            return candidate
    detail = "; ".join(examined) if examined else "no readable candidates"
    raise SystemExit(
        "unable to find the pinned Middleware V3 route contract; "
        "pass --source or set MIDDLEWARE_V3_ROUTE_CONTRACT. "
        f"expected={PINNED_MIDDLEWARE_DIGEST}; examined={detail}"
    )


def classification_counts(routes: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"denied": 0, "private_only": 0, "shared_edge": 0}
    for row in routes:
        classification = row.get("classification")
        if classification not in counts:
            raise ValueError(f"unknown route classification: {classification!r}")
        counts[classification] += 1
    return counts


def validate_source(document: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    actual_digest = canonical_digest(document)
    if actual_digest != PINNED_MIDDLEWARE_DIGEST:
        raise ValueError(
            "Middleware route digest mismatch: "
            f"expected={PINNED_MIDDLEWARE_DIGEST} actual={actual_digest}"
        )
    if document.get("schema") != SOURCE_SCHEMA:
        raise ValueError(
            f"unexpected Middleware schema: {document.get('schema')!r}"
        )
    routes = document.get("routes")
    if not isinstance(routes, list):
        raise ValueError("Middleware route contract has no routes list")
    if len(routes) != 117:
        raise ValueError(f"expected 117 Middleware routes, found {len(routes)}")

    counts = classification_counts(routes)
    if counts != {"denied": 10, "private_only": 2, "shared_edge": 105}:
        raise ValueError(f"unexpected route classification counts: {counts}")

    operation_ids: set[str] = set()
    route_keys: set[tuple[str, str]] = set()
    missing_scope_routes: list[str] = []

    for row in routes:
        operation_id = row.get("operation_id")
        method = row.get("method")
        path = row.get("path")
        classification = row.get("classification")
        scope = row.get("scope")
        auth = row.get("auth")

        if not isinstance(operation_id, str) or not operation_id:
            raise ValueError(f"route missing operation_id: {row!r}")
        if operation_id in operation_ids:
            raise ValueError(f"duplicate operation_id: {operation_id}")
        operation_ids.add(operation_id)

        if not isinstance(method, str) or not isinstance(path, str):
            raise ValueError(f"route missing method/path: {operation_id}")
        key = (method, path)
        if key in route_keys:
            raise ValueError(f"duplicate method/path: {method} {path}")
        route_keys.add(key)

        if classification == "denied":
            if scope != "none" or auth != "deny":
                raise ValueError(
                    f"denied route must remain deny/none: {operation_id}"
                )
        elif not isinstance(scope, str) or not scope or scope == "none":
            missing_scope_routes.append(operation_id)

    if missing_scope_routes:
        raise ValueError(
            "active routes without required scopes: " + ", ".join(missing_scope_routes)
        )

    actual_kernel = {
        (row["method"], row["path"]): row
        for row in routes
        if (row["method"], row["path"]) in KERNEL_ROUTE_POLICY
    }
    if set(actual_kernel) != set(KERNEL_ROUTE_POLICY):
        missing = sorted(set(KERNEL_ROUTE_POLICY) - set(actual_kernel))
        raise ValueError(f"missing Middleware V3 kernel routes: {missing}")

    for key, (expected_scope, _expected_role) in KERNEL_ROUTE_POLICY.items():
        row = actual_kernel[key]
        if row["classification"] != "shared_edge":
            raise ValueError(f"kernel route is not shared_edge: {key}")
        if row["audience"] != MIDDLEWARE_AUDIENCE:
            raise ValueError(f"kernel route audience drift: {key}")
        if row["auth"] != "service-or-user-jwt":
            raise ValueError(f"kernel route auth drift: {key}")
        if row["scope"] != expected_scope:
            raise ValueError(
                f"kernel route scope drift: {key} expected={expected_scope} "
                f"actual={row['scope']}"
            )

    return routes, counts


def route_projection(row: dict[str, Any]) -> dict[str, Any]:
    source_scope = row.get("scope")
    if row["classification"] == "denied":
        scope_mode = "deny"
        required_scope: str | None = None
    elif source_scope in RUNTIME_SCOPE_SELECTORS:
        scope_mode = "runtime-selector"
        required_scope = source_scope
    else:
        scope_mode = "literal-scope"
        required_scope = source_scope

    required_role = None
    policy = KERNEL_ROUTE_POLICY.get((row["method"], row["path"]))
    if policy is not None:
        required_role = policy[1]

    return {
        "operationId": row["operation_id"],
        "method": row["method"],
        "path": row["path"],
        "classification": row["classification"],
        "callingClient": row["calling_client"],
        "audience": row["audience"],
        "requiredScope": required_scope,
        "scopeMode": scope_mode,
        "requiredRealmRole": required_role,
        "auth": row["auth"],
        "idempotencyRequired": bool(row["idempotency"]["required"]),
    }


def build_document(source: dict[str, Any]) -> dict[str, Any]:
    routes, counts = validate_source(source)
    projected_routes = sorted(
        (route_projection(row) for row in routes),
        key=lambda row: (row["path"], row["method"], row["operationId"]),
    )

    literal_scopes = sorted(
        {
            row["requiredScope"]
            for row in projected_routes
            if row["scopeMode"] == "literal-scope"
            and isinstance(row["requiredScope"], str)
        }
    )
    selectors = sorted(
        {
            row["requiredScope"]
            for row in projected_routes
            if row["scopeMode"] == "runtime-selector"
            and isinstance(row["requiredScope"], str)
        }
    )
    missing_required = sorted(
        row["operationId"]
        for row in projected_routes
        if row["classification"] != "denied" and not row["requiredScope"]
    )

    return {
        "schema": OUTPUT_SCHEMA,
        "status": "PREPARED_DISABLED",
        "source": {
            "repository": SOURCE_REPOSITORY,
            "path": SOURCE_PATH,
            "schema": source["schema"],
            "sha256": PINNED_MIDDLEWARE_DIGEST,
            "hashRule": source["hash_rule"],
            "routeCount": len(routes),
            "classificationCounts": counts,
        },
        "issuer": ISSUER,
        "targetAudience": MIDDLEWARE_AUDIENCE,
        "runtimeApplyAuthorized": False,
        "providerEffectsEnabled": False,
        "callerResolutionOwner": "PAS-157",
        "scopePolicy": {
            "realmDefaultAllowed": False,
            "clientDefaultAllowedForPlatformScopes": False,
            "platformScopeAttachment": "optional-only",
            "runtimeSelectorsAreNotKeycloakScopes": sorted(RUNTIME_SCOPE_SELECTORS),
            "notes": (
                "PAS-156 defines the three platform-kernel Keycloak scopes. "
                "All other route scope values are preserved from Middleware as authorization "
                "requirements; this mission neither creates caller clients nor widens grants."
            ),
        },
        "platformAuthority": {
            "clientScopes": [
                {
                    "name": scope,
                    "definition": PLATFORM_SCOPE_FILES[scope],
                    "attachment": "optional",
                    "realmDefault": False,
                }
                for scope in sorted(PLATFORM_SCOPE_FILES)
            ],
            "realmRoles": [
                {
                    "name": "platform-operator",
                    "definition": PLATFORM_ROLE_FILE,
                    "mfaRequired": True,
                    "independentApprovalRequired": True,
                    "activation": "PREPARED_DISABLED",
                    "usedBy": ["replay_operation"],
                }
            ],
        },
        "requiredScopes": literal_scopes,
        "scopeSelectors": selectors,
        "missingRequiredScopes": missing_required,
        "routes": projected_routes,
        "notes": [
            "All 117 Middleware route rows are represented, including denied and private-only routes.",
            "Denied routes remain explicit deny decisions and have no required Keycloak scope.",
            "resolved_from_command_prefix is a Middleware runtime selector, not a literal Keycloak scope.",
            "platform-operator is a protected realm role only for V3 replay; a callingClient value named platform-operator is a separate caller-classification concern owned by PAS-157.",
            "No caller client, secret, live realm mutation, provider effect, or production activation is authorized by this artifact.",
        ],
    }


def rendered(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        help="Path to Middleware deploy/public-api-route-contract.json",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the committed generated artifact differs from the pinned source",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source_path = args.source.expanduser().resolve() if args.source else discover_source()
    source = load_json(source_path)
    document = build_document(source)
    output = rendered(document)

    if args.check:
        if not OUTPUT.is_file():
            raise SystemExit(f"generated artifact missing: {OUTPUT}")
        current = OUTPUT.read_text(encoding="utf-8")
        if current != output:
            raise SystemExit(
                "MIDDLEWARE_API_ACCESS_V3_GENERATOR=DRIFT "
                f"source={source_path}"
            )
        print("MIDDLEWARE_API_ACCESS_V3_GENERATOR=PASS")
    else:
        OUTPUT.write_text(output, encoding="utf-8", newline="\n")
        print(f"GENERATED={OUTPUT}")

    print(f"MIDDLEWARE_ROUTE_DIGEST={PINNED_MIDDLEWARE_DIGEST}")
    print(f"MIDDLEWARE_ROUTE_COUNT={document['source']['routeCount']}")
    print(
        "MIDDLEWARE_ROUTE_CLASSIFICATIONS="
        + json.dumps(document["source"]["classificationCounts"], sort_keys=True)
    )
    print(f"MISSING_REQUIRED_SCOPES={len(document['missingRequiredScopes'])}")


if __name__ == "__main__":
    main()
