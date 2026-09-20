#!/usr/bin/env python3
"""Validate the committed PAS-156 Middleware V3 Keycloak access authority."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "config" / "contracts" / "middleware-api-access.v3.json"
REALM = ROOT / "config" / "realms" / "codestra.json"
CLIENT_DIR = ROOT / "config" / "clients"

EXPECTED_DIGEST = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
EXPECTED_SCHEMA = "codestra.keycloak.middleware-api-access.v3"
PLATFORM_SCOPES = {
    "platform.command": ROOT / "config" / "client-scopes" / "platform.command.json",
    "platform.command.read": ROOT / "config" / "client-scopes" / "platform.command.read.json",
    "platform.command.replay": ROOT / "config" / "client-scopes" / "platform.command.replay.json",
}
PLATFORM_ROLE = (
    ROOT
    / "config"
    / "desired-state"
    / "platform-kernel"
    / "realm-roles"
    / "platform-operator.json"
)
RUNTIME_SELECTOR = "resolved_from_command_prefix"

KERNEL = {
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


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def route_counts(routes: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"denied": 0, "private_only": 0, "shared_edge": 0}
    for row in routes:
        classification = row["classification"]
        assert classification in counts, row
        counts[classification] += 1
    return counts


def validate() -> dict[str, int]:
    authority = load(AUTHORITY)
    assert authority["schema"] == EXPECTED_SCHEMA
    assert authority["status"] == "PREPARED_DISABLED"
    assert authority["source"]["sha256"] == EXPECTED_DIGEST
    assert authority["source"]["schema"] == "codestra.middleware.public-api-route-contract.v2"
    assert authority["source"]["routeCount"] == 117
    assert authority["source"]["classificationCounts"] == {
        "denied": 10,
        "private_only": 2,
        "shared_edge": 105,
    }
    assert authority["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert authority["targetAudience"] == "middleware-api"
    assert authority["runtimeApplyAuthorized"] is False
    assert authority["providerEffectsEnabled"] is False
    assert authority["callerResolutionOwner"] == "PAS-157"

    routes = authority["routes"]
    assert len(routes) == 117
    assert route_counts(routes) == authority["source"]["classificationCounts"]
    assert len({row["operationId"] for row in routes}) == 117
    assert len({(row["method"], row["path"]) for row in routes}) == 117

    missing_required: list[str] = []
    literal_scopes: set[str] = set()
    selectors: set[str] = set()

    for row in routes:
        classification = row["classification"]
        required_scope = row["requiredScope"]
        scope_mode = row["scopeMode"]

        if classification == "denied":
            assert required_scope is None, row
            assert scope_mode == "deny", row
            assert row["auth"] == "deny", row
            continue

        if not isinstance(required_scope, str) or not required_scope:
            missing_required.append(row["operationId"])
            continue

        if scope_mode == "runtime-selector":
            selectors.add(required_scope)
        else:
            assert scope_mode == "literal-scope", row
            literal_scopes.add(required_scope)

    assert missing_required == []
    assert authority["missingRequiredScopes"] == []
    assert authority["requiredScopes"] == sorted(literal_scopes)
    assert authority["scopeSelectors"] == [RUNTIME_SELECTOR]
    assert selectors == {RUNTIME_SELECTOR}

    kernel = {
        (row["method"], row["path"]): row
        for row in routes
        if (row["method"], row["path"]) in KERNEL
    }
    assert set(kernel) == set(KERNEL)
    for key, (scope, role) in KERNEL.items():
        row = kernel[key]
        assert row["classification"] == "shared_edge", row
        assert row["audience"] == "middleware-api", row
        assert row["auth"] == "service-or-user-jwt", row
        assert row["requiredScope"] == scope, row
        assert row["requiredRealmRole"] == role, row

    scope_policy = authority["scopePolicy"]
    assert scope_policy["realmDefaultAllowed"] is False
    assert scope_policy["clientDefaultAllowedForPlatformScopes"] is False
    assert scope_policy["platformScopeAttachment"] == "optional-only"
    assert scope_policy["runtimeSelectorsAreNotKeycloakScopes"] == [RUNTIME_SELECTOR]

    platform_authority = authority["platformAuthority"]
    declared = {
        row["name"]: row for row in platform_authority["clientScopes"]
    }
    assert set(declared) == set(PLATFORM_SCOPES)
    for scope, path in PLATFORM_SCOPES.items():
        definition = load(path)
        assert definition["name"] == scope
        assert definition["protocol"] == "openid-connect"
        assert definition["attributes"]["include.in.token.scope"] == "true"
        assert definition["protocolMappers"] == []
        assert declared[scope]["attachment"] == "optional"
        assert declared[scope]["realmDefault"] is False
        assert declared[scope]["definition"] == str(path.relative_to(ROOT)).replace("\\", "/")

    realm = load(REALM)
    realm_defaults = set(realm.get("defaultDefaultClientScopes") or [])
    assert not realm_defaults.intersection(PLATFORM_SCOPES)

    for client_path in sorted(CLIENT_DIR.glob("*.json")):
        client = load(client_path)
        default_scopes = set(client.get("defaultClientScopes") or [])
        assert not default_scopes.intersection(PLATFORM_SCOPES), client_path

    role_refs = platform_authority["realmRoles"]
    assert len(role_refs) == 1
    role_ref = role_refs[0]
    assert role_ref["name"] == "platform-operator"
    assert role_ref["definition"] == str(PLATFORM_ROLE.relative_to(ROOT)).replace("\\", "/")
    assert role_ref["mfaRequired"] is True
    assert role_ref["independentApprovalRequired"] is True
    assert role_ref["activation"] == "PREPARED_DISABLED"
    assert role_ref["usedBy"] == ["replay_operation"]

    role = load(PLATFORM_ROLE)
    assert role["name"] == "platform-operator"
    assert role["composite"] is False
    assert role["clientRole"] is False
    attributes = role["attributes"]
    assert attributes["codestra.role.family"] == ["platform-kernel"]
    assert attributes["codestra.role.level"] == ["operator"]
    assert attributes["codestra.mfa.required"] == ["true"]
    assert attributes["codestra.assignment.independent_approval"] == ["true"]
    assert attributes["codestra.cross_family_grant"] == ["false"]
    assert attributes["codestra.activation"] == ["PREPARED_DISABLED"]

    return authority["source"]["classificationCounts"]


def main() -> None:
    counts = validate()
    print("MIDDLEWARE_API_ACCESS_V3=PASS")
    print(f"MIDDLEWARE_ROUTE_COUNT={sum(counts.values())}")
    print(f"MIDDLEWARE_SHARED_EDGE={counts['shared_edge']}")
    print(f"MIDDLEWARE_PRIVATE_ONLY={counts['private_only']}")
    print(f"MIDDLEWARE_DENIED={counts['denied']}")
    print("MISSING_REQUIRED_SCOPES=0")


if __name__ == "__main__":
    main()
