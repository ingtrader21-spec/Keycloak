"""PAS-156 Middleware V3 API identity authority contract tests."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = ROOT / "config" / "contracts" / "middleware-api-access.v3.json"
GENERATOR_PATH = ROOT / "scripts" / "generate_middleware_api_access_v3.py"
REALM_PATH = ROOT / "config" / "realms" / "codestra.json"
CLIENT_DIR = ROOT / "config" / "clients"

EXPECTED_DIGEST = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
PLATFORM_SCOPES = {
    "platform.command",
    "platform.command.read",
    "platform.command.replay",
}
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


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class MiddlewareApiAccessV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = load(AUTHORITY_PATH)

    def test_authority_pins_exact_middleware_contract_and_stays_dark(self) -> None:
        source = self.authority["source"]
        self.assertEqual(
            self.authority["schema"],
            "codestra.keycloak.middleware-api-access.v3",
        )
        self.assertEqual(source["sha256"], EXPECTED_DIGEST)
        self.assertEqual(source["routeCount"], 117)
        self.assertEqual(
            source["classificationCounts"],
            {"denied": 10, "private_only": 2, "shared_edge": 105},
        )
        self.assertFalse(self.authority["runtimeApplyAuthorized"])
        self.assertFalse(self.authority["providerEffectsEnabled"])
        self.assertEqual(self.authority["callerResolutionOwner"], "PAS-157")

    def test_all_117_routes_are_represented_once(self) -> None:
        routes = self.authority["routes"]
        self.assertEqual(len(routes), 117)
        self.assertEqual(len({row["operationId"] for row in routes}), 117)
        self.assertEqual(
            len({(row["method"], row["path"]) for row in routes}),
            117,
        )
        classifications = {
            name: sum(row["classification"] == name for row in routes)
            for name in ("denied", "private_only", "shared_edge")
        }
        self.assertEqual(
            classifications,
            {"denied": 10, "private_only": 2, "shared_edge": 105},
        )

    def test_every_active_route_has_scope_or_reviewed_runtime_selector(self) -> None:
        missing = []
        selectors = set()
        for row in self.authority["routes"]:
            if row["classification"] == "denied":
                self.assertIsNone(row["requiredScope"], row)
                self.assertEqual(row["scopeMode"], "deny", row)
                continue

            scope = row["requiredScope"]
            if not isinstance(scope, str) or not scope:
                missing.append(row["operationId"])
            if row["scopeMode"] == "runtime-selector":
                selectors.add(scope)
            else:
                self.assertEqual(row["scopeMode"], "literal-scope", row)

        self.assertEqual(missing, [])
        self.assertEqual(self.authority["missingRequiredScopes"], [])
        self.assertEqual(selectors, {"resolved_from_command_prefix"})
        self.assertEqual(
            self.authority["scopeSelectors"],
            ["resolved_from_command_prefix"],
        )

    def test_platform_kernel_routes_use_reviewed_scopes_and_replay_role(self) -> None:
        routes = {
            (row["method"], row["path"]): row
            for row in self.authority["routes"]
            if (row["method"], row["path"]) in KERNEL
        }
        self.assertEqual(set(routes), set(KERNEL))
        for key, (scope, role) in KERNEL.items():
            with self.subTest(route=key):
                row = routes[key]
                self.assertEqual(row["classification"], "shared_edge")
                self.assertEqual(row["audience"], "middleware-api")
                self.assertEqual(row["auth"], "service-or-user-jwt")
                self.assertEqual(row["requiredScope"], scope)
                self.assertEqual(row["requiredRealmRole"], role)

    def test_platform_scopes_are_optional_and_never_client_or_realm_defaults(self) -> None:
        declared = {
            row["name"]: row
            for row in self.authority["platformAuthority"]["clientScopes"]
        }
        self.assertEqual(set(declared), PLATFORM_SCOPES)

        for scope in sorted(PLATFORM_SCOPES):
            definition = load(ROOT / declared[scope]["definition"])
            self.assertEqual(definition["name"], scope)
            self.assertEqual(definition["protocol"], "openid-connect")
            self.assertEqual(
                definition["attributes"]["include.in.token.scope"],
                "true",
            )
            self.assertEqual(definition["protocolMappers"], [])
            self.assertEqual(declared[scope]["attachment"], "optional")
            self.assertFalse(declared[scope]["realmDefault"])

        realm = load(REALM_PATH)
        realm_defaults = set(realm.get("defaultDefaultClientScopes") or [])
        self.assertFalse(realm_defaults.intersection(PLATFORM_SCOPES))

        for client_file in CLIENT_DIR.glob("*.json"):
            client = load(client_file)
            defaults = set(client.get("defaultClientScopes") or [])
            self.assertFalse(
                defaults.intersection(PLATFORM_SCOPES),
                client_file,
            )

    def test_platform_operator_is_mfa_and_independent_approval_governed(self) -> None:
        (role_ref,) = self.authority["platformAuthority"]["realmRoles"]
        self.assertEqual(role_ref["name"], "platform-operator")
        self.assertTrue(role_ref["mfaRequired"])
        self.assertTrue(role_ref["independentApprovalRequired"])
        self.assertEqual(role_ref["activation"], "PREPARED_DISABLED")
        self.assertEqual(role_ref["usedBy"], ["replay_operation"])

        role = load(ROOT / role_ref["definition"])
        attrs = role["attributes"]
        self.assertEqual(attrs["codestra.mfa.required"], ["true"])
        self.assertEqual(
            attrs["codestra.assignment.independent_approval"],
            ["true"],
        )
        self.assertEqual(attrs["codestra.cross_family_grant"], ["false"])
        self.assertEqual(attrs["codestra.activation"], ["PREPARED_DISABLED"])

    def test_committed_artifact_uses_generator_deterministic_rendering(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "generate_middleware_api_access_v3",
            GENERATOR_PATH,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(
            AUTHORITY_PATH.read_text(encoding="utf-8"),
            module.rendered(self.authority),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
