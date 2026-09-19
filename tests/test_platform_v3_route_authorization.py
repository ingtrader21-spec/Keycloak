"""The Middleware V3 route-authorization contract is prepared, dark and self-consistent.

config/contracts/middleware-v3-route-authorization.v1.json names, per V3 kernel
route, the scope Keycloak issues and the realm role Middleware checks; the private
/metrics scrape binds monitoring-readonly to metrics.read. Every scope it names
exists as an optional client-scope definition, the platform-operator role exists as
a prepared desired-state role that no planner provisions, no client is granted any
of it yet, and the contract cannot be flipped live from this repository alone.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "contracts" / "middleware-v3-route-authorization.v1.json"
ACCESS_MATRIX = ROOT / "config" / "contracts" / "service-access-matrix.json"
CLIENT_SCOPE_DIR = ROOT / "config" / "client-scopes"
CLIENT_DIR = ROOT / "config" / "clients"
ROLE_DIR = ROOT / "config" / "desired-state" / "platform-kernel" / "realm-roles"
OBSERVABILITY_PLANNER = ROOT / "scripts" / "observability_desired_state.py"

KERNEL_ROUTES = {
    ("POST", "/platform/v1/commands"): ("platform.command", None),
    ("GET", "/platform/v1/operations/{operation_id}"): ("platform.command.read", None),
    ("GET", "/platform/v1/operations/{operation_id}/timeline"): ("platform.command.read", None),
    ("POST", "/platform/v1/operations/{operation_id}/cancel"): ("platform.command", None),
    ("POST", "/platform/v1/operations/{operation_id}/replay"): ("platform.command.replay", "platform-operator"),
    ("GET", "/platform/v1/kernel/describe"): ("platform.command.read", None),
}
PRIVILEGED_SCOPES = {"platform.command", "platform.command.read", "platform.command.replay", "metrics.read"}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class RouteAuthorizationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load(CONTRACT)

    def test_contract_is_dark_and_bound_to_the_middleware_audience(self) -> None:
        contract = self.contract
        self.assertEqual(contract["status"], "V3_PENDING_FINAL_MIDDLEWARE_CONTRACT")
        self.assertTrue(contract["V3_PENDING_FINAL_MIDDLEWARE_CONTRACT"])
        self.assertFalse(contract["runtimeApplyAuthorized"])
        self.assertEqual(contract["extendsAccessMatrix"], ACCESS_MATRIX.name)
        matrix = load(ACCESS_MATRIX)
        self.assertEqual(contract["issuer"], matrix["issuer"])
        self.assertEqual(contract["audience"], "middleware-api")
        self.assertEqual(contract["targetClientId"], "middleware-api")
        self.assertEqual(contract["grantType"], matrix["tokenPolicy"]["grantType"])
        self.assertLessEqual(
            contract["maximumAccessTokenLifetimeSeconds"],
            matrix["tokenPolicy"]["maximumAccessTokenLifetimeSeconds"],
        )
        self.assertFalse(contract["refreshTokensAllowed"])
        self.assertFalse(contract["tokenExchange"])
        self.assertFalse(contract["scopePolicy"]["realmDefaultAllowed"])
        self.assertFalse(contract["scopePolicy"]["clientDefaultAllowed"])
        self.assertFalse(contract["scopePolicy"]["browserClientsAllowed"])

    def test_the_six_kernel_routes_carry_the_agreed_scope_and_role(self) -> None:
        routes = {(r["method"], r["path"]): r for r in self.contract["routes"]}
        self.assertEqual(set(routes), set(KERNEL_ROUTES))
        for key, (scope, role) in KERNEL_ROUTES.items():
            with self.subTest(route=key):
                route = routes[key]
                self.assertEqual(route["requiredScope"], scope)
                self.assertEqual(route["requiredRealmRole"], role)
                self.assertEqual(route["principalClasses"], ["SERVICE"])
                self.assertEqual(route["activation"], "PREPARED_DISABLED")
                self.assertEqual(route["allowedCallerClientIds"], [], "no caller is granted before the V3 contract is frozen")
                self.assertEqual(route["idempotencyKeyRequired"], key[0] == "POST")
                self.assertEqual(route["effectful"], key[0] == "POST")

    def test_every_named_scope_exists_as_an_optional_client_scope_definition(self) -> None:
        named = {r["requiredScope"] for r in self.contract["routes"]}
        named |= {r["requiredScope"] for r in self.contract["privateRoutes"]}
        self.assertEqual(named, PRIVILEGED_SCOPES)
        for scope in sorted(named):
            with self.subTest(scope=scope):
                document = load(CLIENT_SCOPE_DIR / f"{scope}.json")
                self.assertEqual(document["name"], scope)
                self.assertEqual(document["attributes"]["include.in.token.scope"], "true")
                self.assertEqual(document["protocolMappers"], [])

    def test_metrics_scrape_is_private_and_bound_to_monitoring_readonly(self) -> None:
        (metrics,) = self.contract["privateRoutes"]
        self.assertEqual((metrics["method"], metrics["path"]), ("GET", "/metrics"))
        self.assertEqual(metrics["exposure"], "private-network-only")
        self.assertFalse(metrics["throughKong"])
        self.assertFalse(metrics["throughCaddy"])
        self.assertEqual(metrics["callerClientId"], "monitoring-readonly")
        self.assertEqual(metrics["requiredScope"], "metrics.read")
        self.assertFalse(metrics["effectful"])
        client = load(CLIENT_DIR / "monitoring-readonly.json")
        self.assertTrue(client["serviceAccountsEnabled"])
        self.assertFalse(client["publicClient"])
        self.assertFalse(client["standardFlowEnabled"])
        self.assertIn("metrics.read", client.get("optionalClientScopes") or [])
        self.assertNotIn("metrics.read", client.get("defaultClientScopes") or [])
        audiences = {
            mapper["config"].get("included.custom.audience")
            for mapper in client.get("protocolMappers") or []
            if mapper.get("protocolMapper") == "oidc-audience-mapper"
        }
        self.assertIn("middleware-api", audiences)

    def test_platform_operator_role_is_prepared_but_provisioned_by_no_planner(self) -> None:
        (role_ref,) = self.contract["realmRoles"]
        self.assertEqual(role_ref["name"], "platform-operator")
        self.assertFalse(role_ref["provisioned"])
        self.assertEqual(role_ref["usedBy"], ["replay_operation"])
        role = load(ROOT / role_ref["definition"])
        self.assertEqual(role["name"], "platform-operator")
        self.assertFalse(role["composite"])
        self.assertFalse(role["clientRole"])
        attributes = role["attributes"]
        self.assertEqual(attributes["codestra.role.family"], ["platform-kernel"])
        self.assertEqual(attributes["codestra.role.level"], ["operator"])
        self.assertEqual(attributes["codestra.mfa.required"], ["true"])
        self.assertEqual(attributes["codestra.assignment.independent_approval"], ["true"])
        self.assertEqual(attributes["codestra.cross_family_grant"], ["false"])
        self.assertEqual(attributes["codestra.activation"], ["PREPARED_DISABLED"])
        # The only desired-state planner in the repository is rooted at the observability
        # family; the platform-kernel family therefore cannot be planned or applied yet.
        planner = OBSERVABILITY_PLANNER.read_text(encoding="utf-8")
        self.assertIn('"desired-state" / "observability"', planner)
        self.assertNotIn("platform-kernel", planner)

    def test_no_client_holds_a_platform_kernel_scope_and_replay_stays_service_only(self) -> None:
        for client_file in sorted(CLIENT_DIR.glob("*.json")):
            client = load(client_file)
            with self.subTest(client=client["clientId"]):
                self.assertFalse(set(client.get("defaultClientScopes") or ()) & PRIVILEGED_SCOPES)
                optional = set(client.get("optionalClientScopes") or ()) & PRIVILEGED_SCOPES
                if client["clientId"] == "monitoring-readonly":
                    self.assertEqual(optional, {"metrics.read"})
                else:
                    self.assertEqual(optional, set(), "platform scopes are attached to no client before activation")
        matrix = load(ACCESS_MATRIX)
        for grant in matrix["grants"]:
            held = set(grant["scopes"]) & PRIVILEGED_SCOPES
            if grant["callerClientId"] == "monitoring-readonly":
                self.assertEqual(held, {"metrics.read"}, grant)
                self.assertEqual(grant["targetClientId"], "middleware-api")
            else:
                self.assertEqual(held, set(), grant)


if __name__ == "__main__":
    unittest.main(verbosity=2)
