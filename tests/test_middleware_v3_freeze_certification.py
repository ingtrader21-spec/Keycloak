"""PAS-8 lane 2 freeze: middleware-api audience, caller model, scopes, roles, MFA.

Every Keycloak artifact that describes Middleware V3 must pin the same route
contract digest, and the identity boundary derived from it must not widen.
Named *certification* so scripts/validate.sh discovers it on every PR.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts import validate_middleware_caller_classification as caller_cert


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"
EDGE = CONFIG / "desired-state" / "edge-integration-certification"
ROUTE_CONTRACT = EDGE / "middleware-public-api-route-contract.v2.json"
ROUTE_PIN = EDGE / "middleware-public-api-route-contract.sha256"
SERVICE_AUTHORITY = EDGE / "canonical-service-authority.v2.json"
ACCESS_V3 = CONFIG / "contracts" / "middleware-api-access.v3.json"
CALLERS = CONFIG / "contracts" / "middleware-caller-classification.v1.json"
PLATFORM_OPERATOR = CONFIG / "desired-state" / "platform-kernel" / "realm-roles" / "platform-operator.json"

FROZEN_SHA256 = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
FROZEN_ROUTE_COUNT = 117
AUDIENCE = "middleware-api"
PRODUCTION_ISSUER = "https://auth.codestra.co/realms/codestra"
PLATFORM_SCOPES = {"platform.command", "platform.command.read", "platform.command.replay"}
REPLAY_ROUTE = ("POST", "/platform/v1/operations/{operation_id}/replay")
# Only these four routes leave the middleware-api audience; any new one is a contract change.
NON_MIDDLEWARE_AUDIENCES = {
    ("GET", "/api/v1/callbacks"): "codestra-callback-api",
    ("POST", "/api/v1/control/callbacks"): "codestra-callback-api",
    ("POST", "/api/v1/integration/automation-results"): "codestra-odoo",
    ("POST", "/api/v1/integration/campaigns/actual-state"): "codestra-odoo",
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class MiddlewareV3FreezeCertificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load(ROUTE_CONTRACT)
        cls.access = load(ACCESS_V3)
        cls.callers = load(CALLERS)
        cls.routes = {(r["method"], r["path"]): r for r in cls.contract["routes"]}
        cls.access_routes = {(r["method"], r["path"]): r for r in cls.access["routes"]}

    def test_every_artifact_pins_the_same_route_contract(self) -> None:
        observed = caller_cert.canonical_route_digest(self.contract)
        self.assertEqual(observed, FROZEN_SHA256)
        self.assertEqual(ROUTE_PIN.read_text(encoding="utf-8").strip(), FROZEN_SHA256)
        self.assertEqual(self.access["source"]["sha256"], FROZEN_SHA256)
        self.assertEqual(self.callers["middleware"]["targetRouteContractSha256"], FROZEN_SHA256)
        self.assertEqual(load(SERVICE_AUTHORITY)["contract"]["sha256"], FROZEN_SHA256)
        self.assertEqual(len(self.routes), FROZEN_ROUTE_COUNT)
        self.assertEqual(self.access["source"]["routeCount"], FROZEN_ROUTE_COUNT)
        self.assertEqual(self.callers["middleware"]["targetRouteCount"], FROZEN_ROUTE_COUNT)

    def test_access_authority_matches_route_contract_row_for_row(self) -> None:
        self.assertEqual(set(self.routes), set(self.access_routes))
        for key, route in self.routes.items():
            row = self.access_routes[key]
            with self.subTest(route=key):
                self.assertEqual(row["operationId"], route["operation_id"])
                self.assertEqual(row["classification"], route["classification"])
                self.assertEqual(row["callingClient"], route["calling_client"])
                self.assertEqual(row["auth"], route["auth"])
                expected_audience = NON_MIDDLEWARE_AUDIENCES.get(key, AUDIENCE)
                self.assertEqual(row["audience"], expected_audience)
                self.assertEqual(route["audience"], expected_audience)
                if route["scope"] == "none":
                    self.assertIsNone(row["requiredScope"])
                else:
                    self.assertEqual(row["requiredScope"], route["scope"])

    def test_caller_model_certifies_against_the_frozen_target(self) -> None:
        report = caller_cert.certify(require_target_contract=True)
        self.assertEqual(report["verdict"], "PASS")
        self.assertTrue(report["routeContract"]["targetMatch"])
        self.assertEqual(report["callerAuthority"]["unknownCallerIdentities"], 0)
        self.assertEqual(report["privilegedDefaultScopeLeaks"], 0)
        self.assertFalse(report["liveApplyAuthorized"])
        self.assertFalse(report["dirtyDesktopAutoGrantAuthorized"])

    def test_token_policy_is_frozen(self) -> None:
        policy = self.callers["tokenPolicy"]
        self.assertEqual(policy["productionIssuer"], PRODUCTION_ISSUER)
        self.assertEqual(self.access["issuer"], PRODUCTION_ISSUER)
        self.assertEqual(self.callers["middleware"]["canonicalAudience"], AUDIENCE)
        self.assertEqual(self.access["targetAudience"], AUDIENCE)
        self.assertLessEqual(policy["maximumAccessTokenLifetimeSeconds"], 300)
        self.assertEqual(policy["serviceGrantType"], "client_credentials")
        self.assertEqual(policy["humanGrantType"], "authorization_code")
        self.assertTrue(policy["humanPkceRequired"])
        self.assertTrue(policy["privilegedHumanMfaRequired"])
        self.assertFalse(policy["wildcardCallerSelectorsAllowed"])
        self.assertFalse(policy["wildcardScopesAllowed"])
        self.assertFalse(policy["dirtyDesktopAutoGrantAuthorized"])
        self.assertIn("codestra-agent-desktop", policy["protectedUngrantableClientIds"])
        self.assertEqual(set(policy["privilegedScopes"]), PLATFORM_SCOPES)
        self.assertEqual(policy["privilegedRoles"], ["platform-operator"])

    def test_platform_scopes_are_optional_only_and_never_defaults(self) -> None:
        scope_policy = self.access["scopePolicy"]
        self.assertFalse(scope_policy["realmDefaultAllowed"])
        self.assertFalse(scope_policy["clientDefaultAllowedForPlatformScopes"])
        self.assertEqual(scope_policy["platformScopeAttachment"], "optional-only")
        declared = {s["name"]: s for s in self.access["platformAuthority"]["clientScopes"]}
        self.assertEqual(set(declared), PLATFORM_SCOPES)
        for name, entry in declared.items():
            with self.subTest(scope=name):
                self.assertEqual(entry["attachment"], "optional")
                self.assertFalse(entry["realmDefault"])
                self.assertEqual(load(ROOT / entry["definition"])["name"], name)
        self.assertFalse(PLATFORM_SCOPES & set(load(SERVICE_AUTHORITY)["realmDefaultClientScopes"]))
        for client_file in sorted((CONFIG / "clients").glob("*.json")):
            client = load(client_file)
            with self.subTest(client=client_file.name):
                self.assertFalse(PLATFORM_SCOPES & set(client.get("defaultClientScopes") or []))
                self.assertFalse(PLATFORM_SCOPES & set(client.get("optionalClientScopes") or []))

    def test_replay_requires_platform_operator_with_mfa(self) -> None:
        replay = self.access_routes[REPLAY_ROUTE]
        self.assertEqual(replay["requiredScope"], "platform.command.replay")
        self.assertEqual(replay["requiredRealmRole"], "platform-operator")
        role_routes = [k for k, r in self.access_routes.items() if r.get("requiredRealmRole")]
        self.assertEqual(role_routes, [REPLAY_ROUTE])
        role = load(PLATFORM_OPERATOR)
        self.assertFalse(role["composite"])
        self.assertEqual(role["attributes"]["codestra.mfa.required"], ["true"])
        self.assertEqual(role["attributes"]["codestra.assignment.independent_approval"], ["true"])
        self.assertEqual(role["attributes"]["codestra.activation"], ["PREPARED_DISABLED"])
        declared = self.access["platformAuthority"]["realmRoles"]
        self.assertEqual([r["name"] for r in declared], ["platform-operator"])
        self.assertTrue(declared[0]["mfaRequired"])

    def test_service_authority_grants_no_platform_or_human_selector(self) -> None:
        authority = load(SERVICE_AUTHORITY)
        for client in authority["clients"]:
            with self.subTest(client=client["clientId"]):
                self.assertFalse(PLATFORM_SCOPES & set(client["scopes"]))
                self.assertEqual(client["defaultClientScopes"], [])
                self.assertFalse(client["productionActivationAuthorized"])
        granted = {c["clientId"] for c in authority["clients"]}
        self.assertFalse(granted & set(authority["unresolvedHumanOrDelegatedAzpSelectors"]))
        self.assertNotIn("codestra-agent-desktop", granted)
        self.assertFalse(authority["productionActivationAuthorized"])


if __name__ == "__main__":
    unittest.main()
