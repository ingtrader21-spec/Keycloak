from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class KongOidcContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.endpoints = load(CONFIG / "endpoints" / "codestra.json")
        self.kong = load(CONFIG / "clients" / "kong-gateway.json")
        self.matrix = load(CONFIG / "contracts" / "service-access-matrix.json")

    def test_canonical_codestra_issuer_and_discovery(self) -> None:
        issuer = "https://auth.codestra.co/realms/codestra"
        self.assertEqual(self.endpoints["issuer"], issuer)
        self.assertEqual(
            self.endpoints["discoveryUrl"],
            issuer + "/.well-known/openid-configuration",
        )
        self.assertEqual(
            self.endpoints["jwksUri"],
            issuer + "/protocol/openid-connect/certs",
        )

    def test_kong_gateway_is_confidential_service_account(self) -> None:
        self.assertEqual(self.kong["clientId"], "kong-gateway")
        self.assertFalse(self.kong["publicClient"])
        self.assertTrue(self.kong["serviceAccountsEnabled"])
        self.assertFalse(self.kong["standardFlowEnabled"])
        self.assertFalse(self.kong["implicitFlowEnabled"])
        self.assertFalse(self.kong["directAccessGrantsEnabled"])
        self.assertFalse(self.kong["fullScopeAllowed"])
        self.assertEqual(self.kong["redirectUris"], [])
        self.assertEqual(self.kong["webOrigins"], [])

    def test_kong_gateway_has_no_literal_secret(self) -> None:
        serialized = json.dumps(self.kong).lower()
        self.assertNotIn('"secret"', serialized)
        self.assertNotIn('"credentials"', serialized)
        self.assertNotIn('access_token', serialized)
        self.assertNotIn('refresh_token', serialized)

    def test_kong_gateway_emits_middleware_audience_and_scopes(self) -> None:
        mappers = {item["name"]: item for item in self.kong["protocolMappers"]}
        self.assertEqual(
            mappers["audience-middleware-api"]["config"]["included.custom.audience"],
            "middleware-api",
        )
        scopes = set(
            mappers["reviewed-service-scopes"]["config"]["claim.value"].split()
        )
        self.assertEqual(
            scopes,
            {"middleware.request.forward", "middleware.status.read"},
        )
        self.assertEqual(
            mappers["tenant-id-from-service-account"]["config"],
            {
                "user.attribute": "tenant_id",
                "claim.name": "tenant_id",
                "jsonType.label": "String",
                "id.token.claim": "false",
                "access.token.claim": "true",
                "userinfo.token.claim": "false",
                "multivalued": "false",
            },
        )

    def test_service_access_matrix_has_exact_kong_middleware_grant(self) -> None:
        grants = [
            item
            for item in self.matrix["grants"]
            if item["callerClientId"] == "kong-gateway"
            and item["targetClientId"] == "middleware-api"
        ]
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0]["audience"], "middleware-api")
        self.assertEqual(
            set(grants[0]["scopes"]),
            {"middleware.request.forward", "middleware.status.read"},
        )

    def test_machine_token_lifetime_is_short(self) -> None:
        self.assertLessEqual(
            int(self.kong["attributes"]["access.token.lifespan"]),
            300,
        )


if __name__ == "__main__":
    unittest.main()
