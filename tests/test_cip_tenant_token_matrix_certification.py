"""CIP Foundation 3 / I1 step 4: negative token matrix.

Certifies the CIP tenant token matrix (issuer, audience, azp, scope, tenant,
expiry, service-account misuse and privilege escalation, plus project, MFA and
algorithm). The runner itself is tested too: a matrix that expects the wrong
verdict must fail, and every base fixture must be accepted unmutated so each
rejection is caused by its own mutation.
"""

from __future__ import annotations

import copy
import unittest

from scripts import cip_tenant_identity as cip
from scripts import cip_tenant_token_matrix as matrix_cert


class CipTenantTokenMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract, _ = cip.build()
        cls.matrix = cip.load_json(matrix_cert.MATRIX_PATH)
        cls.report = matrix_cert.validate_matrix(cls.contract, cls.matrix)
        cls.routes = matrix_cert.access_routes()

    def test_matrix_certifies_every_required_dimension(self) -> None:
        self.assertEqual(self.report["verdict"], "PASS")
        self.assertEqual(self.matrix["requiredDimensions"], matrix_cert.REQUIRED_DIMENSIONS)
        for dimension in matrix_cert.REQUIRED_DIMENSIONS:
            counts = self.report["dimensions"][dimension]
            with self.subTest(dimension=dimension):
                self.assertGreaterEqual(counts["ACCEPT"], 1)
                self.assertGreaterEqual(counts["REJECT"], matrix_cert.MINIMUM_NEGATIVES_PER_REQUIRED_DIMENSION)
        self.assertGreater(self.report["negativeCases"], 60)

    def test_every_base_fixture_is_accepted_unmutated(self) -> None:
        for name in self.matrix["fixtures"]:
            with self.subTest(fixture=name):
                result = matrix_cert.run_case(self.contract, self.matrix, {"id": name, "fixture": name}, self.routes)
                self.assertEqual(result["verdict"], "ACCEPT", result["failures"])

    def test_runner_fails_when_a_negative_case_expects_accept(self) -> None:
        matrix = copy.deepcopy(self.matrix)
        case = next(c for c in matrix["cases"] if c["id"] == "tenant-body-other-tenant")
        case["expect"] = "ACCEPT"
        with self.assertRaisesRegex(matrix_cert.MatrixError, "expected ACCEPT, got REJECT"):
            matrix_cert.validate_matrix(self.contract, matrix)

    def test_runner_fails_when_the_rejection_reason_is_wrong(self) -> None:
        matrix = copy.deepcopy(self.matrix)
        case = next(c for c in matrix["cases"] if c["id"] == "tenant-body-other-tenant")
        case["mustFail"] = "scope"
        with self.assertRaisesRegex(matrix_cert.MatrixError, "must fail 'scope'"):
            matrix_cert.validate_matrix(self.contract, matrix)

    def test_runner_rejects_fixtures_on_routes_middleware_does_not_expose(self) -> None:
        matrix = copy.deepcopy(self.matrix)
        matrix["cases"][0]["mutations"] = {"request.path": "/platform/v1/usage"}
        with self.assertRaisesRegex(matrix_cert.MatrixError, "not a Middleware route"):
            matrix_cert.validate_matrix(self.contract, matrix)

    def test_every_tenant_selector_location_has_a_negative_case(self) -> None:
        locations = {
            "request.headers.X-Tenant-ID",
            "request.body.tenant_id",
            "request.body.command.tenant_id",
            "request.query.tenant_id",
            "request.pathParams.tenant_id",
        }
        mutated = {
            path
            for case in self.matrix["cases"]
            if case["dimension"] in {"tenant", "privilege-escalation"} and case["expect"] == "REJECT"
            for path in (case.get("mutations") or {})
        }
        self.assertTrue(locations <= mutated, sorted(locations - mutated))

    def test_body_tenant_is_a_selector_never_authority(self) -> None:
        base = copy.deepcopy(self.matrix["fixtures"]["userCommandSubmit"])
        self.assertEqual(matrix_cert.verify_request(self.contract, base), [])
        other = copy.deepcopy(base)
        other["request"]["body"]["command"]["tenant_id"] = "TEST_SYN_TENANT_B"
        self.assertEqual(matrix_cert.verify_request(self.contract, other), ["tenant"])
        claimless = copy.deepcopy(base)
        del claimless["token"]["claims"]["tenant_id"]
        claimless["request"]["headers"] = {}
        self.assertEqual(matrix_cert.verify_request(self.contract, claimless), ["tenant"])

    def test_keycloak_issuance_is_role_gated_and_tenant_is_admin_only(self) -> None:
        fixture = copy.deepcopy(self.matrix["fixtures"]["issueUser"])
        fixture["principal"]["realmRoles"] = ["cip-usage-viewer"]
        fixture["requestedScopes"] = list(cip.PRODUCT_SCOPES) + ["platform.command.replay", "platform.tenants.read"]
        claims, issued, refusal = matrix_cert.issue_token(self.contract, fixture)
        self.assertIsNone(refusal)
        self.assertEqual(issued, ["cip.usage.read"])
        self.assertEqual(claims["tenant_id"], "TEST_SYN_TENANT_A")
        fixture["principal"]["attributes"]["codestra_tenant_id"]["setBy"] = "user"
        claims, _, _ = matrix_cert.issue_token(self.contract, fixture)
        self.assertNotIn("tenant_id", claims)

    def test_service_issuance_uses_the_client_tenant_and_no_amr(self) -> None:
        fixture = copy.deepcopy(self.matrix["fixtures"]["issueService"])
        fixture["requestedScopes"] = list(cip.PRODUCT_SCOPES)
        claims, issued, refusal = matrix_cert.issue_token(self.contract, fixture)
        self.assertIsNone(refusal)
        self.assertEqual(issued, ["platform.command", "platform.command.read", "cip.usage.read"])
        self.assertEqual(claims["tenant_id"], "TEST_SYN_TENANT_A")
        self.assertEqual(claims["codestra_actor_kind"], "service")
        self.assertNotIn("amr", claims)

    def test_status_codes_separate_authentication_from_authorization(self) -> None:
        for case in self.report["cases"]:
            if case["verdict"] == "REJECT" and case["tokenIssued"]:
                with self.subTest(case=case["id"]):
                    expected = 401 if matrix_cert.UNAUTHENTICATED & set(case["failures"]) else 403
                    self.assertEqual(case["status"], expected)

    def test_legacy_v3_matrix_is_unchanged(self) -> None:
        legacy = cip.load_json(cip.ROOT / "config" / "certification" / "v3-token-matrix.v1.json")
        self.assertEqual(len(legacy["cases"]), 16)
        self.assertEqual(legacy["mission"], "PAS-157")


if __name__ == "__main__":
    unittest.main()
