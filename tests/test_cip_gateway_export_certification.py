"""CIP Foundation 3 / I1 step 5: exact identity contract and desired-state evidence for Kong.

The release artifacts under release/cip-tenant-identity/ are what Kong (I2)
consumes by digest. These tests prove they are the exact deterministic
rendering of the contract, that every digest they cite matches the committed
file, and that production stays fail-closed.
"""

from __future__ import annotations

import copy
import hashlib
import unittest

from scripts import cip_tenant_identity as cip
from scripts import cip_tenant_token_matrix as matrix_cert


class CipGatewayExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract, cls.rendered = cip.build()
        cls.release = cip.build_release(cls.contract, cls.rendered)
        cls.plan = cls.release[cip.PLAN_PATH]
        cls.gateway = cls.release[cip.GATEWAY_PATH]

    def test_committed_release_artifacts_are_exact_and_checksummed(self) -> None:
        cip.check_release(self.release)
        for path in (cip.PLAN_PATH, cip.GATEWAY_PATH):
            with self.subTest(artifact=path.name):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(cip.checksum_path(path).read_text(encoding="utf-8"), f"{digest}  {path.name}\n")

    def test_contract_change_without_regeneration_is_detected(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["productScopes"][4]["description"] += " Changed."
        stale = cip.build_release(contract, cip.render_desired_state(contract))
        with self.assertRaisesRegex(cip.IdentityError, "stale"):
            cip.check_release(stale)

    def test_gateway_authority_digests_match_the_committed_sources(self) -> None:
        authority = self.gateway["authority"]
        self.assertEqual(authority["contractSha256"], cip.sha256_of(cip.load_json(cip.CONTRACT_PATH)))
        self.assertEqual(authority["tokenMatrixSha256"], cip.sha256_of(cip.load_json(cip.MATRIX_PATH)))
        self.assertEqual(authority["parityEvidenceSha256"], cip.sha256_of(cip.load_json(cip.PARITY_RECORD)))
        self.assertEqual(authority["desiredStatePlanSha256"], hashlib.sha256(cip.PLAN_PATH.read_bytes()).hexdigest())
        self.assertEqual(authority["configurationChecksum"], self.plan["configurationChecksum"])

    def test_plan_targets_staging_only_and_never_changes_frozen_scopes(self) -> None:
        self.assertEqual(self.plan["environment"], "staging")
        self.assertTrue(all(value is False for value in self.plan["repositoryBoundary"].values()))
        actions = {op["action"] for op in self.plan["operations"]}
        self.assertEqual(
            actions,
            {cip.STAGING_ACTION, "REFERENCE_FROZEN_DEFINITION_UNCHANGED", "BLOCKED_ORIGIN_UNRESOLVED"},
        )
        for op in self.plan["operations"]:
            if op["action"] == "REFERENCE_FROZEN_DEFINITION_UNCHANGED":
                with self.subTest(scope=op["resourceId"]):
                    frozen = cip.load_json(cip.FROZEN_SCOPE_DIR / f"{op['resourceId']}.json")
                    self.assertEqual(op["desiredSha256"], cip.sha256_of(frozen))
        blocked = [op["resourceId"] for op in self.plan["operations"] if op["action"] == "BLOCKED_ORIGIN_UNRESOLVED"]
        self.assertEqual(blocked, ["cip-portal"])

    def test_plan_source_files_cover_every_desired_state_file(self) -> None:
        listed = {entry["path"] for entry in self.plan["sourceFiles"]}
        on_disk = {cip.relative(path) for path in cip.DESIRED_ROOT.rglob("*.json")}
        self.assertEqual(listed, on_disk)

    def test_production_registry_is_empty_and_staging_matches_desired_state(self) -> None:
        self.assertEqual(self.gateway["environments"]["production"]["azpRegistry"], {})
        staging = self.gateway["environments"]["staging"]["azpRegistry"]
        self.assertEqual(set(staging), {entry["clientId"] for entry in cip.rendered_clients(self.contract)})
        for client_id, record in staging.items():
            client = self.rendered[cip.DESIRED_ROOT / "clients" / f"{client_id}.json"]
            with self.subTest(client=client_id):
                self.assertEqual(record["allowedScopes"], client["optionalClientScopes"])
                if record["actorKind"] == "service":
                    tenant = next(m for m in client["protocolMappers"] if m["name"] == "claim-tenant-id")
                    self.assertEqual(record["tenant"], tenant["config"]["claim.value"])

    def test_claim_names_match_what_middleware_and_kong_read(self) -> None:
        token = self.gateway["token"]
        self.assertEqual(token["tenantClaim"], "tenant_id")
        self.assertEqual(token["consumerClaim"], "azp")
        self.assertEqual(token["audience"], "middleware-api")
        self.assertIn("tenant_ids", token["prohibitedTenantClaims"])
        self.assertIn("tenant", token["prohibitedTenantClaims"])
        self.assertEqual(token["maximumAccessTokenLifetimeSeconds"], 300)
        self.assertEqual(token["signingAlgorithms"], ["RS256"])

    def test_unbound_scopes_satisfy_no_route_and_bound_routes_exist(self) -> None:
        routes = matrix_cert.access_routes()
        for scope in self.gateway["productScopes"]:
            binding = scope["routeBinding"]
            with self.subTest(scope=scope["name"]):
                if binding["status"] == "BOUND":
                    self.assertTrue(binding["routes"])
                    for route in binding["routes"]:
                        self.assertEqual(routes[(route["method"], route["path"])]["requiredScope"], scope["name"])
                        self.assertEqual(routes[(route["method"], route["path"])]["audience"], "middleware-api")
                else:
                    self.assertEqual(binding["routes"], [])

    def test_failure_codes_cover_every_verifier_category_and_status(self) -> None:
        codes = self.gateway["failureCodes"]
        self.assertEqual(set(codes), matrix_cert.FAILURES - {"grant"})
        for name, code in codes.items():
            with self.subTest(failure=name):
                self.assertEqual(code["status"], matrix_cert.http_status([name]))
        self.assertEqual(codes["tenant"]["error"], "cross_tenant_denied")
        self.assertEqual(codes["scope"]["error"], "insufficient_scope")

    def test_conformance_counts_match_the_certified_matrix(self) -> None:
        report = matrix_cert.certify()
        self.assertEqual(self.gateway["conformance"]["positiveCases"], report["positiveCases"])
        self.assertEqual(self.gateway["conformance"]["negativeCases"], report["negativeCases"])

    def test_release_carries_no_secret_and_authorizes_nothing(self) -> None:
        for document in self.release.values():
            cip.assert_no_secret(document, "release")
        self.assertTrue(all(value is False for value in self.gateway["boundary"].values()))
        self.assertEqual(self.gateway["status"], "PREPARED_DISABLED")


if __name__ == "__main__":
    unittest.main()
