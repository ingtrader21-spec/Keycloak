"""CIP Foundation 3 / I1 step 2: human, service-account and tenant/project claim authority.

The tenant a CIP request acts for comes from the verified token only: an
admin-only user-profile attribute for humans, a hardcoded mapper on a dedicated
single-tenant client for service accounts. These tests prove every way of
self-asserting or widening that tenant is rejected by the contract validator or
by the rendered-client invariants.
"""

from __future__ import annotations

import copy
import json
import unittest

from scripts import cip_tenant_identity as cip


def client_entry(contract: dict, client_id: str) -> dict:
    return next(entry for entry in contract["clients"] if entry["clientId"] == client_id)


class CipTenantIdentityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract, cls.rendered = cip.build()

    def mutated(self) -> dict:
        return copy.deepcopy(self.contract)

    def assert_contract_rejected(self, contract: dict, message: str) -> None:
        with self.assertRaisesRegex(cip.IdentityError, message):
            cip.validate_contract(contract)

    def test_committed_desired_state_is_the_exact_rendering(self) -> None:
        cip.check_desired_state(self.rendered)
        self.assertEqual(self.contract["audience"], "middleware-api")
        self.assertEqual(self.contract["tokenPolicy"]["requiredClaims"][-2:], ["tenant_id", "codestra_actor_kind"])

    def test_cip_clients_stay_outside_live_managed_policy(self) -> None:
        managed = set(cip.load_json(cip.MANAGED_POLICY)["clients"])
        for entry in self.contract["clients"]:
            with self.subTest(client=entry["clientId"]):
                self.assertNotIn(entry["clientId"], managed)
                self.assertFalse((cip.LIVE_CLIENTS_DIR / f"{entry['clientId']}.json").exists())

    def test_human_tenant_attribute_editable_by_user_is_rejected(self) -> None:
        contract = self.mutated()
        contract["claims"]["tenant_id"]["sources"]["user"]["attributePermissions"]["edit"] = ["admin", "user"]
        self.assert_contract_rejected(contract, "admin-only user attribute")

    def test_unmanaged_attributes_editable_by_users_are_rejected(self) -> None:
        contract = self.mutated()
        contract["userProfile"]["unmanagedAttributePolicy"] = "ENABLED"
        self.assert_contract_rejected(contract, "unmanaged attributes")

    def test_browser_client_bound_to_a_tenant_is_rejected(self) -> None:
        contract = self.mutated()
        client_entry(contract, "test-syn-cip-portal")["tenant"] = "TEST_SYN_TENANT_A"
        self.assert_contract_rejected(contract, "browser client must not bind a tenant")

    def test_service_client_without_exactly_one_tenant_is_rejected(self) -> None:
        for bad in (None, "", "*", "TENANT A"):
            contract = self.mutated()
            entry = client_entry(contract, "test-syn-cip-tenant-a-automation")
            if bad is None:
                entry.pop("tenant")
            else:
                entry["tenant"] = bad
            with self.subTest(tenant=bad):
                self.assert_contract_rejected(contract, "needs one tenant")

    def test_shared_or_protected_identity_cannot_become_a_cip_client(self) -> None:
        for client_id in ("kong-gateway", "n8n-automation", "codestra-agent-desktop"):
            contract = self.mutated()
            entry = copy.deepcopy(client_entry(contract, "test-syn-cip-tenant-a-automation"))
            entry["clientId"] = client_id
            contract["clients"].append(entry)
            with self.subTest(client=client_id):
                self.assert_contract_rejected(contract, "managed-client policy|shared or protected")

    def test_audience_is_frozen_to_middleware_api(self) -> None:
        contract = self.mutated()
        contract["audience"] = "codestra-api"
        self.assert_contract_rejected(contract, "frozen to middleware-api")

    def test_route_contract_pin_cannot_drift_from_the_parity_record(self) -> None:
        contract = self.mutated()
        contract["middlewareRouteContract"]["sha256"] = "e5e71fe63e329d55fa884315cfe89bd53be0bafbf9fc6f72054b9a4b4483c28e"
        self.assert_contract_rejected(contract, "route contract digest")

    def test_prohibited_multi_tenant_claims_cannot_be_relaxed(self) -> None:
        contract = self.mutated()
        contract["prohibitedTenantClaims"].remove("tenant_ids")
        self.assert_contract_rejected(contract, "prohibited tenant claims")

    def test_tenant_selectors_must_remain_selector_only(self) -> None:
        contract = self.mutated()
        contract["tenantSelectors"]["rule"] = "The body tenant_id is authoritative when present."
        self.assert_contract_rejected(contract, "selector-only")

    def test_human_mfa_and_pkce_cannot_be_weakened(self) -> None:
        for path, value, message in (
            (("user", "mfaRequired"), False, "MFA"),
            (("user", "pkceMethod"), "plain", "PKCE S256"),
            (("service", "grantType"), "password", "client_credentials"),
        ):
            contract = self.mutated()
            contract["actorKinds"][path[0]][path[1]] = value
            with self.subTest(field=path):
                self.assert_contract_rejected(contract, message)

    def test_production_client_is_never_rendered_with_a_guessed_origin(self) -> None:
        portal = client_entry(self.contract, "cip-portal")
        self.assertFalse(portal["rendered"])
        self.assertEqual(portal["status"], "BLOCKED_ORIGIN_UNRESOLVED")
        contract = self.mutated()
        entry = client_entry(contract, "cip-portal")
        entry.update({"rendered": True, "redirectUris": ["https://portal.codestra.co/callback"], "webOrigins": []})
        self.assert_contract_rejected(contract, "only staging CIP clients")

    def test_secret_values_are_rejected(self) -> None:
        contract = self.mutated()
        client_entry(contract, "test-syn-cip-tenant-a-automation")["clientSecret"] = "must-not-be-committed"
        self.assert_contract_rejected(contract, "secret-bearing")


class CipRenderedClientInvariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract, cls.rendered = cip.build()

    def doc(self, client_id: str) -> tuple[dict, dict]:
        entry = client_entry(self.contract, client_id)
        return entry, copy.deepcopy(self.rendered[cip.DESIRED_ROOT / "clients" / f"{client_id}.json"])

    def assert_client_rejected(self, entry: dict, client: dict, message: str) -> None:
        with self.assertRaisesRegex(cip.IdentityError, message):
            cip.validate_client_document(self.contract, entry, client)

    def test_service_tenant_is_hardcoded_and_exact(self) -> None:
        entry, client = self.doc("test-syn-cip-tenant-a-automation")
        mapper = next(m for m in client["protocolMappers"] if m["name"] == "claim-tenant-id")
        self.assertEqual(mapper["protocolMapper"], "oidc-hardcoded-claim-mapper")
        self.assertEqual(mapper["config"]["claim.value"], "TEST_SYN_TENANT_A")
        mapper["config"]["claim.value"] = "TEST_SYN_TENANT_B"
        self.assert_client_rejected(entry, client, "tenant_id must be hardcoded")

    def test_service_tenant_from_a_mutable_attribute_is_rejected(self) -> None:
        entry, client = self.doc("test-syn-cip-tenant-a-automation")
        mapper = next(m for m in client["protocolMappers"] if m["name"] == "claim-tenant-id")
        mapper["protocolMapper"] = "oidc-usermodel-attribute-mapper"
        self.assert_client_rejected(entry, client, "tenant_id must be hardcoded")

    def test_multi_tenant_claim_on_any_client_is_rejected(self) -> None:
        for client_id in ("test-syn-cip-portal", "test-syn-cip-tenant-a-automation"):
            entry, client = self.doc(client_id)
            client["protocolMappers"].append(
                cip._hardcoded("claim-tenant-ids", "tenant_ids", json.dumps(["A", "B"]), "JSON")
            )
            with self.subTest(client=client_id):
                self.assert_client_rejected(entry, client, "prohibited tenant claim tenant_ids")

    def test_browser_client_cannot_hardcode_a_tenant(self) -> None:
        entry, client = self.doc("test-syn-cip-portal")
        client["protocolMappers"].append(cip._hardcoded("claim-tenant-id", "tenant_id", "TEST_SYN_TENANT_A", "String"))
        self.assert_client_rejected(entry, client, "must not hardcode a tenant")

    def test_browser_client_takes_tenant_only_from_the_user_context_scope(self) -> None:
        entry, client = self.doc("test-syn-cip-portal")
        self.assertEqual(client["defaultClientScopes"], ["basic", "cip.user.context"])
        client["defaultClientScopes"] = ["basic"]
        self.assert_client_rejected(entry, client, "basic \\+ cip.user.context")

    def test_service_client_cannot_read_user_attributes(self) -> None:
        entry, client = self.doc("test-syn-cip-tenant-a-automation")
        client["optionalClientScopes"].append("cip.user.context")
        self.assert_client_rejected(entry, client, "must not read user attributes")

    def test_actor_kind_claim_must_match_the_client_shape(self) -> None:
        entry, client = self.doc("test-syn-cip-tenant-a-automation")
        mapper = next(m for m in client["protocolMappers"] if m["name"] == "claim-codestra-actor-kind")
        mapper["config"]["claim.value"] = "user"
        self.assert_client_rejected(entry, client, "codestra_actor_kind")

    def test_service_client_with_browser_flow_is_rejected(self) -> None:
        entry, client = self.doc("test-syn-cip-tenant-a-automation")
        client["standardFlowEnabled"] = True
        self.assert_client_rejected(entry, client, "confidential client_credentials only")

    def test_second_audience_or_token_exchange_is_rejected(self) -> None:
        entry, client = self.doc("test-syn-cip-tenant-a-automation")
        extra = copy.deepcopy(client["protocolMappers"][0])
        extra["name"] = "audience-codestra-api"
        extra["config"]["included.custom.audience"] = "codestra-api"
        client["protocolMappers"].append(extra)
        self.assert_client_rejected(entry, client, "only emitted audience")
        entry, client = self.doc("test-syn-cip-tenant-a-automation")
        client["attributes"]["standard.token.exchange.enabled"] = "true"
        self.assert_client_rejected(entry, client, "token exchange")

    def test_user_profile_attributes_are_admin_only(self) -> None:
        profile = copy.deepcopy(self.rendered[cip.DESIRED_ROOT / "user-profile" / "cip-tenant-attributes.json"])
        cip.validate_user_profile(profile)
        profile["attributes"][0]["permissions"]["edit"] = ["admin", "user"]
        with self.assertRaisesRegex(cip.IdentityError, "admin-only"):
            cip.validate_user_profile(profile)
        profile = copy.deepcopy(self.rendered[cip.DESIRED_ROOT / "user-profile" / "cip-tenant-attributes.json"])
        profile["attributes"][0]["required"] = {"roles": ["user"]}
        with self.assertRaisesRegex(cip.IdentityError, "registration"):
            cip.validate_user_profile(profile)


if __name__ == "__main__":
    unittest.main()
