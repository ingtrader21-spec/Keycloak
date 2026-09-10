import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "webphone_contract", ROOT / "scripts/validate-webphone-production-client.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class WebphoneContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(
            (ROOT / "config/contracts/webphone-production-client.json").read_text())
        self.client = json.loads(
            (ROOT / "config/clients/codestra-provisioning-service.json").read_text())

    def test_production_contract(self):
        module.validate(self.contract, self.client)

    def test_rejects_staging_client_and_issuer(self):
        for key, value in [
            ("clientId", "codestra-provisioning-service-staging"),
            ("issuer", "https://auth-staging.codestra.co/realms/codestra"),
        ]:
            contract = copy.deepcopy(self.contract)
            contract[key] = value
            with self.assertRaises(ValueError):
                module.validate(contract, self.client)

    def test_rejects_broader_roles_and_shared_credentials(self):
        for key, value in [
            ("realmManagementRoles", ["view-users", "manage-users"]),
            ("realmRoles", ["realm-admin"]),
            ("adapterCredentialSharingAllowed", True),
        ]:
            contract = copy.deepcopy(self.contract)
            contract[key] = value
            with self.assertRaises(ValueError):
                module.validate(contract, self.client)

    def test_rejects_interactive_grants_and_long_tokens(self):
        for key in ["publicClient", "standardFlowEnabled", "implicitFlowEnabled",
                    "directAccessGrantsEnabled", "fullScopeAllowed"]:
            client = copy.deepcopy(self.client)
            client[key] = True
            with self.assertRaises(ValueError):
                module.validate(self.contract, client)
        self.client["attributes"]["access.token.lifespan"] = "3600"
        with self.assertRaises(ValueError):
            module.validate(self.contract, self.client)

    def test_rejects_wrong_audience_extra_scope_and_missing_claim(self):
        for mapper, key, value in [
            (0, "included.custom.audience", "middleware-api"),
            (1, "claim.value", "identity:rotate provisioning:execute provisioning:read admin"),
            (1, "claim.name", "scope"),
        ]:
            client = copy.deepcopy(self.client)
            client["protocolMappers"][mapper]["config"][key] = value
            with self.assertRaises(ValueError):
                module.validate(self.contract, client)
