from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "service_integrations",
    ROOT / "scripts" / "validate-service-integrations.py",
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class PlatformApiIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.machine = json.loads(
            (ROOT / "config/contracts/machine-clients.json").read_text(encoding="utf-8")
        )
        cls.access = json.loads(
            (ROOT / "config/contracts/service-access-matrix.json").read_text(encoding="utf-8")
        )
        cls.clients = {
            client_id: json.loads(
                (ROOT / f"config/clients/{client_id}.json").read_text(encoding="utf-8")
            )
            for client_id in ("sdk-intake", "alertmanager", "kong-gateway", "n8n-automation")
        }

    def test_canonical_machine_and_access_contracts_pass(self) -> None:
        VALIDATOR.validate_machine_contract(copy.deepcopy(self.machine))
        grants = VALIDATOR.validate_access_matrix(copy.deepcopy(self.access))
        self.assertEqual(
            grants[("sdk-intake", "middleware-api")],
            {"leads.write", "surveys.write"},
        )
        self.assertEqual(
            grants[("alertmanager", "middleware-api")],
            {"alerts.write"},
        )

    def test_sdk_intake_has_only_lead_and_survey_write_scopes(self) -> None:
        VALIDATOR.validate_client_document(
            "sdk-intake",
            copy.deepcopy(self.clients["sdk-intake"]),
            {"leads.write", "surveys.write"},
        )

    def test_alertmanager_is_write_only(self) -> None:
        VALIDATOR.validate_client_document(
            "alertmanager",
            copy.deepcopy(self.clients["alertmanager"]),
            {"alerts.write"},
        )

    def test_sdk_intake_scope_expansion_is_rejected(self) -> None:
        access = copy.deepcopy(self.access)
        grant = next(
            item for item in access["grants"]
            if item["callerClientId"] == "sdk-intake"
        )
        grant["scopes"].append("odoo.leads.write")
        grant["scopes"].sort()
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.validate_access_matrix(access)

    def test_alertmanager_read_scope_is_rejected(self) -> None:
        access = copy.deepcopy(self.access)
        grant = next(
            item for item in access["grants"]
            if item["callerClientId"] == "alertmanager"
        )
        grant["scopes"] = ["alerts.read", "alerts.write"]
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.validate_access_matrix(access)

    def test_alertmanager_provider_bypass_is_rejected(self) -> None:
        access = copy.deepcopy(self.access)
        access["grants"].append(
            {
                "callerClientId": "alertmanager",
                "targetClientId": "klyrow-gateway",
                "audience": "klyrow-gateway",
                "scopes": ["email.send"],
            }
        )
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.validate_access_matrix(access)

    def test_wildcard_scope_is_rejected(self) -> None:
        access = copy.deepcopy(self.access)
        grant = next(
            item for item in access["grants"]
            if item["callerClientId"] == "sdk-intake"
        )
        grant["scopes"] = ["*"]
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.validate_access_matrix(access)

    def test_machine_refresh_tokens_and_full_scope_are_rejected(self) -> None:
        access = copy.deepcopy(self.access)
        access["tokenPolicy"]["refreshTokensAllowed"] = True
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.validate_access_matrix(access)

        access = copy.deepcopy(self.access)
        access["tokenPolicy"]["fullScopeAllowed"] = True
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.validate_access_matrix(access)

    def test_unbounded_machine_token_lifetime_is_rejected(self) -> None:
        access = copy.deepcopy(self.access)
        access["tokenPolicy"]["maximumAccessTokenLifetimeSeconds"] = 301
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.validate_access_matrix(access)

        client = copy.deepcopy(self.clients["sdk-intake"])
        client["attributes"]["access.token.lifespan"] = "301"
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.validate_client_document(
                "sdk-intake", client, {"leads.write", "surveys.write"}
            )

    def test_password_implicit_and_device_flows_are_rejected(self) -> None:
        for field in (
            "directAccessGrantsEnabled",
            "implicitFlowEnabled",
            "standardFlowEnabled",
        ):
            client = copy.deepcopy(self.clients["sdk-intake"])
            client[field] = True
            with self.assertRaises(VALIDATOR.ContractError):
                VALIDATOR.validate_client_document(
                    "sdk-intake", client, {"leads.write", "surveys.write"}
                )

        client = copy.deepcopy(self.clients["sdk-intake"])
        client["attributes"]["oauth2.device.authorization.grant.enabled"] = "true"
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.validate_client_document(
                "sdk-intake", client, {"leads.write", "surveys.write"}
            )

    def test_committed_secret_is_rejected(self) -> None:
        client = copy.deepcopy(self.clients["sdk-intake"])
        client["clientSecret"] = "must-not-be-committed"
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.validate_client_document(
                "sdk-intake", client, {"leads.write", "surveys.write"}
            )

    def test_static_tenant_claim_on_shared_gateway_is_rejected(self) -> None:
        for client_id in ("kong-gateway", "n8n-automation"):
            client = copy.deepcopy(self.clients[client_id])
            client.setdefault("protocolMappers", []).append(
                {
                    "name": "static-tenant",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-hardcoded-claim-mapper",
                    "consentRequired": False,
                    "config": {
                        "claim.name": "tenant_id",
                        "claim.value": "one-tenant-for-all-requests",
                        "jsonType.label": "String",
                        "access.token.claim": "true",
                    },
                }
            )
            with self.assertRaises(VALIDATOR.ContractError):
                VALIDATOR.validate_client_document(client_id, client)


if __name__ == "__main__":
    unittest.main()
