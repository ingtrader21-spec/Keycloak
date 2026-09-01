from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "provider_authority", ROOT / "scripts" / "validate-provider-control-authority.py"
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ProviderControlAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(VALIDATOR.CONTRACT.read_text(encoding="utf-8"))

    def reject(self, contract: dict) -> None:
        with self.assertRaises(ValueError):
            VALIDATOR.validate(contract)

    def test_canonical_contract_passes(self) -> None:
        VALIDATOR.validate(copy.deepcopy(self.contract))

    def test_direct_middleware_provider_grant_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["grants"].append({
            "callerClientId": "middleware-api",
            "targetClientId": "telnexa-gateway",
            "audience": "telnexa-gateway",
            "scopes": ["sms.send"],
        })
        self.reject(contract)

    def test_direct_n8n_provider_grant_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["grants"].append({
            "callerClientId": "n8n-automation",
            "targetClientId": "klyrow-gateway",
            "audience": "klyrow-gateway",
            "scopes": ["email.send"],
        })
        self.reject(contract)

    def test_missing_worker_readback_scope_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        grant = next(
            item for item in contract["grants"]
            if item["callerClientId"] == "middleware-worker"
            and item["targetClientId"] == "telnexa-gateway"
        )
        grant["scopes"].remove("sms.status.read")
        self.reject(contract)

    def test_application_scope_swap_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        grant = next(
            item for item in contract["grants"]
            if item["callerClientId"] == "codestra-ai"
        )
        grant["scopes"] = ["marketing.campaign.request"]
        self.reject(contract)


if __name__ == "__main__":
    unittest.main()
