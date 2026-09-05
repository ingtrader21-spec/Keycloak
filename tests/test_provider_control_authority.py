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
CALLING_CONTRACT_LOCK = ROOT / ".codestra" / "calling-contract.lock.json"


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


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

    def test_direct_application_provider_grant_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["grants"].append({
            "callerClientId": "codestra-ai",
            "targetClientId": "ai-provider-adapter",
            "audience": "ai-provider-adapter",
            "scopes": ["ai.provider.dispatch"],
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

    def test_missing_social_readback_scope_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        grant = next(
            item for item in contract["grants"]
            if item["callerClientId"] == "middleware-worker"
            and item["targetClientId"] == "postly-adapter"
        )
        grant["scopes"].remove("social.status.read")
        self.reject(contract)

    def test_missing_ai_readback_scope_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        grant = next(
            item for item in contract["grants"]
            if item["callerClientId"] == "middleware-worker"
            and item["targetClientId"] == "ai-provider-adapter"
        )
        grant["scopes"].remove("ai.provider.status.read")
        self.reject(contract)

    def test_missing_marketing_readback_scope_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        grant = next(
            item for item in contract["grants"]
            if item["callerClientId"] == "middleware-worker"
            and item["targetClientId"] == "marketing-provider-adapter"
        )
        grant["scopes"].remove("marketing.provider.status.read")
        self.reject(contract)

    def test_application_scope_swap_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        grant = next(
            item for item in contract["grants"]
            if item["callerClientId"] == "codestra-ai"
        )
        grant["scopes"] = ["marketing.campaign.request"]
        self.reject(contract)


class CallingContractLockTests(unittest.TestCase):
    EXPECTED = {
        "schema_version": "codestra.calling-contract-lock.v1",
        "version": "1.0.0",
        "sha256": "b39cdffe56a8185c91174228f0423df68b1137f34875f6ee52f9914f904bf724",
        "authority": "appolon1908-hue/codestra-production-platform#257",
        "role": "identity",
        "external_effects_enabled": False,
    }

    def test_identity_lock_matches_protected_contract_exactly(self) -> None:
        actual = json.loads(
            CALLING_CONTRACT_LOCK.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
        self.assertEqual(actual, self.EXPECTED)
        self.assertIs(actual["external_effects_enabled"], False)

    def test_duplicate_contract_keys_are_rejected(self) -> None:
        for sample in (
            '{"sha256":"wrong","sha256":"b39cdffe56a8185c91174228f0423df68b1137f34875f6ee52f9914f904bf724"}',
            '{"role":"wrong","role":"identity"}',
            '{"external_effects_enabled":true,"external_effects_enabled":false}',
        ):
            with self.subTest(sample=sample):
                with self.assertRaises(ValueError):
                    json.loads(sample, object_pairs_hook=reject_duplicate_keys)


if __name__ == "__main__":
    unittest.main()
