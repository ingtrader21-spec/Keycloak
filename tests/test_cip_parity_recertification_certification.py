"""CIP Foundation 3 / I1 step 1: Middleware V3 parity re-certification record.

The record in config/certification/ is the read-only evidence that Keycloak PR
#127's frozen identity still matches Middleware, Kong and Caddy. These tests keep
the record consistent with every artifact that pins the frozen contract, so a
repin cannot silently leave stale parity evidence behind.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"
RECORD = CONFIG / "certification" / "cip-f3-cross-repo-parity-recertification.v1.json"
ACCESS_V3 = CONFIG / "contracts" / "middleware-api-access.v3.json"
CALLERS = CONFIG / "contracts" / "middleware-caller-classification.v1.json"
ROUTE_PIN = (
    CONFIG / "desired-state" / "edge-integration-certification" / "middleware-public-api-route-contract.sha256"
)
SHA = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class CipParityRecertificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record = load(RECORD)
        cls.access = load(ACCESS_V3)
        cls.callers = load(CALLERS)

    def test_record_pins_the_same_frozen_contract_as_every_keycloak_artifact(self) -> None:
        frozen = self.record["frozen"]
        self.assertEqual(frozen["routeContractSha256"], self.access["source"]["sha256"])
        self.assertEqual(frozen["routeContractSha256"], self.callers["middleware"]["targetRouteContractSha256"])
        self.assertEqual(frozen["routeContractSha256"], ROUTE_PIN.read_text(encoding="utf-8").strip())
        self.assertEqual(frozen["routeCount"], self.access["source"]["routeCount"])
        self.assertEqual(frozen["issuer"], self.access["issuer"])
        self.assertEqual(frozen["audience"], "middleware-api")
        self.assertEqual(frozen["audience"], self.access["targetAudience"])
        self.assertEqual(frozen["audience"], self.callers["middleware"]["canonicalAudience"])
        self.assertEqual(self.record["inputs"]["middlewareMain"]["canonicalSha256"], frozen["routeContractSha256"])

    def test_current_mains_and_mission_heads_certify_with_zero_mismatches(self) -> None:
        frozen = self.record["frozen"]
        for label in ("currentMains", "missionHeads"):
            result = self.record["results"][label]
            with self.subTest(snapshot=label):
                self.assertEqual(result["verdict"], "PASS")
                self.assertEqual(result["exitCode"], 0)
                self.assertEqual(result["routeContractSha256"], frozen["routeContractSha256"])
                self.assertEqual(result["routeCount"], frozen["routeCount"])
                self.assertEqual(result["sharedEdgeRoutes"], 105)
                self.assertEqual(set(result["mismatches"]), {"caddy", "keycloakAccessAuthority", "keycloakEdgeContract", "kong"})
                self.assertTrue(all(count == 0 for count in result["mismatches"].values()))

    def test_unmerged_middleware_draft_is_not_adopted_and_fails_closed(self) -> None:
        draft = self.record["results"]["middlewareKernelDraft"]
        self.assertEqual(draft["verdict"], "FAIL")
        self.assertNotEqual(draft["exitCode"], 0)
        self.assertNotEqual(draft["routeContractSha256"], self.record["frozen"]["routeContractSha256"])
        self.assertGreater(draft["mismatches"]["keycloakEdgeContract"], 0)
        assessment = self.record["middlewareKernelDraftAssessment"]
        self.assertEqual(assessment["status"], "NOT_ADOPTED_FAIL_CLOSED")
        self.assertEqual(assessment["addedRouteAudience"], "middleware-api")

    def test_inputs_are_exact_commits_and_digests(self) -> None:
        self.assertEqual(self.record["keycloakBase"]["head"], "521403d518b78e625eba5c2394131548819cd5ab")
        for name, entry in self.record["inputs"].items():
            with self.subTest(input=name):
                self.assertRegex(entry["commit"], COMMIT)
                self.assertRegex(entry["fileSha256"], SHA)
        self.assertEqual(self.record["inputs"]["kongMissionHead"]["pullRequest"], 120)
        self.assertEqual(self.record["inputs"]["caddyMissionHead"]["pullRequest"], 186)

    def test_audience_freeze_and_safety_flags(self) -> None:
        freeze = self.record["audienceFreeze"]
        self.assertEqual(freeze["audience"], "middleware-api")
        self.assertEqual(freeze["middlewareApiRoutes"] + sum(freeze["explicitExceptions"].values()), 117)
        self.assertIs(self.record["liveApplyAuthorized"], False)
        self.assertIs(self.record["productionGo"], False)


if __name__ == "__main__":
    unittest.main()
