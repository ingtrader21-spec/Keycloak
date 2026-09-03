from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "repository_name_authority",
    ROOT / "scripts" / "validate-repository-name-authority.py",
)
assert SPEC is not None and SPEC.loader is not None
AUTHORITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTHORITY)


class LiveRepositoryIdentityTests(unittest.TestCase):
    def test_matching_live_ids_pass(self) -> None:
        mappings = {
            1: ("appolon1908-hue/example-one", "appolon1908-hue/example-one-new"),
            2: ("appolon1908-hue/example-two", "appolon1908-hue/example-two-new"),
        }
        observed = {
            "appolon1908-hue/example-one": 1,
            "appolon1908-hue/example-two": 2,
        }
        AUTHORITY.validate_live_repository_ids(mappings, observed.__getitem__)

    def test_recreated_slug_with_wrong_id_is_rejected(self) -> None:
        mappings = {
            1: ("appolon1908-hue/example-one", "appolon1908-hue/example-one-new"),
        }
        with self.assertRaises(SystemExit):
            AUTHORITY.validate_live_repository_ids(mappings, lambda _repo: 99)


class InfrastructureCheckoutTests(unittest.TestCase):
    CURRENT = "appolon1908-hue/Infustruction-repo"
    TARGET = "appolon1908-hue/Codestra-Infrastructure"
    SHA = "a" * 40

    def workflow(self, infrastructure_credentials: str = "false") -> str:
        return f"""jobs:
  validate:
    env:
      INFRASTRUCTURE_SHA: {self.SHA}
    steps:
      - name: Unrelated checkout
        uses: actions/checkout@example
        with:
          persist-credentials: false
      - name: Check out Infrastructure authority
        uses: actions/checkout@example
        with:
          repository: {self.CURRENT}
          persist-credentials: {infrastructure_credentials}
          ref: {self.SHA}
"""

    def test_scoped_credential_protection_passes(self) -> None:
        AUTHORITY.validate_infrastructure_checkout(
            self.workflow(),
            self.CURRENT,
            self.TARGET,
        )

    def test_unrelated_checkout_cannot_mask_missing_protection(self) -> None:
        with self.assertRaises(SystemExit):
            AUTHORITY.validate_infrastructure_checkout(
                self.workflow("true"),
                self.CURRENT,
                self.TARGET,
            )

    def test_infrastructure_ref_must_match_authority_sha(self) -> None:
        changed = self.workflow().replace(f"ref: {self.SHA}", f"ref: {'b' * 40}")
        with self.assertRaises(SystemExit):
            AUTHORITY.validate_infrastructure_checkout(
                changed,
                self.CURRENT,
                self.TARGET,
            )


if __name__ == "__main__":
    unittest.main()
