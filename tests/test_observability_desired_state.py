from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from observability_desired_state import (  # noqa: E402
    DESIRED_ROOT,
    DesiredStateError,
    build_plan,
    load_json,
    validate_client,
    validate_role,
)


class ObservabilityDesiredStateTests(unittest.TestCase):
    def test_render_is_deterministic_and_repository_only(self) -> None:
        first = build_plan()
        second = build_plan()
        self.assertEqual(first, second)
        self.assertFalse(first["repositoryBoundary"]["runtimeStateRead"])
        self.assertFalse(first["repositoryBoundary"]["liveApplyAuthorized"])
        self.assertEqual(len(first["operations"]), 8)

    def test_wildcard_callback_is_rejected(self) -> None:
        client = copy.deepcopy(load_json(DESIRED_ROOT / "clients" / "grafana-observability.json"))
        client["redirectUris"] = ["https://graf.codestra.media/*"]
        with self.assertRaises(DesiredStateError):
            validate_client("grafana-observability", client)

    def test_password_grant_is_rejected(self) -> None:
        client = copy.deepcopy(load_json(DESIRED_ROOT / "clients" / "superset-analytics.json"))
        client["directAccessGrantsEnabled"] = True
        with self.assertRaises(DesiredStateError):
            validate_client("superset-analytics", client)

    def test_cross_family_role_is_rejected(self) -> None:
        role = copy.deepcopy(load_json(DESIRED_ROOT / "realm-roles" / "secrets-admin.json"))
        role["attributes"]["codestra.role.family"] = ["observability"]
        with self.assertRaises(DesiredStateError):
            validate_role("secrets-admin", role)

    def test_embedded_client_secret_is_rejected(self) -> None:
        client = copy.deepcopy(load_json(DESIRED_ROOT / "clients" / "openbao-secrets.json"))
        client["secret"] = "must-not-be-committed"
        with self.assertRaises(DesiredStateError):
            validate_client("openbao-secrets", client)


if __name__ == "__main__":
    unittest.main()
