"""Middleware V3 platform scopes are prepared as optional client scopes only.

platform.command, platform.command.read and platform.command.replay exist as
client-scope definitions so the Middleware V3 kernel edge can be activated
without a realm change later, but until the Middleware V3 route contract is
frozen (V3_PENDING_FINAL_MIDDLEWARE_CONTRACT) they are attached to no client,
and at no point may they become realm-wide or client default scopes.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT_SCOPE_DIR = ROOT / "config" / "client-scopes"
CLIENT_DIR = ROOT / "config" / "clients"
REALM = ROOT / "config" / "realms" / "codestra.json"
PLATFORM_SCOPES = ("platform.command", "platform.command.read", "platform.command.replay")
MONITORING_SCOPE = "metrics.read"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class PlatformV3ScopeTests(unittest.TestCase):
    def test_platform_scopes_are_defined_as_optional_token_scopes(self) -> None:
        for name in PLATFORM_SCOPES + (MONITORING_SCOPE,):
            with self.subTest(scope=name):
                document = load(CLIENT_SCOPE_DIR / f"{name}.json")
                self.assertEqual(document["name"], name)
                self.assertEqual(document["protocol"], "openid-connect")
                self.assertEqual(document["attributes"]["include.in.token.scope"], "true")
                self.assertEqual(document["attributes"]["display.on.consent.screen"], "false")
                self.assertEqual(document["protocolMappers"], [])
        for name in PLATFORM_SCOPES:
            with self.subTest(scope=name):
                document = load(CLIENT_SCOPE_DIR / f"{name}.json")
                self.assertIn("V3_PENDING_FINAL_MIDDLEWARE_CONTRACT", document["description"])
                self.assertIn("never a realm default", document["description"])

    def test_platform_scopes_are_never_default_scopes(self) -> None:
        realm = load(REALM)
        for key in ("defaultDefaultClientScopes", "defaultOptionalClientScopes"):
            self.assertFalse(set(realm.get(key) or ()) & set(PLATFORM_SCOPES), key)
        for client_file in sorted(CLIENT_DIR.glob("*.json")):
            client = load(client_file)
            with self.subTest(client=client["clientId"]):
                self.assertFalse(set(client.get("defaultClientScopes") or ()) & set(PLATFORM_SCOPES))
                mappers = json.dumps(client.get("protocolMappers") or [])
                for name in PLATFORM_SCOPES:
                    self.assertNotIn(name, mappers, "platform scopes are never hard-coded into a token")

    def test_platform_scopes_are_attached_only_to_confidential_service_clients(self) -> None:
        """Until the V3 contract is frozen no client carries them; once one does it must be
        a confidential service account with the Middleware audience, never a browser client."""
        for client_file in sorted(CLIENT_DIR.glob("*.json")):
            client = load(client_file)
            attached = set(client.get("optionalClientScopes") or ()) & set(PLATFORM_SCOPES)
            if not attached:
                continue
            with self.subTest(client=client["clientId"]):
                self.assertTrue(client["serviceAccountsEnabled"])
                self.assertFalse(client["publicClient"])
                self.assertFalse(client["standardFlowEnabled"])
                self.assertFalse(client["fullScopeAllowed"])
                audiences = {
                    mapper["config"].get("included.custom.audience")
                    for mapper in client.get("protocolMappers") or []
                    if mapper.get("protocolMapper") == "oidc-audience-mapper"
                }
                self.assertIn("middleware-api", audiences)


if __name__ == "__main__":
    unittest.main(verbosity=2)
