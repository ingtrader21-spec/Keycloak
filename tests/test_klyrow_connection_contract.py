import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]


class TestKlyrowConnections(unittest.TestCase):
    def test_smtp_name_private_route_and_realm_are_one_contract(self):
        smtp = json.loads((ROOT / "config/email/keycloak-security-smtp.json").read_text())["smtp"]
        realm = json.loads((ROOT / "config/realms/codestra.json").read_text())["smtpServer"]
        compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
        self.assertEqual(smtp["defaultHost"], "mail.klyrow.com")
        self.assertEqual(realm["host"], smtp["defaultHost"])
        self.assertEqual(compose["services"]["keycloak"]["extra_hosts"],
                         [smtp["defaultHost"] + ":" + smtp["privateAddress"]])
        self.assertEqual((realm["auth"], realm["starttls"], realm["ssl"]), ("true", "true", "false"))

    def test_password_reset_validator_rejects_ip_hostname_and_public_route(self):
        spec = importlib.util.spec_from_file_location("password_reset_contract", ROOT / "scripts/validate-password-reset-contract.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        original = json.loads(module.CONTRACT.read_text())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "smtp.json"
            for field, value in (("defaultHost", "10.40.0.4"), ("privateAddress", "37.27.128.39"), ("defaultPort", 25)):
                candidate = json.loads(json.dumps(original))
                candidate["smtp"][field] = value
                path.write_text(json.dumps(candidate))
                with self.subTest(field=field), patch.object(module, "CONTRACT", path), self.assertRaises(module.ContractError):
                    module.validate()

    def test_portal_api_audience_does_not_replace_id_token_audience(self):
        client = json.loads((ROOT / "config/clients/klyrow-portal.json").read_text())
        self.assertEqual(client["redirectUris"], ["https://app.klyrow.com/auth/callback"])
        self.assertEqual(client["attributes"]["pkce.code.challenge.method"], "S256")
        mapper = client["protocolMappers"][0]["config"]
        self.assertEqual(mapper["included.custom.audience"], "klyrow-api")
        self.assertEqual(mapper["id.token.claim"], "false")
        self.assertFalse(client["fullScopeAllowed"])
