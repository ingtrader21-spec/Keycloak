"""Reject SMTP transport changes that break private routing or verified TLS."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "password_reset_contract", ROOT / "scripts/validate-password-reset-contract.py"
)
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class PrivateSmtpTransportTests(unittest.TestCase):
    def setUp(self):
        self.smtp = json.loads((ROOT / "config/email/keycloak-security-smtp.json").read_text())["smtp"]
        self.realm = json.loads((ROOT / "config/realms/codestra.json").read_text())
        self.compose = yaml.safe_load((ROOT / "compose.yaml").read_text())

    def validate(self):
        VALIDATOR.validate_private_smtp_transport(self.smtp, self.realm, self.compose)

    def test_reviewed_dns_identity_uses_private_route(self):
        self.validate()

    def test_ip_address_cannot_replace_certificate_identity(self):
        self.smtp["defaultHost"] = "10.40.0.4"
        self.realm["smtpServer"]["host"] = "10.40.0.4"
        with self.assertRaises(VALIDATOR.ContractError):
            self.validate()

    def test_missing_private_mapping_rejects_public_dns_fallback(self):
        self.compose["services"]["keycloak"].pop("extra_hosts")
        with self.assertRaises(VALIDATOR.ContractError):
            self.validate()

    def test_wrong_private_mapping_is_rejected(self):
        self.compose["services"]["keycloak"]["extra_hosts"]["mail.klyrow.com"] = "37.27.128.39"
        with self.assertRaises(VALIDATOR.ContractError):
            self.validate()

    def test_realm_cannot_drift_from_tls_identity(self):
        self.realm["smtpServer"]["host"] = "unreviewed.example"
        with self.assertRaises(VALIDATOR.ContractError):
            self.validate()

    def test_tls_and_authentication_cannot_be_disabled(self):
        for field in ("auth", "starttls"):
            with self.subTest(field=field):
                realm = copy.deepcopy(self.realm)
                realm["smtpServer"][field] = "false"
                with self.assertRaises(VALIDATOR.ContractError):
                    VALIDATOR.validate_private_smtp_transport(self.smtp, realm, self.compose)

    def test_private_port_is_preserved(self):
        self.smtp["defaultPort"] = 25
        with self.assertRaises(VALIDATOR.ContractError):
            self.validate()


if __name__ == "__main__":
    unittest.main()
