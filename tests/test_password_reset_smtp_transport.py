"""Reject SMTP transport changes that break private routing or verified TLS."""
import copy
import importlib.util
import json
import os
import subprocess
import tempfile
from unittest import mock
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



class RuntimeSmtpTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.compose_file = self.directory / "runtime.yaml"
        self.env_file = self.directory / "runtime.env"
        self.compose_file.write_text("services: {}\n")
        self.env_file.touch()
        self.env = {
            "RUNTIME_REPO_DIR": str(self.directory),
            "RUNTIME_COMPOSE_FILE": str(self.compose_file),
            "RUNTIME_ENV_FILE": str(self.env_file),
        }
        self.container_id = "a" * 64
        self.compose = {
            "name": "codestra-identity",
            "services": {"keycloak": {"extra_hosts": ["mail.klyrow.com=10.40.0.4"]}},
        }
        self.container = {
            "State": {"Running": True},
            "Config": {"Labels": {
                "com.docker.compose.project": "codestra-identity",
                "com.docker.compose.service": "keycloak",
            }},
            "HostConfig": {"ExtraHosts": ["mail.klyrow.com:10.40.0.4"], "NetworkMode": "identity"},
        }
        self.resolution = "10.40.0.4 STREAM mail.klyrow.com\n10.40.0.4 DGRAM\n"
        self.commands = []

    def run_command(self, command, **kwargs):
        self.commands.append(command)
        if command[:2] == ["docker", "compose"]:
            self.assertIn(str(self.compose_file), command)
            self.assertIn(str(self.env_file), command)
            if command[-3:] == ["config", "--format", "json"]:
                output = json.dumps(self.compose)
            else:
                self.assertEqual(command[-4:-1], ["ps", "--all", "--quiet"])
                output = self.container_id + "\n"
        elif command[:2] == ["docker", "inspect"]:
            output = json.dumps([self.container])
        else:
            self.assertEqual(command, [
                "docker", "exec", self.container_id, "getent", "ahosts", "mail.klyrow.com",
            ])
            output = self.resolution
        return subprocess.CompletedProcess(command, 0, output, "")

    def validate(self):
        with mock.patch.dict(os.environ, self.env, clear=True):
            with mock.patch.object(VALIDATOR.subprocess, "run", side_effect=self.run_command):
                VALIDATOR.validate_runtime_private_smtp_transport()

    def test_rendered_and_running_private_mapping_passes(self):
        self.validate()
        self.assertTrue(any(command[:2] == ["docker", "exec"] for command in self.commands))

    def test_canonical_mapping_cannot_mask_missing_runtime_mapping(self):
        self.compose["services"]["keycloak"].pop("extra_hosts")
        with self.assertRaisesRegex(VALIDATOR.ContractError, "Rendered runtime Compose"):
            self.validate()
        self.assertEqual(len(self.commands), 1)

    def test_compose_edit_without_container_recreation_is_rejected(self):
        self.container["HostConfig"]["ExtraHosts"] = []
        with self.assertRaisesRegex(VALIDATOR.ContractError, "has not activated"):
            self.validate()

    def test_running_container_with_wrong_project_is_rejected(self):
        self.container["Config"]["Labels"]["com.docker.compose.project"] = "unrelated"
        with self.assertRaisesRegex(VALIDATOR.ContractError, "project/service"):
            self.validate()

    def test_stopped_container_is_rejected(self):
        self.container["State"]["Running"] = False
        with self.assertRaisesRegex(VALIDATOR.ContractError, "not running"):
            self.validate()

    def test_public_or_mixed_resolution_is_rejected(self):
        for resolution in ("37.27.128.39 STREAM\n", self.resolution + "37.27.128.39 STREAM\n", ""):
            with self.subTest(resolution=resolution):
                self.resolution = resolution
                with self.assertRaisesRegex(VALIDATOR.ContractError, "exclusively"):
                    self.validate()

    def test_conflicting_mapping_is_rejected(self):
        self.container["HostConfig"]["ExtraHosts"].append("mail.klyrow.com:37.27.128.39")
        with self.assertRaises(VALIDATOR.ContractError):
            self.validate()

    def test_missing_runtime_binding_cannot_skip_check(self):
        self.env.pop("RUNTIME_COMPOSE_FILE")
        with self.assertRaisesRegex(VALIDATOR.ContractError, "absolute runtime path"):
            self.validate()
        self.assertEqual(self.commands, [])

    def test_explicit_staging_service_is_supported(self):
        self.env["RUNTIME_KEYCLOAK_SERVICE"] = "keycloak-staging"
        self.compose["services"]["keycloak-staging"] = self.compose["services"].pop("keycloak")
        self.container["Config"]["Labels"]["com.docker.compose.service"] = "keycloak-staging"
        self.validate()

    def test_runtime_command_errors_never_echo_secret_bearing_output(self):
        result = subprocess.CompletedProcess([], 1, "sensitive-stdout", "sensitive-stderr")
        with mock.patch.object(VALIDATOR.subprocess, "run", return_value=result):
            with self.assertRaises(VALIDATOR.ContractError) as error:
                VALIDATOR.runtime_command(["docker", "compose"], "Runtime Compose rendering")
        self.assertEqual(str(error.exception), "Runtime Compose rendering failed")


class SmtpEnvironmentExampleTests(unittest.TestCase):
    def setUp(self):
        self.smtp = json.loads((ROOT / "config/email/keycloak-security-smtp.json").read_text())["smtp"]
        self.example = (ROOT / "deploy/keycloak-email.env.example").read_text()

    def test_repository_example_matches_transport(self):
        VALIDATOR.validate_email_environment_example(self.smtp, self.example)

    def test_stale_ip_example_is_rejected(self):
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.validate_email_environment_example(
                self.smtp, self.example.replace("KC_SMTP_HOST=mail.klyrow.com", "KC_SMTP_HOST=10.40.0.4"),
            )


if __name__ == "__main__":
    unittest.main()
