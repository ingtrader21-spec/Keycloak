import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime = load("runtime_smtp", ROOT / "scripts/verify_runtime_smtp.py")
policy = load("workflow_policy_smtp", ROOT / "scripts/validate-workflows-core.py")


class RuntimeSmtpTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.compose = Path(temporary.name) / "compose.yaml"
        self.env_file = Path(temporary.name) / "runtime.env"
        self.compose.write_text("services: {}\n")
        self.env_file.write_text("SYNTHETIC_FIXTURE=true\n")
        self.identity = "a" * 64
        self.container = {
            "Id": self.identity, "State": {"Running": True},
            "Config": {"Labels": {"com.docker.compose.service": "keycloak",
                                  "com.docker.compose.project.config_files": str(self.compose)}},
            "HostConfig": {"ExtraHosts": ["mail.klyrow.com:10.40.0.4"]},
        }

    def verify(self, container=None, hosts="10.40.0.4 mail.klyrow.com\n", after=None):
        with patch.object(runtime, "command", side_effect=[
            self.identity, json.dumps([container or self.container]), hosts, after or self.identity,
        ]) as commands:
            runtime.verify(str(self.compose), str(self.env_file), "mail.klyrow.com", "10.40.0.4")
            self.assertEqual(commands.call_args_list[2].args[0][:2], ["exec", self.identity])

    def test_active_private_binding_passes(self):
        self.verify()

    def test_source_only_binding_does_not_count(self):
        self.compose.write_text("services:\n  keycloak:\n    extra_hosts: [mail.klyrow.com:10.40.0.4]\n")
        self.container["HostConfig"]["ExtraHosts"] = []
        with self.assertRaisesRegex(runtime.RuntimeSmtpError, "SMTP_PRIVATE_BINDING_MISSING"):
            self.verify()

    def test_public_conflicting_or_missing_active_hosts_fail(self):
        for hosts in ("", "37.27.128.39 mail.klyrow.com\n",
                      "10.40.0.4 mail.klyrow.com\n37.27.128.39 mail.klyrow.com\n"):
            with self.subTest(hosts=hosts), self.assertRaisesRegex(runtime.RuntimeSmtpError, "SMTP_ACTIVE_HOSTS_MISMATCH"):
                self.verify(hosts=hosts)

    def test_wrong_service_or_compose_identity_fails(self):
        for field, value in (("com.docker.compose.service", "other"),
                             ("com.docker.compose.project.config_files", "/different/compose.yaml")):
            container = copy.deepcopy(self.container)
            container["Config"]["Labels"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(runtime.RuntimeSmtpError, "RUNTIME_IDENTITY_MISMATCH"):
                self.verify(container=container)

    def test_container_replacement_invalidates_check(self):
        with self.assertRaisesRegex(runtime.RuntimeSmtpError, "KEYCLOAK_CONTAINER_CHANGED"):
            self.verify(after="b" * 64)

    def test_runtime_failure_never_discloses_compose_output(self):
        error = subprocess.CalledProcessError(1, "docker", output="synthetic-private-value")
        with patch.object(runtime.subprocess, "run", side_effect=error):
            with self.assertRaisesRegex(runtime.RuntimeSmtpError, "^RUNTIME_INSPECTION_FAILED$"):
                runtime.command(["inspect", self.identity])

    def test_workflow_requires_non_optional_check_before_apply(self):
        path = ROOT / ".github/workflows/deploy.yml"
        workflow = policy.load_workflow(path)
        policy.validate_smtp_apply_gate(path, workflow)
        for mutation in ("remove", "ignore", "skip", "late"):
            candidate = copy.deepcopy(workflow)
            steps = candidate["jobs"]["reconcile"]["steps"]
            guard = next(step for step in steps if step.get("run") == "python3 scripts/verify_runtime_smtp.py")
            if mutation == "remove":
                steps.remove(guard)
            elif mutation == "ignore":
                guard["continue-on-error"] = "true"
            elif mutation == "skip":
                guard["if"] = "false"
            else:
                steps.remove(guard)
                steps.append(guard)
            with self.subTest(mutation=mutation), self.assertRaises(policy.PolicyError):
                policy.validate_smtp_apply_gate(path, candidate)

    def test_direct_production_apply_checks_before_auth_and_realm_write(self):
        source = (ROOT / "scripts/apply-plan.sh").read_text()
        guard = 'python3 "$ROOT_DIR/scripts/verify_runtime_smtp.py"'
        self.assertEqual(source.count(guard), 2)
        self.assertLess(source.index(guard), source.index("\nkeycloak_authenticate\n"))
        self.assertLess(source.rindex(guard), source.index('keycloak_api PUT "/admin/realms/$(urlencode "$KC_TARGET_REALM")"'))
