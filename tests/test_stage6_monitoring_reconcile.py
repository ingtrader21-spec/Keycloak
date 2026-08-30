from __future__ import annotations

import base64
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/reconcile_monitoring_readonly_staging.py"
spec = importlib.util.spec_from_file_location("monitoring_reconcile", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def token(payload: dict[str, object]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}.test-signature"


class MonitoringReconcileTests(unittest.TestCase):
    def test_desired_client_is_fail_closed(self):
        value = module.desired_client(ROOT / "config/clients/monitoring-readonly.json")
        self.assertEqual(value["clientId"], "monitoring-readonly")
        self.assertFalse(value["fullScopeAllowed"])
        self.assertTrue(value["serviceAccountsEnabled"])
        self.assertEqual(value["redirectUris"], [])

    def test_token_metadata_requires_exact_client_audience_scopes_and_ttl(self):
        valid = token({
            "iat": 100,
            "exp": 400,
            "azp": "monitoring-readonly",
            "aud": ["middleware-api"],
            "scope": "health.read metrics.read",
        })
        metadata = module.decode_token_metadata(valid)
        self.assertEqual(metadata["ttl_seconds"], 300)
        self.assertEqual(metadata["scopes"], ["health.read", "metrics.read"])
        invalid = token({
            "iat": 100,
            "exp": 401,
            "azp": "monitoring-readonly",
            "aud": ["middleware-api"],
            "scope": "health.read metrics.read",
        })
        with self.assertRaises(module.ReconciliationError):
            module.decode_token_metadata(invalid)

    def test_private_outputs_are_mode_0600(self):
        with tempfile.TemporaryDirectory() as temp:
            output = module.validate_output_dir(Path(temp).resolve() / "outside-repository")
            path = output / "token"
            module.private_write(path, "sensitive-value\n")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text(), "sensitive-value\n")

    def test_repository_output_path_is_rejected(self):
        with self.assertRaises(module.ReconciliationError):
            module.validate_output_dir((ROOT / "tmp-stage6-secrets").resolve())
        with self.assertRaises(module.ReconciliationError):
            module.validate_output_dir(Path("relative-output"))

    def test_managed_projection_ignores_server_owned_nested_fields(self):
        desired = module.desired_client(ROOT / "config/clients/monitoring-readonly.json")
        live = json.loads(json.dumps(desired))
        live["id"] = "internal-client-id"
        live["secret"] = "server-owned-secret"
        live["protocolMappers"] = list(reversed(live["protocolMappers"]))
        for index, mapper in enumerate(live["protocolMappers"]):
            mapper["id"] = f"server-mapper-{index}"
        self.assertEqual(
            module.managed_projection(live, desired),
            module.managed_projection(desired, desired),
        )
        projected = module.managed_projection(live, desired)
        self.assertNotIn("id", projected)
        self.assertNotIn("secret", projected)

    def test_admin_endpoint_is_canonical_or_explicit_loopback(self):
        module.validate_runtime_urls(
            "https://auth.codestra.co",
            "https://auth.codestra.co",
            "codestra",
            allow_loopback_admin=False,
        )
        module.validate_runtime_urls(
            "http://127.0.0.1:8080",
            "https://auth.codestra.co",
            "codestra",
            allow_loopback_admin=True,
        )
        with self.assertRaises(module.ReconciliationError):
            module.validate_runtime_urls(
                "https://attacker.example",
                "https://auth.codestra.co",
                "codestra",
                allow_loopback_admin=False,
            )
        with self.assertRaises(module.ReconciliationError):
            module.validate_runtime_urls(
                "http://127.0.0.1:8080",
                "https://auth.codestra.co",
                "codestra",
                allow_loopback_admin=False,
            )


if __name__ == "__main__":
    unittest.main()
