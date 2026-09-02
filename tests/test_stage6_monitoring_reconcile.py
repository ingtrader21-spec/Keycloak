from __future__ import annotations

import base64
import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/reconcile_monitoring_readonly_staging.py"
spec = importlib.util.spec_from_file_location("monitoring_reconcile", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def token(scope: str, jti: str = "test") -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(
        json.dumps(
            {
                "iat": 100,
                "exp": 400,
                "azp": "monitoring-readonly",
                "aud": ["middleware-api"],
                "scope": scope,
                "jti": jti,
            }
        ).encode()
    ).decode().rstrip("=")
    return f"{header}.{body}.test-signature"


class MonitoringReconcileTests(unittest.TestCase):
    def test_desired_client_uses_only_optional_monitoring_scopes(self):
        value = module.desired_client(
            ROOT / "config/clients/monitoring-readonly.json"
        )
        self.assertEqual(value["clientId"], "monitoring-readonly")
        self.assertFalse(value["fullScopeAllowed"])
        self.assertTrue(value["serviceAccountsEnabled"])
        self.assertEqual(value["redirectUris"], [])
        self.assertEqual(
            value["optionalClientScopes"], ["health.read", "metrics.read"]
        )
        self.assertEqual(
            [mapper["name"] for mapper in value["protocolMappers"]],
            ["audience-middleware-api"],
        )
        self.assertEqual(
            [
                mapper["config"]["included.custom.audience"]
                for mapper in value["protocolMappers"]
            ],
            ["middleware-api"],
        )

    def test_dedicated_client_scope_contracts_are_exact(self):
        for name in module.SCOPE_NAMES:
            value = module.desired_client_scope(
                ROOT / f"config/client-scopes/{name}.json", name
            )
            self.assertEqual(value["name"], name)
            self.assertEqual(value["protocolMappers"], [])
            self.assertEqual(
                value["attributes"]["include.in.token.scope"], "true"
            )

    def test_token_metadata_requires_one_exact_scope(self):
        metrics = module.decode_token_metadata(
            token("metrics.read", "metrics"), "metrics.read"
        )
        self.assertEqual(metrics["ttl_seconds"], 300)
        self.assertEqual(metrics["scopes"], ["metrics.read"])
        health = module.decode_token_metadata(
            token("health.read", "health"), "health.read"
        )
        self.assertEqual(health["scopes"], ["health.read"])
        with self.assertRaises(module.ReconciliationError):
            module.decode_token_metadata(
                token("health.read metrics.read", "combined"), "metrics.read"
            )
        with self.assertRaises(module.ReconciliationError):
            module.decode_token_metadata(
                token("health.read", "wrong"), "metrics.read"
            )

    def test_token_metadata_rejects_extra_audience(self):
        encoded = token("metrics.read", "extra-audience")
        header, payload, signature = encoded.split(".")
        decoded = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        decoded["aud"] = ["middleware-api", "marketing-provider-adapter"]
        expanded = base64.urlsafe_b64encode(
            json.dumps(decoded).encode()
        ).decode().rstrip("=")
        with self.assertRaises(module.ReconciliationError):
            module.decode_token_metadata(
                f"{header}.{expanded}.{signature}",
                "metrics.read",
            )

    def test_issue_token_requests_the_exact_optional_scope(self):
        expected_token = token("metrics.read", "issued")

        def fake_request(method, url, **kwargs):
            self.assertEqual(method, "POST")
            self.assertTrue(url.endswith("/realms/codestra/protocol/openid-connect/token"))
            self.assertEqual(kwargs["form"]["scope"], "metrics.read")
            return 200, {}, json.dumps({"access_token": expected_token}).encode()

        with patch.object(module, "http_request", side_effect=fake_request):
            issued, metadata = module.issue_token(
                "https://auth-staging.codestra.co",
                "codestra",
                "secret-value-that-is-long-enough",
                "metrics.read",
            )
        self.assertEqual(issued, expected_token)
        self.assertEqual(metadata["scopes"], ["metrics.read"])

    def test_private_outputs_are_mode_0600(self):
        with tempfile.TemporaryDirectory() as temp:
            output = module.validate_output_dir(
                Path(temp).resolve() / "outside-repository"
            )
            path = output / "token"
            module.private_write(path, "sensitive-value\n")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text(), "sensitive-value\n")

    def test_repository_output_path_is_rejected(self):
        with self.assertRaises(module.ReconciliationError):
            module.validate_output_dir(
                (ROOT / "tmp-stage6-secrets").resolve()
            )
        with self.assertRaises(module.ReconciliationError):
            module.validate_output_dir(Path("relative-output"))

    def test_managed_projection_ignores_server_owned_nested_fields(self):
        desired = module.desired_client(
            ROOT / "config/clients/monitoring-readonly.json"
        )
        live = json.loads(json.dumps(desired))
        live["id"] = "internal-client-id"
        live["secret"] = "server-owned-secret"
        live["protocolMappers"] = list(reversed(live["protocolMappers"]))
        for index, mapper in enumerate(live["protocolMappers"]):
            mapper["id"] = f"server-mapper-{index}"
        self.assertEqual(
            module.managed_projection(
                live, desired, module.CLIENT_MANAGED_KEYS
            ),
            module.managed_projection(
                desired, desired, module.CLIENT_MANAGED_KEYS
            ),
        )

    def test_managed_projection_rejects_unexpected_live_mapper(self):
        desired = module.desired_client(
            ROOT / "config/clients/monitoring-readonly.json"
        )
        live = json.loads(json.dumps(desired))
        live["protocolMappers"].append(
            {
                "id": "legacy-provider-mapper",
                "name": "audience-marketing-provider-adapter",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": "marketing-provider-adapter"
                },
            }
        )
        self.assertNotEqual(
            module.managed_projection(live, desired, module.CLIENT_MANAGED_KEYS),
            module.managed_projection(desired, desired, module.CLIENT_MANAGED_KEYS),
        )

    def test_apply_client_deletes_unexpected_live_mapper(self):
        desired = module.desired_client(
            ROOT / "config/clients/monitoring-readonly.json"
        )
        live = json.loads(json.dumps(desired))
        live["id"] = "monitoring-internal-id"
        live["protocolMappers"][0]["id"] = "middleware-mapper-id"
        legacy = {
            "id": "legacy-provider-mapper-id",
            "name": "audience-marketing-provider-adapter",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.custom.audience": "marketing-provider-adapter"
            },
        }
        live["protocolMappers"].append(legacy)
        cleaned = json.loads(json.dumps(live))
        cleaned["protocolMappers"].remove(legacy)

        with patch.object(
            module, "list_client", side_effect=[[live], [cleaned]]
        ), patch.object(module, "http_request") as request:
            internal_id, result = module.apply_client(
                "https://auth-staging.codestra.co",
                "codestra",
                "admin-token",
                desired,
            )

        self.assertEqual(internal_id, "monitoring-internal-id")
        self.assertEqual(result, "updated")
        request.assert_called_once()
        method, url = request.call_args.args[:2]
        self.assertEqual(method, "DELETE")
        self.assertTrue(url.endswith("/protocol-mappers/models/legacy-provider-mapper-id"))

    def test_admin_endpoint_is_staging_canonical_or_explicit_loopback(self):
        module.validate_runtime_urls(
            "https://auth-staging.codestra.co",
            "https://auth-staging.codestra.co",
            "codestra",
            allow_loopback_admin=False,
        )
        module.validate_runtime_urls(
            "http://127.0.0.1:8080",
            "https://auth-staging.codestra.co",
            "codestra",
            allow_loopback_admin=True,
        )
        with self.assertRaises(module.ReconciliationError):
            module.validate_runtime_urls(
                "https://attacker.example",
                "https://auth-staging.codestra.co",
                "codestra",
                allow_loopback_admin=False,
            )
        with self.assertRaises(module.ReconciliationError):
            module.validate_runtime_urls(
                "https://auth.codestra.co",
                "https://auth.codestra.co",
                "codestra",
                allow_loopback_admin=False,
            )


if __name__ == "__main__":
    unittest.main()
