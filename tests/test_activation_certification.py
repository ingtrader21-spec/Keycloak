import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "activation_certification", ROOT / "scripts/certify-activation-readback.py"
)
certification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(certification)


class FakeKeycloak:
    def __init__(self, environment="staging"):
        self.environment = environment
        contract = certification.load_json("config/certification/activation-readback.json")
        endpoints = certification.load_json(contract["environments"][environment]["endpointContractPath"])
        self.endpoints = endpoints
        self.desired = certification.load_json(contract["desiredClientPath"])
        self.live = copy.deepcopy(self.desired)
        self.live["id"] = "klyrow-internal-id"
        self.token = "admin-access-token"
        self.calls = []

    def __call__(self, method, url, *, token=None, form=None):
        self.calls.append((method, url, token, copy.deepcopy(form)))
        if method == "GET" and url == self.endpoints["discoveryUrl"]:
            return 200, {"issuer": self.endpoints["issuer"], "jwks_uri": self.endpoints["jwksUri"]}
        if method == "GET" and url == self.endpoints["jwksUri"]:
            return 200, {"keys": [{"kid": "test-key", "kty": "RSA", "n": "abc", "e": "AQAB"}]}
        if method == "POST" and url.endswith("/realms/master/protocol/openid-connect/token"):
            if form != {
                "grant_type": "client_credentials",
                "client_id": "readback-client",
                "client_secret": "readback-secret",
            }:
                raise AssertionError("unexpected token request")
            return 200, {"access_token": self.token, "token_type": "Bearer"}
        if method == "GET" and "clients?clientId=klyrow-portal&exact=true" in url:
            if token != self.token:
                raise AssertionError("client lookup is not authenticated")
            return 200, [{"id": "klyrow-internal-id", "clientId": "klyrow-portal"}]
        if method == "GET" and url.endswith("/clients/klyrow-internal-id"):
            if token != self.token:
                raise AssertionError("client detail read is not authenticated")
            return 200, copy.deepcopy(self.live)
        raise AssertionError(f"unexpected call: {method} {url}")


class ActivationCertificationTests(unittest.TestCase):
    def certify(self, environment="staging", api=None):
        api = api or FakeKeycloak(environment)
        evidence = certification.certify(
            environment,
            "readback-client",
            "readback-secret",
            "a" * 40,
            transport=api,
            now=lambda: datetime(2026, 9, 12, 8, 30, tzinfo=timezone.utc),
        )
        return evidence, api

    def test_readback_is_exact_and_credential_free(self):
        evidence, api = self.certify()
        self.assertTrue(evidence["klyrow_projection_matches"])
        self.assertEqual(evidence["klyrow_redirect_uris"], ["https://klyrow.com/"])
        self.assertFalse(evidence["mutation_attempted"])
        self.assertEqual([call[0] for call in api.calls], ["GET", "GET", "POST", "GET", "GET"])
        serialized = json.dumps(evidence)
        for secret in ("readback-secret", "admin-access-token"):
            self.assertNotIn(secret, serialized)

    def test_staging_and_production_use_distinct_authorities(self):
        issuers = set()
        for environment, host in (
            ("staging", "auth-staging.codestra.co"),
            ("production", "auth.codestra.co"),
        ):
            with self.subTest(environment=environment):
                evidence, api = self.certify(environment)
                issuers.add(evidence["issuer"])
                self.assertTrue(all(host in call[1] for call in api.calls))
        self.assertEqual(len(issuers), 2)

    def test_environment_must_be_explicit_before_network(self):
        api = FakeKeycloak()
        for environment in ("", "prod", "../production"):
            with self.assertRaises(certification.CertificationError):
                certification.certify(
                    environment,
                    "readback-client",
                    "readback-secret",
                    "a" * 40,
                    transport=api,
                )
        self.assertEqual(api.calls, [])

    def test_live_klyrow_drift_fails_closed(self):
        api = FakeKeycloak()
        api.live["redirectUris"] = ["https://evil.example/callback"]
        with self.assertRaises(certification.CertificationError):
            self.certify(api=api)

    def test_missing_duplicate_or_malformed_client_fails_closed(self):
        for response in ([], [{"clientId": "klyrow-portal"}, {"clientId": "klyrow-portal"}], [{}]):
            api = FakeKeycloak()
            original = api.__call__

            def transport(method, url, *, token=None, form=None, response=response):
                if method == "GET" and "clients?clientId=klyrow-portal&exact=true" in url:
                    api.calls.append((method, url, token, copy.deepcopy(form)))
                    return 200, copy.deepcopy(response)
                return original(method, url, token=token, form=form)

            with self.assertRaises(certification.CertificationError):
                certification.certify(
                    "staging",
                    "readback-client",
                    "readback-secret",
                    "a" * 40,
                    transport=transport,
                )

    def test_repository_sha_is_exact(self):
        for bad in ("", "abc", "A" * 40, "a" * 39, "a" * 41):
            with patch.dict(certification.os.environ, {"GITHUB_SHA": ""}, clear=False):
                if bad:
                    with self.assertRaises(certification.CertificationError):
                        certification.repository_sha(bad)
        self.assertEqual(certification.repository_sha("b" * 40), "b" * 40)

    def test_transport_rejects_mutation_methods_before_network(self):
        with patch.object(certification, "build_opener") as opener:
            for method in ("PUT", "PATCH", "DELETE"):
                with self.assertRaises(certification.CertificationError):
                    certification.request_json(method, "https://auth.codestra.co/test")
            opener.assert_not_called()

    def test_protected_contract_and_workflow_cannot_enable_apply(self):
        contract = certification.load_json("config/certification/activation-readback.json")
        matrix = certification.load_json("config/certification/service-identity-matrix.json")
        workflow = (ROOT / ".github/workflows/keycloak-activation-readback.yml").read_text(encoding="utf-8")
        self.assertFalse(contract["mutationAllowed"])
        self.assertFalse(matrix["productionMutationAllowed"])
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("runs-on: [self-hosted, linux, x64, keycloak-deploy]", workflow)
        self.assertIn("${{ secrets.KC_READBACK_CLIENT_ID }}", workflow)
        self.assertIn("${{ secrets.KC_READBACK_CLIENT_SECRET }}", workflow)
        self.assertNotIn("${{ secrets.KC_ADMIN_CLIENT_ID }}", workflow)
        self.assertNotIn("${{ secrets.KC_ADMIN_CLIENT_SECRET }}", workflow)
        self.assertIn("scripts/certify-activation-readback.py", workflow)
        for forbidden in ("apply-plan.sh", "plan.sh --apply", "kubectl apply", "docker compose up", "curl -X PUT"):
            self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
