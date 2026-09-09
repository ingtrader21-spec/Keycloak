import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("disabled_certification", ROOT / "scripts/certify_disabled_client.py")
certification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(certification)


class FakeKeycloak:
    def __init__(self):
        self.client = {
            "id": "fixture-uuid", "clientId": "disabled-fixture", "enabled": False,
            "publicClient": False, "bearerOnly": False, "serviceAccountsEnabled": True,
            "protocol": "openid-connect", "clientAuthenticatorType": "client-secret",
        }
        self.clients = [self.client]
        self.secret = "fixture-secret"
        self.auth = (200, {"access_token": "admin-token"})
        self.rejection = (401, {"error": "invalid_client"})
        self.lookup_status = 200
        self.secret_status = 200
        self.after_grant = lambda: None
        self.calls = []

    def __call__(self, method, url, **kwargs):
        self.calls.append((method, url, copy.deepcopy(kwargs)))
        if method == "GET":
            if kwargs.get("token") != "admin-token":
                raise AssertionError("Admin API read is not authenticated")
            if url.endswith("/client-secret"):
                return self.secret_status, {"type": "secret", "value": self.secret}
            return self.lookup_status, copy.deepcopy(self.clients)
        if method == "POST" and url.endswith("/realms/master/protocol/openid-connect/token"):
            return self.auth
        if method == "POST" and url.endswith("/realms/codestra/protocol/openid-connect/token"):
            self.after_grant()
            return self.rejection
        raise AssertionError("Unexpected endpoint or mutation")


class DisabledClientCertificationTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeKeycloak()

    def certify(self, environment="staging", secret="fixture-secret"):
        return certification.certify(environment, "readback-client", "readback-secret",
                                     "disabled-fixture", secret, transport=self.api)

    def test_authenticated_reads_surround_grant_and_sanitized_evidence(self):
        evidence = self.certify()
        self.assertEqual([c[0] for c in self.api.calls], ["POST", "GET", "GET", "POST", "GET", "GET"])
        self.assertIn("clientId=disabled-fixture&exact=true", self.api.calls[1][1])
        self.assertEqual(evidence["internalClientId"], "fixture-uuid")
        self.assertTrue(evidence["credentialMatchedBeforeAndAfter"])
        self.assertFalse(evidence["enabled"])
        self.assertEqual(evidence["httpStatus"], 401)
        for secret in ("fixture-secret", "readback-secret", "admin-token", "access_token"):
            self.assertNotIn(secret, json.dumps(evidence))

    def test_environments_never_share_token_or_admin_endpoints(self):
        for environment, host in (("staging", "auth-staging.codestra.co"), ("production", "auth.codestra.co")):
            with self.subTest(environment=environment):
                self.api = FakeKeycloak()
                evidence = self.certify(environment)
                self.assertEqual(evidence["issuer"], "https://" + host + "/realms/codestra")
                self.assertTrue(all(url.startswith("https://" + host + "/") for _, url, _ in self.api.calls))

    def test_environment_must_be_explicit_before_authentication(self):
        for environment in ("", "prod", "../codestra"):
            with self.assertRaises(certification.CertificationError):
                self.certify(environment)
        self.assertEqual(self.api.calls, [])

    def test_missing_duplicate_and_wrong_client_cannot_certify(self):
        for clients in ([], [self.api.client, self.api.client], [dict(self.api.client, clientId="other")]):
            self.api.clients = clients
            with self.assertRaises(certification.CertificationError):
                self.certify()

    def test_enabled_or_non_service_client_cannot_certify(self):
        for key, value in (("enabled", True), ("enabled", "false"), ("publicClient", True),
                           ("bearerOnly", True), ("serviceAccountsEnabled", False),
                           ("protocol", "saml"), ("clientAuthenticatorType", "client-jwt"), ("id", "")):
            with self.subTest(key=key, value=value):
                self.api = FakeKeycloak()
                self.api.client[key] = value
                with self.assertRaises(certification.CertificationError):
                    self.certify()
                self.assertEqual(len(self.api.calls), 2)

    def test_mistyped_secret_stops_before_negative_grant(self):
        with self.assertRaises(certification.CertificationError):
            self.certify(secret="mistyped-secret")
        self.assertEqual(len(self.api.calls), 3)

    def test_no_admin_auth_or_secret_read_permission_fails_closed(self):
        for kind in ("auth", "lookup", "secret"):
            with self.subTest(kind=kind):
                self.api = FakeKeycloak()
                if kind == "auth":
                    self.api.auth = (401, {"error": "sensitive remote error"})
                elif kind == "lookup":
                    self.api.lookup_status = 403
                else:
                    self.api.secret_status = 403
                with self.assertRaises(certification.CertificationError) as error:
                    self.certify()
                self.assertNotIn("sensitive", str(error.exception))

    def test_http_rejection_alone_is_insufficient(self):
        for response in ((401, {}), (400, {"error": "invalid_scope"}), (401, "invalid_client"),
                         (200, {"access_token": "unexpected"}), (503, {"error": "invalid_client"}),
                         (401, {"error": "invalid_client", "access_token": "unexpected"})):
            self.api.rejection = response
            with self.assertRaises(certification.CertificationError):
                self.certify()

    def test_rotation_enablement_or_replacement_during_grant_fails_closed(self):
        changes = [lambda: setattr(self.api, "secret", "rotated-secret"),
                   lambda: self.api.client.update(enabled=True),
                   lambda: self.api.client.update(id="replacement-uuid")]
        for change in changes:
            self.api = FakeKeycloak()
            self.api.after_grant = change
            with self.assertRaises(certification.CertificationError):
                self.certify()

    def test_caller_evidence_does_not_replace_credentials(self):
        result = subprocess.run(["python3", str(ROOT / "scripts/certify_disabled_client.py")],
                                env={"DEPLOY_ENVIRONMENT": "staging",
                                     "DISABLED_CLIENT_EVIDENCE_FILE": "/forged/evidence.json"},
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("credentials are required", result.stderr)


class TransportTests(unittest.TestCase):
    def test_no_redirect_handler(self):
        with self.assertRaises(certification.CertificationError):
            certification.NoRedirects().redirect_request(None, None, 307, "", {}, "https://other.invalid")

    def test_cleartext_and_url_credentials_rejected_before_network(self):
        for url in ("http://example.invalid", "https://user:secret@example.invalid"):
            with patch.object(certification, "build_opener") as opener:
                with self.assertRaises(certification.CertificationError):
                    certification.request_json("POST", url)
                opener.assert_not_called()

    def test_form_and_bearer_sent_without_redirect_following(self):
        response = io.BytesIO(b'{"ok":true}')
        response.code = 200
        with patch.object(certification, "build_opener") as opener:
            opener.return_value.open.return_value = response
            status, result = certification.request_json("POST", "https://example.invalid/token",
                                                        token="token", form={"client_secret": "x&y"})
            self.assertIsInstance(opener.call_args.args[0], certification.NoRedirects)
            req = opener.return_value.open.call_args.args[0]
            self.assertEqual(req.data, b"client_secret=x%26y")
            self.assertEqual(req.get_header("Authorization"), "Bearer token")
            self.assertEqual(opener.return_value.open.call_args.kwargs["timeout"], 30)
            self.assertEqual((status, result), (200, {"ok": True}))

    def test_http_error_json_is_available_for_oauth_rejection(self):
        error = HTTPError("https://example.invalid", 401, "", {}, io.BytesIO(b'{"error":"invalid_client"}'))
        with patch.object(certification, "build_opener") as opener:
            opener.return_value.open.side_effect = error
            self.assertEqual(certification.request_json("POST", "https://example.invalid"),
                             (401, {"error": "invalid_client"}))

    def test_network_failures_do_not_echo_remote_details(self):
        with patch.object(certification, "build_opener") as opener:
            opener.return_value.open.side_effect = URLError("secret remote details")
            with self.assertRaises(certification.CertificationError) as error:
                certification.request_json("POST", "https://example.invalid")
            self.assertNotIn("secret", str(error.exception))

    def test_malformed_large_and_redirect_responses_fail(self):
        for code, body in ((200, b"secret-not-json"), (200, b"x" * (certification.MAX_RESPONSE_BYTES + 1)),
                           (302, b"{}")):
            response = io.BytesIO(body)
            response.code = code
            with patch.object(certification, "build_opener") as opener:
                opener.return_value.open.return_value = response
                with self.assertRaises(certification.CertificationError):
                    certification.request_json("GET", "https://example.invalid")


if __name__ == "__main__":
    unittest.main()
