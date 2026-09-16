from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import edge_certification_desired_state as desired_state  # noqa: E402


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


identity_tool = load_script("certify_edge_identity_staging")
reconciler = load_script("reconcile_edge_certification_staging")

CONTRACT = desired_state.load_json(desired_state.CONTRACT_PATH)
IDENTITY = {identity["clientId"]: identity for identity in CONTRACT["identities"]}
EDGE_SHA = CONTRACT["edgeContract"]["sha256"]


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


# --- a small deterministic RSA key so RS256 can be exercised without dependencies ---


def _is_probable_prime(candidate: int, rng: random.Random, rounds: int = 16) -> bool:
    if candidate < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if candidate % small == 0:
            return candidate == small
    d, r = candidate - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = rng.randrange(2, candidate - 1)
        x = pow(a, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, rng: random.Random) -> int:
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate, rng):
            return candidate


def rsa_keypair(seed: int = 7, bits: int = 512) -> tuple[int, int, int]:
    rng = random.Random(seed)
    e = 65537
    while True:
        p, q = _prime(bits, rng), _prime(bits, rng)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            return p * q, e, pow(e, -1, phi)


KEY_N, KEY_E, KEY_D = rsa_keypair()
JWK = {"kty": "RSA", "kid": "test-kid", "use": "sig", "alg": "RS256",
       "n": b64url(KEY_N.to_bytes((KEY_N.bit_length() + 7) // 8, "big")), "e": b64url(KEY_E.to_bytes(3, "big"))}


def sign_jwt(claims: dict, kid: str = "test-kid") -> str:
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}).encode())
    payload = b64url(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    k = (KEY_N.bit_length() + 7) // 8
    em = int.from_bytes(identity_tool.emsa_pkcs1_v15(signing_input, k), "big")
    signature = pow(em, KEY_D, KEY_N).to_bytes(k, "big")
    return f"{header}.{payload}.{b64url(signature)}"


def good_claims(identity: dict, now: int = 1_800_000_000) -> dict:
    return {
        "iss": CONTRACT["issuer"], "aud": identity["audience"], "azp": identity["clientId"],
        "sub": f"service-account-{identity['clientId']}", "jti": f"jti-{identity['clientId']}",
        "typ": "Bearer", "iat": now - 10, "nbf": now - 10, "exp": now + 290,
        "scope": " ".join(identity["scopes"]), "environment": "staging",
        "tenant_id": identity["tenant"], "business_units": identity["businessUnits"],
        "campaigns": identity["campaigns"],
    }


# --- desired state ----------------------------------------------------------------


class DesiredStateTests(unittest.TestCase):
    def test_render_is_deterministic_repository_only_and_checked_in(self) -> None:
        first, second = desired_state.build_plan(), desired_state.build_plan()
        self.assertEqual(first, second)
        self.assertEqual(first["edgeContract"]["sha256"], EDGE_SHA)
        self.assertFalse(any(first["repositoryBoundary"].values()))
        self.assertEqual(len(first["operations"]), 3 + 5 + 5)
        desired_state.check_artifacts(first)

    def test_contract_declares_exactly_the_canonical_routes_and_identities(self) -> None:
        shared = {(r["method"], r["path"], r["scope"]) for r in CONTRACT["routes"] if r["classification"] == "shared_edge"}
        self.assertEqual(shared, set(desired_state.CANONICAL_ROUTES))
        self.assertEqual(
            sorted(IDENTITY),
            ["test-syn-n8n-read", "test-syn-n8n-submit", "test-syn-odoo-reader", "test-syn-wrong-audience", "test-syn-wrong-tenant"],
        )
        self.assertEqual(IDENTITY["test-syn-n8n-submit"]["scopes"], ["n8n.results.submit"])
        self.assertEqual(IDENTITY["test-syn-wrong-audience"]["scopes"], [])
        self.assertNotEqual(IDENTITY["test-syn-wrong-audience"]["audience"], CONTRACT["audience"])
        for identity in CONTRACT["identities"]:
            self.assertNotIn("odoo.campaign.control.write", identity["scopes"])
            self.assertNotIn("odoo.campaign.control.read", identity["scopes"])

    def test_retired_route_and_missing_classification_are_rejected(self) -> None:
        contract = copy.deepcopy(CONTRACT)
        contract["routes"].append({"method": "POST", "path": "/api/v1/integrations/odoo/campaign-actions", "scope": "odoo.campaigns.read", "classification": "shared_edge"})
        with self.assertRaises(desired_state.DesiredStateError):
            desired_state.validate_contract(contract)
        contract = copy.deepcopy(CONTRACT)
        contract["routes"][0].pop("classification")
        with self.assertRaises(desired_state.DesiredStateError):
            desired_state.validate_contract(contract)

    def test_production_issuer_and_activation_flags_are_rejected(self) -> None:
        contract = copy.deepcopy(CONTRACT)
        contract["issuer"] = "https://auth.codestra.co/realms/codestra"
        with self.assertRaises(desired_state.DesiredStateError):
            desired_state.validate_contract(contract)
        contract = copy.deepcopy(CONTRACT)
        contract["boundary"]["productionActivationAuthorized"] = True
        with self.assertRaises(desired_state.DesiredStateError):
            desired_state.validate_contract(contract)

    def test_wrong_audience_identity_may_not_carry_the_middleware_audience(self) -> None:
        identity = copy.deepcopy(IDENTITY["test-syn-wrong-audience"])
        identity["audience"] = CONTRACT["audience"]
        with self.assertRaises(desired_state.DesiredStateError):
            desired_state.validate_identity_declaration(identity, CONTRACT["audience"])

    def test_identity_with_write_or_outbound_scope_is_rejected(self) -> None:
        for extra in ("odoo.campaign.control.write", "odoo.campaign.control.read"):
            identity = copy.deepcopy(IDENTITY["test-syn-odoo-reader"])
            identity["scopes"] = identity["scopes"] + [extra]
            with self.assertRaises(desired_state.DesiredStateError):
                desired_state.validate_identity_declaration(identity, CONTRACT["audience"])

    def test_client_shape_is_exact(self) -> None:
        path = desired_state.DESIRED_ROOT / "clients" / "test-syn-n8n-read.json"
        for field, value in (
            ("directAccessGrantsEnabled", True),
            ("fullScopeAllowed", True),
            ("publicClient", True),
            ("defaultClientScopes", ["basic", "n8n.results.read", "n8n.results.submit"]),
            ("optionalClientScopes", ["odoo.campaigns.read"]),
            ("redirectUris", ["https://example.invalid/cb"]),
            ("secret", "must-not-be-committed"),
        ):
            client = copy.deepcopy(desired_state.load_json(path))
            client[field] = value
            with self.assertRaises(desired_state.DesiredStateError, msg=field):
                desired_state.validate_client(IDENTITY["test-syn-n8n-read"], client)
        client = copy.deepcopy(desired_state.load_json(path))
        client["protocolMappers"][1]["config"]["claim.value"] = "production"
        with self.assertRaises(desired_state.DesiredStateError):
            desired_state.validate_client(IDENTITY["test-syn-n8n-read"], client)
        client = copy.deepcopy(desired_state.load_json(path))
        client["protocolMappers"].append({"name": "reviewed-service-scopes", "protocolMapper": "oidc-hardcoded-claim-mapper", "config": {"claim.name": "scope", "claim.value": "odoo.campaign.control.write"}})
        with self.assertRaises(desired_state.DesiredStateError):
            desired_state.validate_client(IDENTITY["test-syn-n8n-read"], client)

    def test_ingress_scope_leaking_into_live_capable_sets_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            live_clients = Path(tmp) / "clients"
            live_clients.mkdir()
            leaked = desired_state.load_json(ROOT / "config/clients/n8n-automation.json")
            leaked["protocolMappers"][-1]["config"]["claim.value"] += " n8n.results.submit"
            (live_clients / "n8n-automation.json").write_text(json.dumps(leaked), encoding="utf-8")
            with patch.object(desired_state, "LIVE_CLIENTS_DIR", live_clients):
                with self.assertRaisesRegex(desired_state.DesiredStateError, "ingress scope granted to production client"):
                    desired_state.validate_isolation(CONTRACT)
            forbidden = desired_state.load_json(ROOT / "config/clients/n8n-automation.json")
            forbidden["protocolMappers"][-1]["config"]["claim.value"] = "odoo.campaign.control.write"
            (live_clients / "n8n-automation.json").write_text(json.dumps(forbidden), encoding="utf-8")
            with patch.object(desired_state, "LIVE_CLIENTS_DIR", live_clients):
                with self.assertRaisesRegex(desired_state.DesiredStateError, "forbidden scope"):
                    desired_state.validate_isolation(CONTRACT)
            policy = Path(tmp) / "managed-clients.json"
            policy.write_text(json.dumps({"clients": ["middleware-api", "test-syn-n8n-submit"]}), encoding="utf-8")
            with patch.object(desired_state, "MANAGED_POLICY", policy):
                with self.assertRaisesRegex(desired_state.DesiredStateError, "leaked into"):
                    desired_state.validate_isolation(CONTRACT)
            realm = Path(tmp) / "realm.json"
            realm.write_text(json.dumps({"realm": "codestra", "defaultDefaultClientScopes": ["odoo.campaigns.read"]}), encoding="utf-8")
            with patch.object(desired_state, "REALM_PATH", realm):
                with self.assertRaisesRegex(desired_state.DesiredStateError, "realm-wide"):
                    desired_state.validate_isolation(CONTRACT)

    def test_edge_contract_cross_check_requires_identical_hash_and_routes(self) -> None:
        document = {
            "schema": "codestra.middleware.public-api-route-contract.v1",
            "routes": [
                {"method": method, "path": path, "auth": "x", "scope": scope}
                for method, path, scope in desired_state.CANONICAL_ROUTES
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            deploy = Path(tmp) / "deploy"
            deploy.mkdir()
            (deploy / "public-api-route-contract.json").write_text(json.dumps(document), encoding="utf-8")
            digest = desired_state.edge_contract_sha256(document)
            (deploy / "public-api-route-contract.sha256").write_text(digest + "\n", encoding="utf-8")
            contract = copy.deepcopy(CONTRACT)
            contract["edgeContract"]["sha256"] = digest
            result = desired_state.cross_check_edge_contract(contract, Path(tmp))
            self.assertTrue(result["hashesIdentical"] and result["routesIdentical"])
            with self.assertRaisesRegex(desired_state.DesiredStateError, "hash mismatch"):
                desired_state.cross_check_edge_contract(CONTRACT if EDGE_SHA != digest else {**contract, "edgeContract": {**contract["edgeContract"], "sha256": "0" * 64}}, Path(tmp))
            document["routes"][1]["scope"] = "n8n.results.submit"
            (deploy / "public-api-route-contract.json").write_text(json.dumps(document), encoding="utf-8")
            drifted = desired_state.edge_contract_sha256(document)
            (deploy / "public-api-route-contract.sha256").write_text(drifted + "\n", encoding="utf-8")
            contract["edgeContract"]["sha256"] = drifted
            with self.assertRaisesRegex(desired_state.DesiredStateError, "route/scope mismatch"):
                desired_state.cross_check_edge_contract(contract, Path(tmp))


# --- identity certification tool ---------------------------------------------------


class IdentityToolTests(unittest.TestCase):
    def test_rs256_verification_accepts_valid_and_rejects_tampered_signatures(self) -> None:
        token = sign_jwt({"sub": "x"})
        head, body, signature = token.split(".")
        self.assertTrue(identity_tool.rs256_verify(JWK, f"{head}.{body}".encode(), identity_tool.b64url_decode(signature)))
        self.assertFalse(identity_tool.rs256_verify(JWK, f"{head}.{body}x".encode(), identity_tool.b64url_decode(signature)))
        flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
        self.assertFalse(identity_tool.rs256_verify(JWK, f"{head}.{body}".encode(), identity_tool.b64url_decode(flipped)))
        self.assertEqual(identity_tool.SHA256_DIGEST_INFO, bytes.fromhex("3031300d060960864801650304020105000420"))

    def test_claim_checks_pass_for_conforming_tokens_and_name_each_deviation(self) -> None:
        now = 1_800_000_000
        for identity in CONTRACT["identities"]:
            checks = identity_tool.check_claims(identity, CONTRACT, good_claims(identity, now), now=now)
            self.assertEqual([c["name"] for c in checks if c["status"] != "PASS"], [], identity["clientId"])
        reader = IDENTITY["test-syn-odoo-reader"]
        deviations = {
            "aud": ("aud_exact", ["middleware-api", "account"]),
            "scope": ("scope_exact", "odoo.campaigns.read n8n.results.read"),
            "tenant_id": ("tenant_id", "OTHER"),
            "exp": ("lifetime_bounded", now + 3600),
            "environment": ("environment_claim", "production"),
            "realm_access": ("no_realm_role_grant", {"roles": ["default-roles-codestra"]}),
            "azp": ("azp", "middleware-api"),
        }
        for claim, (check_name, value) in deviations.items():
            claims = good_claims(reader, now)
            claims[claim] = value
            failed = [c["name"] for c in identity_tool.check_claims(reader, CONTRACT, claims, now=now) if c["status"] != "PASS"]
            self.assertIn(check_name, failed, claim)
        claims = good_claims(reader, now)
        claims["scope"] = "odoo.campaigns.read odoo.campaign.control.write"
        failed = [c["name"] for c in identity_tool.check_claims(reader, CONTRACT, claims, now=now) if c["status"] != "PASS"]
        self.assertIn("no_forbidden_or_outbound_scope", failed)
        wrong = IDENTITY["test-syn-wrong-audience"]
        claims = good_claims(wrong, now)
        claims["aud"] = CONTRACT["audience"]
        failed = [c["name"] for c in identity_tool.check_claims(wrong, CONTRACT, claims, now=now) if c["status"] != "PASS"]
        self.assertIn("aud_excludes_middleware", failed)

    def test_preconditions_refuse_production_raw_secrets_and_missing_files(self) -> None:
        base = {"CERTIFY_ENVIRONMENT": "staging", "CERTIFY_CAMPAIGN_ID": "TEST_SYN"}
        with self.assertRaises(identity_tool.Refused):
            identity_tool.load_preconditions({**base, "CERTIFY_ENVIRONMENT": "production"})
        with self.assertRaises(identity_tool.Refused):
            identity_tool.load_preconditions({**base, "CERTIFY_CAMPAIGN_ID": "MOY-SHIPPER-OUT"})
        with self.assertRaisesRegex(identity_tool.Refused, "raw credentials"):
            identity_tool.load_preconditions({**base, "CERTIFY_CLIENT_SECRET_N8N_SUBMIT": "plain"})
        with self.assertRaisesRegex(identity_tool.Refused, "is required"):
            identity_tool.load_preconditions(base)
        with self.assertRaisesRegex(identity_tool.Refused, "disagrees"):
            identity_tool.load_preconditions({**base, "CERTIFY_KEYCLOAK_ISSUER": "https://auth.codestra.co/realms/codestra"})

    def test_secret_file_must_be_an_absolute_regular_file_with_one_secret(self) -> None:
        with self.assertRaises(identity_tool.Refused):
            identity_tool.read_secret_file("relative/secret", "x")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "secret"
            path.write_text("short\n", encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(identity_tool.Refused, "one non-empty secret"):
                identity_tool.read_secret_file(str(path), "x")
            path.write_text("a-sufficiently-long-secret-value\n", encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertEqual(identity_tool.read_secret_file(str(path), "x"), "a-sufficiently-long-secret-value")

    def test_offline_certification_run_reports_redacted_claims_and_no_tokens(self) -> None:
        issuer = CONTRACT["issuer"]
        now = 1_800_000_000
        minted: list[str] = []

        def fake_http_json(url: str, *, form=None, timeout):
            if url.endswith("/.well-known/openid-configuration"):
                return 200, {"issuer": issuer, "token_endpoint": CONTRACT["tokenEndpoint"], "jwks_uri": CONTRACT["jwksUri"]}
            if url == CONTRACT["jwksUri"]:
                return 200, {"keys": [JWK]}
            if url == CONTRACT["tokenEndpoint"]:
                self.assertEqual(form["grant_type"], "client_credentials")
                self.assertNotIn("scope", form)
                claims = good_claims(IDENTITY[form["client_id"]], now)
                claims["jti"] = f"jti-{len(minted)}"
                token = sign_jwt(claims)
                minted.append(token)
                return 200, {"access_token": token, "token_type": "Bearer", "expires_in": 300}
            raise AssertionError(url)

        secrets = {client_id: "secret-" + client_id for client_id in IDENTITY}
        with patch.object(identity_tool, "http_json", fake_http_json), patch.object(identity_tool.time, "time", lambda: now):
            report = identity_tool.certify(CONTRACT, secrets, timeout=1.0)
        self.assertEqual(report["verdict"], "PASS", json.dumps(report, indent=1)[:2000])
        self.assertEqual(report["totals"]["minted"], 5)
        self.assertEqual(report["edgeContractSha256"], EDGE_SHA)
        rendered = json.dumps(report)
        for token in minted:
            self.assertNotIn(token, rendered)
            self.assertNotIn(token.split(".")[2], rendered)
        for secret in secrets.values():
            self.assertNotIn(secret, rendered)
        self.assertNotIn("eyJ", rendered)
        submit = report["identities"]["test-syn-n8n-submit"]
        self.assertTrue(submit["signature"]["verified"])
        self.assertEqual(submit["claims"]["scope"], "n8n.results.submit")
        self.assertEqual(submit["claims"]["aud"], "middleware-api")
        self.assertEqual(report["identities"]["test-syn-wrong-audience"]["claims"]["aud"], "test-syn-wrong-audience")
        self.assertEqual(report["identities"]["test-syn-wrong-tenant"]["claims"]["tenant_id"], "TEST_SYN_OTHER_TENANT")

    def test_offline_certification_fails_closed_on_a_leaked_scope(self) -> None:
        issuer = CONTRACT["issuer"]
        now = 1_800_000_000

        def fake_http_json(url: str, *, form=None, timeout):
            if url.endswith("/.well-known/openid-configuration"):
                return 200, {"issuer": issuer, "token_endpoint": CONTRACT["tokenEndpoint"], "jwks_uri": CONTRACT["jwksUri"]}
            if url == CONTRACT["jwksUri"]:
                return 200, {"keys": [JWK]}
            claims = good_claims(IDENTITY[form["client_id"]], now)
            claims["jti"] = form["client_id"]
            if form["client_id"] == "test-syn-wrong-audience":
                claims["scope"] = "n8n.results.read"  # a realm-wide grant would look like this
            return 200, {"access_token": sign_jwt(claims)}

        with patch.object(identity_tool, "http_json", fake_http_json), patch.object(identity_tool.time, "time", lambda: now):
            report = identity_tool.certify(CONTRACT, {c: "s" * 20 for c in IDENTITY}, timeout=1.0)
        self.assertEqual(report["verdict"], "NO_GO")
        failed = [c["name"] for c in report["identities"]["test-syn-wrong-audience"]["checks"] if c["status"] != "PASS"]
        self.assertIn("scope_exact", failed)

    def test_unverifiable_signature_is_a_failure_not_a_pass(self) -> None:
        token = sign_jwt(good_claims(IDENTITY["test-syn-n8n-read"]))
        head, body, signature = token.split(".")
        other = {**JWK, "kid": "other-kid"}
        with self.assertRaisesRegex(identity_tool.CertificationError, "not uniquely resolvable"):
            identity_tool.decode_and_verify(token, {"keys": [other]})
        with self.assertRaisesRegex(identity_tool.CertificationError, "does not verify"):
            identity_tool.decode_and_verify(f"{head}.{body}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}", {"keys": [JWK]})

    def test_output_path_must_stay_outside_the_checkout(self) -> None:
        with self.assertRaises(identity_tool.Refused):
            identity_tool.validate_output_path(str(ROOT / "release" / "leak.json"))
        with self.assertRaises(identity_tool.Refused):
            identity_tool.validate_output_path("relative.json")


# --- staging reconciler --------------------------------------------------------------


class FakeAdminApi:
    """Minimal in-memory Keycloak Admin API for the certification resources."""

    def __init__(self, realm_defaults: list[str] | None = None) -> None:
        self.scopes: dict[str, dict] = {"basic-id": {"id": "basic-id", "name": "basic", "protocol": "openid-connect", "attributes": {}, "protocolMappers": []}}
        self.clients: dict[str, dict] = {}
        self.default_links: dict[str, dict[str, str]] = {}
        self.realm_defaults = realm_defaults or ["basic"]
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method, url, *, bearer=None, json_body=None, form=None, expected={200}):
        path = url.split("/admin/realms/codestra", 1)[1] if "/admin/realms/codestra" in url else url
        self.calls.append((method, path))
        if path.startswith("/realms/master/protocol/openid-connect/token") or url.endswith("/protocol/openid-connect/token"):
            return 200, {}, json.dumps({"access_token": "admin-token"}).encode()
        if path == "/default-default-client-scopes":
            return 200, {}, json.dumps([{"name": n} for n in self.realm_defaults]).encode()
        if path == "/default-optional-client-scopes":
            return 200, {}, b"[]"
        if path == "/client-scopes" and method == "GET":
            return 200, {}, json.dumps(list(self.scopes.values())).encode()
        if path == "/client-scopes" and method == "POST":
            scope_id = f"scope-{json_body['name']}"
            self.scopes[scope_id] = {"id": scope_id, **json_body}
            return 201, {"location": f"{url}/{scope_id}"}, b""
        if path.startswith("/client-scopes/") and method == "GET":
            return 200, {}, json.dumps(self.scopes[path.rsplit("/", 1)[1]]).encode()
        if path.startswith("/clients?clientId="):
            client_id = path.split("=", 1)[1]
            found = [c for c in self.clients.values() if c["clientId"] == client_id]
            return 200, {}, json.dumps(found).encode()
        if path == "/clients" and method == "POST":
            internal = f"id-{json_body['clientId']}"
            self.clients[internal] = {"id": internal, **json_body}
            self.default_links[internal] = {"basic": "basic-id"}
            return 201, {"location": f"{url}/{internal}"}, b""
        if path.startswith("/clients/") and path.endswith("/default-client-scopes") and method == "GET":
            internal = path.split("/")[2]
            return 200, {}, json.dumps([{"id": i, "name": n} for n, i in self.default_links[internal].items()]).encode()
        if path.startswith("/clients/") and "/default-client-scopes/" in path:
            internal, scope_id = path.split("/")[2], path.rsplit("/", 1)[1]
            name = self.scopes[scope_id]["name"]
            if method == "PUT":
                self.default_links[internal][name] = scope_id
            else:
                self.default_links[internal].pop(name)
            return 204, {}, b""
        if path.startswith("/clients/") and path.endswith("/client-secret"):
            return 200, {}, json.dumps({"value": "generated-secret-value-0123456789"}).encode()
        if path.startswith("/clients/") and method == "PUT":
            internal = path.split("/")[2]
            self.clients[internal] = {"id": internal, **json_body}
            return 204, {}, b""
        raise AssertionError((method, path))


class ReconcilerTests(unittest.TestCase):
    def test_plan_mode_reads_only_and_reports_creates(self) -> None:
        api = FakeAdminApi()
        contract, scopes, clients = reconciler.load_desired()
        with patch.object(reconciler._base, "http_request", api):
            bearer = reconciler.admin_token("https://kc", "master", "admin", "secret")
            reconciler.assert_no_realm_wide_ingress_grant("https://kc", "codestra", bearer, set(contract["ingressScopes"]))
            actions = {name: reconciler.scope_plan_action("https://kc", "codestra", bearer, scope)[0] for name, scope in scopes.items()}
            self.assertEqual(set(actions.values()), {"create"})
            self.assertIsNone(reconciler.find_client("https://kc", "codestra", bearer, "test-syn-n8n-submit"))
        self.assertFalse([call for call in api.calls if call[0] in {"POST", "PUT", "DELETE"} and "token" not in call[1]])

    def test_realm_wide_ingress_grant_stops_the_reconciler(self) -> None:
        api = FakeAdminApi(realm_defaults=["basic", "n8n.results.read"])
        with patch.object(reconciler._base, "http_request", api):
            with self.assertRaisesRegex(reconciler.ReconciliationError, "realm default"):
                reconciler.assert_no_realm_wide_ingress_grant("https://kc", "codestra", "t", {"n8n.results.read"})

    def test_apply_creates_scopes_clients_and_exact_default_links(self) -> None:
        api = FakeAdminApi()
        _, scopes, clients = reconciler.load_desired()
        with patch.object(reconciler._base, "http_request", api):
            scope_ids = {"basic": "basic-id"}
            for name, scope in scopes.items():
                scope_ids[name], result = reconciler.apply_client_scope("https://kc", "codestra", "t", scope)
                self.assertEqual(result, "created")
            desired = clients["test-syn-wrong-tenant"]
            internal_id, result = reconciler.apply_client("https://kc", "codestra", "t", desired)
            self.assertEqual(result, "created")
            api.default_links[internal_id]["profile"] = "scope-profile"
            api.scopes["scope-profile"] = {"id": "scope-profile", "name": "profile"}
            links = reconciler.reconcile_default_scope_links("https://kc", "codestra", internal_id, "t", desired["defaultClientScopes"], scope_ids)
            self.assertEqual(sorted(api.default_links[internal_id]), ["basic", "n8n.results.read", "odoo.campaigns.read"])
            self.assertIn("removed:profile", links)
            readback = reconciler.find_client("https://kc", "codestra", "t", "test-syn-wrong-tenant")
            self.assertEqual(reconciler.managed_projection(readback, desired, reconciler.CLIENT_MANAGED_KEYS), reconciler.managed_projection(desired, desired, reconciler.CLIENT_MANAGED_KEYS))
            self.assertEqual(reconciler.apply_client("https://kc", "codestra", "t", desired)[1], "unchanged")
            self.assertEqual(reconciler.disable_client("https://kc", "codestra", "t", "test-syn-wrong-tenant"), "disabled")
            self.assertEqual(reconciler.disable_client("https://kc", "codestra", "t", "test-syn-wrong-tenant"), "already-disabled")
            self.assertEqual(reconciler.disable_client("https://kc", "codestra", "t", "test-syn-n8n-read"), "absent")

    def test_desired_state_is_loaded_through_the_validator(self) -> None:
        contract, scopes, clients = reconciler.load_desired()
        self.assertEqual(sorted(scopes), sorted(desired_state.INGRESS_SCOPES))
        self.assertEqual(sorted(clients), sorted(IDENTITY))
        self.assertEqual(contract["edgeContract"]["sha256"], EDGE_SHA)

    def test_main_refuses_without_staging_preconditions(self) -> None:
        with patch.object(sys, "argv", ["reconcile", "--mode", "plan", "--output-dir", str(Path(tempfile.gettempdir()) / "edge-cert")]):
            with patch.dict(os.environ, {"CERTIFY_ENVIRONMENT": "production", "CERTIFY_CAMPAIGN_ID": "TEST_SYN"}, clear=False):
                with self.assertRaisesRegex(reconciler.ReconciliationError, "staging"):
                    reconciler.main()


if __name__ == "__main__":
    unittest.main()
