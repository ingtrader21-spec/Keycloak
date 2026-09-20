"""Keycloak -> OpenBao workload identity: exact clients, scope, claims and staging-only reconciliation."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import openbao_workload_identity_desired_state as desired_state  # noqa: E402


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


reconciler = load_script("reconcile_openbao_workload_identity_staging")
CONTRACT = desired_state.load_json(desired_state.CONTRACT_PATH)
AUTHORITY = desired_state.load_json(desired_state.VENDORED_AUTHORITY)
MANAGED = desired_state.load_json(desired_state.MANAGED_POLICY)["clients"]
MONITORING_PLANE = (
    "prometheus-openbao", "grafana-runtime", "alloy-collector", "otel-gateway", "loki-runtime",
    "tempo-runtime", "redis-exporter", "postgres-exporter", "superset-analytics",
)


class DesiredStateTests(unittest.TestCase):
    def test_committed_desired_state_validates(self) -> None:
        contract, authority, documents = desired_state.validate()
        self.assertEqual(contract["openbaoAuthority"]["sha256"], desired_state.digest(authority))
        self.assertEqual(sorted(e["clientId"] for e in contract["newClients"]), sorted(MONITORING_PLANE))
        self.assertGreaterEqual(len(documents), 2 + len(MONITORING_PLANE))

    def test_every_openbao_role_resolves_to_exactly_one_client_or_is_declared_unresolved(self) -> None:
        identities = {role["serviceIdentity"] for role in AUTHORITY["roles"]}
        resolved = {e["clientId"] for e in CONTRACT["newClients"]} | {e["clientId"] for e in CONTRACT["existingClientBindings"]}
        unresolved = {e["openbaoIdentity"] for e in CONTRACT["unresolvedOpenBaoIdentities"]}
        self.assertEqual(identities, resolved | unresolved)
        self.assertFalse(resolved & unresolved)
        for client_id in resolved:
            self.assertTrue((desired_state.CLIENT_DIR / f"{client_id}.json").is_file() or (desired_state.LIVE_CLIENTS_DIR / f"{client_id}.json").is_file(), client_id)

    def test_new_clients_are_confidential_service_accounts_with_only_the_optional_openbao_scope(self) -> None:
        for client_id in MONITORING_PLANE:
            client = desired_state.load_json(desired_state.CLIENT_DIR / f"{client_id}.json")
            self.assertFalse(client["publicClient"])
            self.assertTrue(client["serviceAccountsEnabled"])
            self.assertFalse(client["standardFlowEnabled"] or client["implicitFlowEnabled"] or client["directAccessGrantsEnabled"])
            self.assertFalse(client["fullScopeAllowed"])
            self.assertEqual(client["defaultClientScopes"], ["basic"])
            self.assertEqual(client["optionalClientScopes"], ["openbao.workload"])
            self.assertEqual(client["attributes"]["access.token.lifespan"], "300")
            self.assertNotIn(client_id, MANAGED)
            for mapper in client["protocolMappers"]:
                self.assertNotEqual(mapper["config"].get("included.custom.audience"), "openbao")
                self.assertNotEqual(mapper["config"].get("claim.name"), "codestra_environment")

    def test_scope_emits_openbao_audience_and_environment_placeholder_in_access_token_only(self) -> None:
        scope = desired_state.load_json(desired_state.SCOPE_PATH)
        mappers = {m["name"]: m for m in scope["protocolMappers"]}
        self.assertEqual(mappers["audience-openbao"]["config"]["included.custom.audience"], "openbao")
        self.assertEqual(mappers["audience-openbao"]["config"]["id.token.claim"], "false")
        claim = mappers["claim-codestra-environment"]["config"]
        self.assertEqual(claim["claim.name"], "codestra_environment")
        self.assertEqual(claim["claim.value"], "${CODESTRA_ENVIRONMENT}")
        self.assertEqual(claim["access.token.claim"], "true")
        self.assertEqual(claim["id.token.claim"], "false")

    def test_issuers_match_openbao_and_keycloak_endpoint_documents(self) -> None:
        self.assertEqual(CONTRACT["issuers"]["staging"], AUTHORITY["issuersByEnvironment"]["staging"])
        self.assertEqual(CONTRACT["issuers"]["production"], AUTHORITY["issuersByEnvironment"]["production"])
        self.assertNotEqual(CONTRACT["issuers"]["staging"], CONTRACT["issuers"]["production"])

    def test_monitoring_readonly_never_gets_a_secret_reading_scope(self) -> None:
        live = desired_state.load_json(desired_state.LIVE_CLIENTS_DIR / "monitoring-readonly.json")
        self.assertEqual(live["defaultClientScopes"], [])
        self.assertEqual(sorted(live["optionalClientScopes"]), ["health.read", "metrics.read"])
        self.assertNotIn("openbao.workload", live["optionalClientScopes"])
        for mapper in live["protocolMappers"]:
            self.assertIsNone(desired_state.NEVER_SECRET_SCOPES.search(str(mapper["config"].get("claim.value", ""))))
        self.assertIn("monitoring-readonly", {e["clientId"] for e in CONTRACT["neverBound"]})

    def test_grafana_is_the_only_new_client_with_read_only_middleware_scopes(self) -> None:
        for client_id in MONITORING_PLANE:
            client = desired_state.load_json(desired_state.CLIENT_DIR / f"{client_id}.json")
            audiences = {m["config"].get("included.custom.audience") for m in client["protocolMappers"]}
            if client_id == "grafana-runtime":
                self.assertIn("middleware-api", audiences)
                scopes = next(m["config"]["claim.value"] for m in client["protocolMappers"] if m["config"].get("claim.name") == "scope").split()
                self.assertTrue(all(s.endswith(".read") for s in scopes), scopes)
            else:
                self.assertEqual(client["protocolMappers"], [])

    # --- negative cases ---------------------------------------------------------------

    def test_browser_client_bound_to_the_scope_is_rejected(self) -> None:
        contract = copy.deepcopy(CONTRACT)
        odoo_web = desired_state.load_json(desired_state.LIVE_CLIENTS_DIR / "odoo-web.json")
        poisoned = dict(odoo_web, optionalClientScopes=list(odoo_web.get("optionalClientScopes", [])) + ["openbao.workload"])
        original = desired_state.load_json

        def fake_load(path: Path):
            if path.name == "odoo-web.json":
                return poisoned
            return original(path)

        with patch.object(desired_state, "load_json", fake_load):
            with self.assertRaisesRegex(desired_state.DesiredStateError, "browser client"):
                desired_state.validate_never_bound(contract)

    def test_realm_default_scope_is_rejected(self) -> None:
        original = desired_state.load_json

        def fake_load(path: Path):
            value = original(path)
            if path == desired_state.REALM_PATH:
                value = dict(value, defaultOptionalClientScopes=list(value.get("defaultOptionalClientScopes", [])) + ["openbao.workload"])
            return value

        with patch.object(desired_state, "load_json", fake_load):
            with self.assertRaisesRegex(desired_state.DesiredStateError, "realm"):
                desired_state.validate_never_bound(CONTRACT)

    def test_client_level_openbao_audience_or_environment_claim_is_rejected(self) -> None:
        client = desired_state.load_json(desired_state.CLIENT_DIR / "loki-runtime.json")
        poisoned = copy.deepcopy(client)
        poisoned["protocolMappers"] = [{"name": "x", "protocolMapper": "oidc-audience-mapper", "config": {"included.custom.audience": "openbao"}}]
        with self.assertRaisesRegex(desired_state.DesiredStateError, "optional scope"):
            desired_state.validate_confidential_client(poisoned, "loki-runtime")
        poisoned["protocolMappers"] = [{"name": "x", "protocolMapper": "oidc-hardcoded-claim-mapper", "config": {"claim.name": "codestra_environment", "claim.value": "production"}}]
        with self.assertRaisesRegex(desired_state.DesiredStateError, "optional scope"):
            desired_state.validate_confidential_client(poisoned, "loki-runtime")

    def test_client_with_a_secret_reading_or_provider_write_scope_is_rejected(self) -> None:
        client = copy.deepcopy(desired_state.load_json(desired_state.CLIENT_DIR / "grafana-runtime.json"))
        for mapper in client["protocolMappers"]:
            if mapper["config"].get("claim.name") == "scope":
                mapper["config"]["claim.value"] = "secret.read.all"
        with self.assertRaisesRegex(desired_state.DesiredStateError, "forbidden scope"):
            desired_state.validate_confidential_client(client, "grafana-runtime")

    def test_unresolved_identity_must_be_declared(self) -> None:
        contract = copy.deepcopy(CONTRACT)
        contract["unresolvedOpenBaoIdentities"] = []
        with self.assertRaisesRegex(desired_state.DesiredStateError, "without a Keycloak resolution"):
            desired_state.validate_resolution(contract, AUTHORITY)

    def test_new_client_that_is_already_managed_is_rejected(self) -> None:
        contract = copy.deepcopy(CONTRACT)
        contract["newClients"][0]["clientId"] = "middleware-api"
        contract["newClients"][0]["openbaoIdentity"] = "middleware-api"
        with self.assertRaisesRegex(desired_state.DesiredStateError, "protected managed client"):
            desired_state.validate_new_clients(contract, AUTHORITY, MANAGED)

    def test_vendored_authority_digest_mismatch_is_rejected(self) -> None:
        contract = copy.deepcopy(CONTRACT)
        contract["openbaoAuthority"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(desired_state.DesiredStateError, "pinned sha256"):
            desired_state.validate_vendored_authority(contract)

    def test_cross_check_rejects_a_differing_openbao_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "config").mkdir()
            (repo / "openbao" / "auth").mkdir(parents=True)
            drifted = copy.deepcopy(AUTHORITY)
            drifted["roles"] = drifted["roles"][:-1]
            (repo / "config" / "workload-secret-authority.v1.json").write_text(json.dumps(drifted), encoding="utf-8")
            (repo / "openbao" / "auth" / "jwt-roles.v1.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(desired_state.DesiredStateError, "differs from the vendored"):
                desired_state.cross_check(CONTRACT, repo)


class FakeAdminApi:
    """Minimal in-memory Keycloak Admin API covering scopes, clients and optional links."""

    def __init__(self, realm_defaults: list[str] | None = None, managed: dict[str, dict] | None = None) -> None:
        self.scopes: dict[str, dict] = {"basic-id": {"id": "basic-id", "name": "basic", "protocol": "openid-connect", "attributes": {}, "protocolMappers": []}}
        self.clients: dict[str, dict] = dict(managed or {})
        self.optional_links: dict[str, dict[str, str]] = {internal: {} for internal in self.clients}
        self.realm_defaults = realm_defaults or ["basic"]
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method, url, *, bearer=None, json_body=None, form=None, expected={200}):
        path = url.split("/admin/realms/codestra", 1)[1] if "/admin/realms/codestra" in url else url
        self.calls.append((method, path))
        if url.endswith("/protocol/openid-connect/token"):
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
            return 200, {}, json.dumps([c for c in self.clients.values() if c["clientId"] == client_id]).encode()
        if path == "/clients" and method == "POST":
            internal = f"id-{json_body['clientId']}"
            self.clients[internal] = {"id": internal, **json_body}
            self.optional_links[internal] = {}
            return 201, {"location": f"{url}/{internal}"}, b""
        if path.startswith("/clients/") and path.endswith("/optional-client-scopes") and method == "GET":
            internal = path.split("/")[2]
            return 200, {}, json.dumps([{"id": i, "name": n} for n, i in self.optional_links[internal].items()]).encode()
        if path.startswith("/clients/") and "/optional-client-scopes/" in path:
            internal, scope_id = path.split("/")[2], path.rsplit("/", 1)[1]
            name = self.scopes[scope_id]["name"]
            if method == "PUT":
                self.optional_links[internal][name] = scope_id
            else:
                self.optional_links[internal].pop(name)
            return 204, {}, b""
        if path.startswith("/clients/") and path.endswith("/client-secret"):
            return 200, {}, json.dumps({"value": "generated-secret-value-0123456789"}).encode()
        if path.startswith("/clients/") and method == "PUT":
            internal = path.split("/")[2]
            self.clients[internal] = {"id": internal, **json_body}
            return 204, {}, b""
        raise AssertionError((method, path))


def managed_fixture() -> dict[str, dict]:
    clients = {}
    for client_id in ("middleware-api", "monitoring-readonly", "odoo-web"):
        live = desired_state.load_json(desired_state.LIVE_CLIENTS_DIR / f"{client_id}.json")
        clients[f"id-{client_id}"] = {"id": f"id-{client_id}", **live}
    return clients


class ReconcilerTests(unittest.TestCase):
    def test_scope_is_rendered_for_staging_only_from_the_placeholder(self) -> None:
        _, scope, clients = reconciler.load_desired()
        claim = next(m["config"] for m in scope["protocolMappers"] if m["config"].get("claim.name") == "codestra_environment")
        self.assertEqual(claim["claim.value"], "staging")
        self.assertEqual(sorted(clients), sorted(MONITORING_PLANE))
        already = copy.deepcopy(scope)
        with self.assertRaisesRegex(reconciler.ReconciliationError, "placeholder"):
            reconciler.render_scope(already, "production")

    def test_plan_mode_reads_only(self) -> None:
        api = FakeAdminApi(managed=managed_fixture())
        _, scope, _ = reconciler.load_desired()
        with patch.object(reconciler._base, "http_request", api):
            bearer = reconciler.admin_token("https://kc", "master", "admin", "secret")
            self.assertEqual(reconciler.scope_plan_action("https://kc", "codestra", bearer, scope)[0], "create")
            self.assertIsNone(reconciler.find_client("https://kc", "codestra", bearer, "grafana-runtime"))
            self.assertIsNotNone(reconciler.find_client("https://kc", "codestra", bearer, "middleware-api"))
        self.assertFalse([c for c in api.calls if c[0] in {"POST", "PUT", "DELETE"} and "token" not in c[1]])

    def test_apply_creates_scope_clients_and_links_without_touching_other_optional_scopes(self) -> None:
        api = FakeAdminApi(managed=managed_fixture())
        api.scopes["scope-other"] = {"id": "scope-other", "name": "other.scope"}
        api.optional_links["id-middleware-api"] = {"other.scope": "scope-other"}
        contract, scope, clients = reconciler.load_desired()
        with patch.object(reconciler._base, "http_request", api):
            scope_id, result = reconciler.apply_client_scope("https://kc", "codestra", "t", scope)
            self.assertEqual(result, "created")
            internal_id, created = reconciler.apply_client("https://kc", "codestra", "t", clients["tempo-runtime"])
            self.assertEqual(created, "created")
            self.assertEqual(reconciler.ensure_optional_link("https://kc", "codestra", internal_id, "t", scope_id), "linked")
            self.assertEqual(reconciler.ensure_optional_link("https://kc", "codestra", internal_id, "t", scope_id), "unchanged")
            self.assertEqual(reconciler.ensure_optional_link("https://kc", "codestra", "id-middleware-api", "t", scope_id), "linked")
            self.assertEqual(api.optional_links["id-middleware-api"], {"other.scope": "scope-other", "openbao.workload": scope_id})
            reconciler.assert_scope_boundary("https://kc", "codestra", "t", contract)
            self.assertEqual(reconciler.remove_optional_link("https://kc", "codestra", "id-middleware-api", "t"), "unlinked")
            self.assertEqual(reconciler.remove_optional_link("https://kc", "codestra", "id-middleware-api", "t"), "absent")
            self.assertEqual(api.optional_links["id-middleware-api"], {"other.scope": "scope-other"})

    def test_scope_boundary_fails_when_monitoring_readonly_or_realm_defaults_carry_the_scope(self) -> None:
        contract, scope, _ = reconciler.load_desired()
        api = FakeAdminApi(managed=managed_fixture())
        with patch.object(reconciler._base, "http_request", api):
            scope_id, _ = reconciler.apply_client_scope("https://kc", "codestra", "t", scope)
            api.optional_links["id-monitoring-readonly"] = {"openbao.workload": scope_id}
            with self.assertRaisesRegex(reconciler.ReconciliationError, "never-bound"):
                reconciler.assert_scope_boundary("https://kc", "codestra", "t", contract)
        api = FakeAdminApi(realm_defaults=["basic", "openbao.workload"], managed=managed_fixture())
        with patch.object(reconciler._base, "http_request", api):
            with self.assertRaisesRegex(reconciler.ReconciliationError, "realm default"):
                reconciler.assert_scope_boundary("https://kc", "codestra", "t", contract)

    def test_main_refuses_without_staging_preconditions(self) -> None:
        with patch.object(sys, "argv", ["reconcile", "--mode", "plan", "--output-dir", str(Path(tempfile.gettempdir()) / "openbao-wi")]):
            with patch.dict(os.environ, {"CERTIFY_ENVIRONMENT": "production"}, clear=False):
                with self.assertRaisesRegex(reconciler.ReconciliationError, "staging"):
                    reconciler.main()


if __name__ == "__main__":
    unittest.main()
