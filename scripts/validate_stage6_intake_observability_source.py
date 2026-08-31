#!/usr/bin/env python3
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/reconcile_monitoring_readonly_staging.py"
RENDERER = ROOT / "scripts/render-machine-client-overlays.py"
CLIENT = ROOT / "config/clients/monitoring-readonly.json"
CLIENT_SCOPE_DIR = ROOT / "config/client-scopes"
STAGING_ENDPOINTS = ROOT / "config/endpoints/codestra-staging.json"
RUNTIME_WORKFLOW = ROOT / ".github/workflows/runtime-preflight.yml"
SERVICE_MATRIX = ROOT / "config/contracts/service-access-matrix.json"
STAGING_PUBLIC_URL = "https://auth-staging.codestra.co"
PRODUCTION_PUBLIC_URL = "https://auth.codestra.co"
INFRASTRUCTURE_SHA = "61787bd39515b775ba6b22c3e7af5862b44b3dad"
PROMETHEUS_SHA = "4230ec1c398db69e8ca95848135b13dd84e03c94"
OLD_INFRASTRUCTURE_SHA = "cf0bdb702660db84642433b89ac8c61f68b6df44"
OLD_PROMETHEUS_SHA = "e2aa1793764421fb87da1d2e3525100c098c09c9"
SCOPE_NAMES = ("health.read", "metrics.read")


def load_module():
    spec = importlib.util.spec_from_file_location("monitoring_reconcile", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def main() -> None:
    desired = json.loads(CLIENT.read_text())
    assert desired["clientId"] == "monitoring-readonly"
    assert desired["enabled"] is True
    assert desired["publicClient"] is False
    assert desired["serviceAccountsEnabled"] is True
    assert desired["standardFlowEnabled"] is False
    assert desired["implicitFlowEnabled"] is False
    assert desired["directAccessGrantsEnabled"] is False
    assert desired["fullScopeAllowed"] is False
    assert desired["redirectUris"] == [] and desired["webOrigins"] == []
    assert desired["defaultClientScopes"] == []
    assert desired["optionalClientScopes"] == list(SCOPE_NAMES)
    assert desired["attributes"]["access.token.lifespan"] == "300"
    mappers = {item["name"]: item for item in desired["protocolMappers"]}
    assert mappers["audience-middleware-api"]["config"]["included.custom.audience"] == "middleware-api"
    assert "reviewed-service-scopes" not in mappers
    assert "secret" not in desired

    for name in SCOPE_NAMES:
        scope = json.loads((CLIENT_SCOPE_DIR / f"{name}.json").read_text())
        assert scope["name"] == name
        assert scope["protocol"] == "openid-connect"
        assert scope["protocolMappers"] == []
        assert scope["attributes"] == {
            "display.on.consent.screen": "false",
            "include.in.token.scope": "true",
        }

    matrix = json.loads(SERVICE_MATRIX.read_text())
    monitoring_grants = [
        grant
        for grant in matrix["grants"]
        if grant["callerClientId"] == "monitoring-readonly"
    ]
    assert monitoring_grants
    assert all(grant["scopes"] == list(SCOPE_NAMES) for grant in monitoring_grants)

    endpoints = json.loads(STAGING_ENDPOINTS.read_text())
    assert endpoints["publicUrl"] == STAGING_PUBLIC_URL
    assert endpoints["adminApiBaseUrl"] == STAGING_PUBLIC_URL
    assert endpoints["issuer"] == STAGING_PUBLIC_URL + "/realms/codestra"
    assert endpoints["jwksUri"] == STAGING_PUBLIC_URL + "/realms/codestra/protocol/openid-connect/certs"
    assert endpoints["tokenEndpoint"] == STAGING_PUBLIC_URL + "/realms/codestra/protocol/openid-connect/token"
    assert endpoints["realm"] == "codestra"
    assert endpoints["adminAuthenticationRealm"] == "master"
    assert all(PRODUCTION_PUBLIC_URL not in str(value) for value in endpoints.values())

    source = SCRIPT.read_text()
    ast.parse(source)
    assert 'CLIENT_ID = "monitoring-readonly"' in source
    assert 'PUBLIC_URL = "https://auth-staging.codestra.co"' in source
    assert 'SCOPE_NAMES = ("health.read", "metrics.read")' in source
    assert '"scope": expected_scope' in source
    assert 'scopes != {expected_scope}' in source
    assert 'other_clients_modified": False' in source
    assert 'os.chmod(path, 0o600)' in source
    assert 'metrics.token' in source and 'health.token' in source
    assert 'exact_scope_isolation": True' in source
    assert 'print(metrics_token)' not in source
    assert 'print(health_token)' not in source
    assert 'print(secret)' not in source
    assert 'PUBLIC_URL = "https://auth.codestra.co"' not in source

    renderer = RENDERER.read_text()
    ast.parse(renderer)
    assert 'MONITORING_OPTIONAL_SCOPES = ("health.read", "metrics.read")' in renderer
    assert 'CLIENT_SCOPE_DIR' in renderer
    assert 'optional_client_scopes = list(MONITORING_OPTIONAL_SCOPES)' in renderer
    assert 'reviewed-service-scopes' in renderer

    workflow = RUNTIME_WORKFLOW.read_text()
    assert workflow.count(INFRASTRUCTURE_SHA) >= 2
    assert workflow.count(PROMETHEUS_SHA) >= 2
    assert OLD_INFRASTRUCTURE_SHA not in workflow
    assert OLD_PROMETHEUS_SHA not in workflow
    assert workflow.count(STAGING_PUBLIC_URL) >= 2
    assert "KC_BASE_URL: ${{ vars.KC_BASE_URL }}" in workflow
    assert "KC_PUBLIC_URL: ${{ vars.KC_PUBLIC_URL }}" in workflow
    assert "collect_staging_intake_evidence_v2.py" in workflow
    assert "production_identity_endpoint_allowed == false" in workflow
    assert "PROMETHEUS_TARGET_STATE=pending" in workflow
    assert "BLACKBOX_TARGET_STATE=pending" in workflow

    module = load_module()
    validated = module.desired_client(CLIENT)
    assert validated["clientId"] == "monitoring-readonly"
    for name in SCOPE_NAMES:
        module.desired_client_scope(CLIENT_SCOPE_DIR / f"{name}.json", name)
    assert module.PUBLIC_URL == STAGING_PUBLIC_URL
    assert module.SCOPE_NAMES == SCOPE_NAMES
    print("KEYCLOAK_STAGE6_INTAKE_OBSERVABILITY_SOURCE=PASS")


if __name__ == "__main__":
    main()
