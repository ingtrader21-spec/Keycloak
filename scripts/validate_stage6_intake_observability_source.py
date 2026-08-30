#!/usr/bin/env python3
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/reconcile_monitoring_readonly_staging.py"
CLIENT = ROOT / "config/clients/monitoring-readonly.json"


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
    assert desired["attributes"]["access.token.lifespan"] == "300"
    mappers = {item["name"]: item for item in desired["protocolMappers"]}
    assert mappers["audience-middleware-api"]["config"]["included.custom.audience"] == "middleware-api"
    assert set(mappers["reviewed-service-scopes"]["config"]["claim.value"].split()) == {"metrics.read", "health.read"}
    assert "secret" not in desired

    source = SCRIPT.read_text()
    ast.parse(source)
    assert 'CLIENT_ID = "monitoring-readonly"' in source
    assert 'TARGET_REALM = "codestra"' in source
    assert 'PUBLIC_URL = "https://auth.codestra.co"' in source
    assert 'other_clients_modified": False' in source
    assert 'os.chmod(path, 0o600)' in source
    assert 'metrics.token' in source and 'health.token' in source
    assert 'print(metrics_token)' not in source
    assert 'print(health_token)' not in source
    assert 'print(secret)' not in source

    module = load_module()
    validated = module.desired_client(CLIENT)
    assert validated["clientId"] == "monitoring-readonly"
    assert module.REQUIRED_SCOPES == {"metrics.read", "health.read"}
    print("KEYCLOAK_STAGE6_INTAKE_OBSERVABILITY_SOURCE=PASS")


if __name__ == "__main__":
    main()
