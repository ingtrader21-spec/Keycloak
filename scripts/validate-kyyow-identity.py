#!/usr/bin/env python3
import json
from pathlib import Path
from urllib.parse import urlparse

root = Path(__file__).resolve().parents[1]
contract = json.loads((root / "contracts/kyyow-saas-identity-v1.json").read_text())

assert contract["contract_version"] == "1.0"
assert contract["realm"] == "kyyow"
assert contract["issuer"] == "https://auth.kyyow.com/realms/kyyow"
assert contract["status"] == "prepared-not-applied"
assert contract["security"]["deployment_authorized"] is False
assert contract["tenant_model"]["single_tenant_per_session"] is True
assert contract["tenant_model"]["tenant_claim_required"] is True
assert "platform-superadmin" in contract["realm_roles"]
assert "administrator" in contract["realm_roles"]
assert len(contract["realm_roles"]) == len(set(contract["realm_roles"]))

ids = [client["client_id"] for client in contract["clients"]]
assert len(ids) == len(set(ids))
for client in contract["clients"]:
    assert client["direct_access_grants"] is False
    if client["type"] == "public-browser":
        assert client["authorization_code_flow"] is True
        assert client["pkce_method"] == "S256"
        assert client["implicit_flow"] is False
        assert client["service_accounts"] is False
        for value in client["redirect_uris"] + client["web_origins"]:
            parsed = urlparse(value)
            assert parsed.scheme == "https" and parsed.hostname == "app.kyyow.com"
            assert "*" not in value
    else:
        assert client["authorization_code_flow"] is False
        assert client["service_accounts"] is True
        assert client["preferred_authentication"][0] in {"tls_client_auth", "private_key_jwt"}

middleware = next(client for client in contract["clients"] if client["client_id"] == "kyyow-middleware-odoo")
assert middleware["scopes"] == ["odoo.kpi.write", "odoo.incident.write"]
for client in contract["clients"]:
    if client is not middleware:
        assert all(not scope.startswith("odoo.") for scope in client.get("scopes", []))

assert contract["token_policy"]["access_token_lifespan_seconds"] <= 300
assert contract["token_policy"]["service_token_lifespan_seconds"] <= 300
assert contract["token_policy"]["refresh_token_rotation"] is True
assert contract["admin_boundary"]["mfa_required"] is True
print("KYYOW_IDENTITY_CONTRACT=PASS")
