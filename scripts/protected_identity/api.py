from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .common import ENDPOINTS, fail, load_json, assert_no_sensitive_fields, canonical_bytes

@dataclass
class Environment:
    base_url: str
    public_url: str
    target_realm: str
    admin_realm: str
    admin_client_id: str
    admin_client_secret: str | None
    admin_username: str | None
    admin_password: str | None
    deployment_environment: str

    @classmethod
    def from_os(cls) -> "Environment":
        endpoints = load_json(ENDPOINTS)
        if not isinstance(endpoints, dict):
            fail("canonical endpoint contract must be an object")
        base_url = os.environ.get("KC_BASE_URL", "").rstrip("/")
        public_url = os.environ.get("KC_PUBLIC_URL", endpoints.get("publicUrl", ""))
        target_realm = os.environ.get("KC_TARGET_REALM", endpoints.get("realm", ""))
        admin_realm = os.environ.get("KC_ADMIN_REALM", endpoints.get("adminAuthenticationRealm", ""))
        admin_client_id = os.environ.get("KC_ADMIN_CLIENT_ID", "")
        deployment_environment = os.environ.get("DEPLOY_ENVIRONMENT", "")
        if deployment_environment not in {"staging", "production"}:
            fail("DEPLOY_ENVIRONMENT must be staging or production")
        if not base_url or not admin_client_id:
            fail("KC_BASE_URL and KC_ADMIN_CLIENT_ID are required")
        canonical_base = str(endpoints.get("adminApiBaseUrl", "")).rstrip("/")
        is_local_test = base_url.startswith("http://127.0.0.1:") or base_url.startswith("http://localhost:")
        if base_url != canonical_base:
            if not (is_local_test and os.environ.get("ALLOW_NONCANONICAL_KC_BASE_URL_FOR_TESTS") == "true"):
                fail(f"KC_BASE_URL must equal {canonical_base}")
        if is_local_test and os.environ.get("ALLOW_INSECURE_KC_BASE_URL") != "true":
            fail("localhost HTTP requires ALLOW_INSECURE_KC_BASE_URL=true")
        if not (base_url.startswith("https://") or is_local_test):
            fail("KC_BASE_URL must use HTTPS")
        if public_url != endpoints.get("publicUrl"):
            fail("KC_PUBLIC_URL is not canonical")
        if target_realm != endpoints.get("realm"):
            fail("KC_TARGET_REALM is not canonical")
        if admin_realm != endpoints.get("adminAuthenticationRealm"):
            fail("KC_ADMIN_REALM is not canonical")
        secret = os.environ.get("KC_ADMIN_CLIENT_SECRET")
        username = os.environ.get("KC_ADMIN_USERNAME")
        password = os.environ.get("KC_ADMIN_PASSWORD")
        if not secret and not (username and password):
            fail("set KC_ADMIN_CLIENT_SECRET or KC_ADMIN_USERNAME/KC_ADMIN_PASSWORD")
        return cls(base_url, public_url, target_realm, admin_realm, admin_client_id, secret, username, password, deployment_environment)


class KeycloakAdmin:
    def __init__(self, env: Environment):
        self.env = env
        self.token = self._authenticate()

    def _request_raw(self, request: urllib.request.Request, *, allow_404: bool = False) -> bytes | None:
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if allow_404 and exc.code == 404:
                return None
            fail(f"Keycloak API request failed with HTTP {exc.code}: {request.method} {request.full_url}")
        except urllib.error.URLError as exc:
            fail(f"Keycloak API request failed: {exc.reason}")

    def _authenticate(self) -> str:
        token_url = f"{self.env.base_url}/realms/{urllib.parse.quote(self.env.admin_realm, safe='')}/protocol/openid-connect/token"
        if self.env.admin_client_secret:
            form = {
                "grant_type": "client_credentials",
                "client_id": self.env.admin_client_id,
                "client_secret": self.env.admin_client_secret,
            }
        else:
            form = {
                "grant_type": "password",
                "client_id": self.env.admin_client_id,
                "username": self.env.admin_username or "",
                "password": self.env.admin_password or "",
            }
        request = urllib.request.Request(
            token_url,
            data=urllib.parse.urlencode(form).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            method="POST",
        )
        body = self._request_raw(request)
        try:
            value = json.loads((body or b"").decode("utf-8"))
            token = value["access_token"]
        except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError):
            fail("Keycloak token response did not contain an access token")
        if not isinstance(token, str) or not token:
            fail("Keycloak access token is invalid")
        return token

    def request(self, method: str, path: str, body: dict[str, Any] | None = None, *, allow_404: bool = False) -> Any:
        if not path.startswith("/"):
            fail("Keycloak API path must begin with /")
        data = None
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        if body is not None:
            assert_no_sensitive_fields(body, f"request {method} {path}")
            data = canonical_bytes(body)
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.env.base_url + path, data=data, headers=headers, method=method)
        raw = self._request_raw(request, allow_404=allow_404)
        if raw is None or not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            fail(f"Keycloak API returned invalid JSON: {method} {path}")

    @property
    def realm_path(self) -> str:
        return f"/admin/realms/{urllib.parse.quote(self.env.target_realm, safe='')}"

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        query = urllib.parse.urlencode({"clientId": client_id, "exact": "true"})
        matches = self.request("GET", f"{self.realm_path}/clients?{query}")
        if not isinstance(matches, list):
            fail(f"invalid client lookup response for {client_id}")
        if len(matches) > 1:
            fail(f"multiple clients matched clientId={client_id}")
        if not matches:
            return None
        client_uuid = matches[0].get("id")
        if not isinstance(client_uuid, str) or not client_uuid:
            fail(f"client lookup omitted id for {client_id}")
        value = self.request("GET", f"{self.realm_path}/clients/{urllib.parse.quote(client_uuid, safe='')}")
        if not isinstance(value, dict):
            fail(f"invalid client representation for {client_id}")
        return value

    def get_client_uuid(self, client_id: str) -> str | None:
        query = urllib.parse.urlencode({"clientId": client_id, "exact": "true"})
        matches = self.request("GET", f"{self.realm_path}/clients?{query}")
        if not isinstance(matches, list) or len(matches) > 1:
            fail(f"invalid client lookup response for {client_id}")
        if not matches:
            return None
        value = matches[0].get("id")
        if not isinstance(value, str) or not value:
            fail(f"client lookup omitted id for {client_id}")
        return value

    def get_role(self, role_name: str) -> dict[str, Any] | None:
        value = self.request("GET", f"{self.realm_path}/roles/{urllib.parse.quote(role_name, safe='')}", allow_404=True)
        if value is None:
            return None
        if not isinstance(value, dict):
            fail(f"invalid realm-role representation for {role_name}")
        return value
