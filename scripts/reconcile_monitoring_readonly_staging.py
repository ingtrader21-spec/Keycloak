#!/usr/bin/env python3
"""Narrow Stage 6 reconciliation for the monitoring-readonly Keycloak identity.

Only one confidential client and two dedicated optional client scopes are
managed. Client secrets and bearer tokens are written to 0600 files outside the
Git checkout, never printed, and never written to uploaded evidence.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CLIENT_ID = "monitoring-readonly"
TARGET_REALM = "codestra"
PUBLIC_URL = "https://auth-staging.codestra.co"
SCOPE_NAMES = ("health.read", "metrics.read")
CLIENT_SCOPE_DIR = ROOT / "config/client-scopes"
CLIENT_MANAGED_KEYS = {
    "clientId", "name", "description", "enabled", "protocol", "publicClient",
    "bearerOnly", "consentRequired", "standardFlowEnabled", "implicitFlowEnabled",
    "directAccessGrantsEnabled", "serviceAccountsEnabled",
    "authorizationServicesEnabled", "frontchannelLogout", "fullScopeAllowed",
    "redirectUris", "webOrigins", "defaultClientScopes", "optionalClientScopes",
    "attributes", "protocolMappers",
}
CLIENT_SCOPE_MANAGED_KEYS = {
    "name", "description", "protocol", "attributes", "protocolMappers"
}


class ReconciliationError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ReconciliationError(f"redirect prohibited: {code}")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_hash(value: object) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    )


def validate_output_dir(path: Path) -> Path:
    if not path.is_absolute():
        raise ReconciliationError(
            "output directory must be an absolute path outside the repository"
        )
    if path.is_symlink():
        raise ReconciliationError("output directory must not be a symlink")
    resolved = path.resolve(strict=False)
    repository = ROOT.resolve()
    if resolved == repository or repository in resolved.parents:
        raise ReconciliationError("secret outputs must remain outside the Git checkout")
    current = resolved
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise ReconciliationError("output directory contains a symlink component")
        current = current.parent
    resolved.mkdir(parents=True, exist_ok=True)
    os.chmod(resolved, 0o700)
    if stat.S_IMODE(resolved.stat().st_mode) & 0o077:
        raise ReconciliationError("output directory permissions must be 0700 or stricter")
    return resolved


def private_write(path: Path, value: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ReconciliationError(f"output path is a symlink: {path}")
    data = value.encode() if isinstance(value, str) else value
    path.write_bytes(data)
    os.chmod(path, 0o600)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ReconciliationError(f"output permissions are unsafe: {path}")


def http_request(
    method: str,
    url: str,
    *,
    bearer: str | None = None,
    json_body: object | None = None,
    form: dict[str, str] | None = None,
    expected: set[int] = {200},
) -> tuple[int, dict[str, str], bytes]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "codestra-keycloak-stage6/2.0",
    }
    body: bytes | None = None
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(json_body, separators=(",", ":")).encode()
    elif form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urllib.parse.urlencode(form).encode()
    request = urllib.request.Request(url, method=method, data=body, headers=headers)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=15) as response:
            status = response.status
            response_headers = {
                key.lower(): value for key, value in response.headers.items()
            }
            response_body = response.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        response_headers = {
            key.lower(): value for key, value in exc.headers.items()
        }
        response_body = exc.read()
    except Exception as exc:
        raise ReconciliationError(
            f"Keycloak request failed: {method} {urllib.parse.urlsplit(url).path}"
        ) from exc
    if status not in expected:
        raise ReconciliationError(
            f"Keycloak request returned HTTP {status}: "
            f"{method} {urllib.parse.urlsplit(url).path}"
        )
    return status, response_headers, response_body


def json_response(body: bytes, context: str) -> Any:
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise ReconciliationError(f"{context} returned invalid JSON") from exc


def project_like(current: Any, template: Any) -> Any:
    if isinstance(template, dict):
        if not isinstance(current, dict):
            return None
        return {
            key: project_like(current.get(key), child)
            for key, child in sorted(template.items())
        }
    if isinstance(template, list):
        if not isinstance(current, list):
            return None
        if all(
            isinstance(item, dict) and isinstance(item.get("name"), str)
            for item in template
        ):
            current_by_name = {
                item.get("name"): item
                for item in current
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            }
            return [
                project_like(current_by_name.get(item["name"]), item)
                for item in template
            ]
        if all(not isinstance(item, (dict, list)) for item in template):
            try:
                return sorted(current)
            except TypeError:
                return current
        if len(current) != len(template):
            return None
        return [
            project_like(value, shape)
            for value, shape in zip(current, template)
        ]
    return current


def managed_projection(
    value: dict[str, Any], desired_shape: dict[str, Any], keys: set[str]
) -> dict[str, Any]:
    return {
        key: project_like(value.get(key), desired_shape.get(key))
        for key in sorted(keys)
    }


def desired_client(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if value.get("clientId") != CLIENT_ID:
        raise ReconciliationError("desired client ID is not monitoring-readonly")
    required_flags = {
        "enabled": True,
        "publicClient": False,
        "bearerOnly": False,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "authorizationServicesEnabled": False,
        "fullScopeAllowed": False,
    }
    for key, expected in required_flags.items():
        if value.get(key) is not expected:
            raise ReconciliationError(f"unsafe desired client setting: {key}")
    if value.get("redirectUris") != [] or value.get("webOrigins") != []:
        raise ReconciliationError("monitoring client must not declare browser origins")
    if value.get("defaultClientScopes") != []:
        raise ReconciliationError("monitoring client must not have default client scopes")
    if tuple(value.get("optionalClientScopes", [])) != SCOPE_NAMES:
        raise ReconciliationError("monitoring optional scopes are not exact")
    lifespan = int((value.get("attributes") or {}).get("access.token.lifespan", "0"))
    if lifespan < 60 or lifespan > 300:
        raise ReconciliationError("monitoring token lifespan must be 60-300 seconds")
    mappers = {item.get("name"): item for item in value.get("protocolMappers", [])}
    if set(mappers) != {"audience-middleware-api"}:
        raise ReconciliationError(
            "monitoring client must have exactly one middleware audience mapper"
        )
    audience = mappers["audience-middleware-api"]
    if (audience.get("config") or {}).get("included.custom.audience") != "middleware-api":
        raise ReconciliationError("middleware-api audience mapper is missing")
    if "secret" in value:
        raise ReconciliationError("client secret must not be committed")
    return value


def desired_client_scope(path: Path, expected_name: str) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if value.get("name") != expected_name or expected_name not in SCOPE_NAMES:
        raise ReconciliationError("monitoring client-scope name is not approved")
    if value.get("protocol") != "openid-connect":
        raise ReconciliationError("monitoring client scope must use OpenID Connect")
    if value.get("protocolMappers") != []:
        raise ReconciliationError("monitoring client scope must not add claims or audiences")
    attributes = value.get("attributes")
    if attributes != {
        "display.on.consent.screen": "false",
        "include.in.token.scope": "true",
    }:
        raise ReconciliationError("monitoring client-scope attributes are not exact")
    return value


def admin_token(base_url: str, admin_realm: str, client_id: str, client_secret: str) -> str:
    _, _, body = http_request(
        "POST",
        f"{base_url}/realms/{urllib.parse.quote(admin_realm)}/protocol/openid-connect/token",
        form={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    token = json_response(body, "admin token").get("access_token")
    if not isinstance(token, str) or not token:
        raise ReconciliationError("admin access token is missing")
    return token


def list_client(base_url: str, realm: str, bearer: str) -> list[dict[str, Any]]:
    _, _, body = http_request(
        "GET",
        f"{base_url}/admin/realms/{urllib.parse.quote(realm)}/clients"
        f"?clientId={urllib.parse.quote(CLIENT_ID)}",
        bearer=bearer,
    )
    value = json_response(body, "client query")
    if not isinstance(value, list) or len(value) > 1:
        raise ReconciliationError("monitoring client query is ambiguous")
    return value


def list_client_scopes(base_url: str, realm: str, bearer: str) -> list[dict[str, Any]]:
    _, _, body = http_request(
        "GET",
        f"{base_url}/admin/realms/{urllib.parse.quote(realm)}/client-scopes",
        bearer=bearer,
    )
    value = json_response(body, "client-scope query")
    if not isinstance(value, list):
        raise ReconciliationError("client-scope query did not return a list")
    return value


def get_client_scope(
    base_url: str, realm: str, scope_id: str, bearer: str
) -> dict[str, Any]:
    _, _, body = http_request(
        "GET",
        f"{base_url}/admin/realms/{urllib.parse.quote(realm)}/client-scopes/"
        f"{urllib.parse.quote(scope_id)}",
        bearer=bearer,
    )
    value = json_response(body, "client-scope readback")
    if not isinstance(value, dict):
        raise ReconciliationError("client-scope readback is not an object")
    return value


def find_scope(
    base_url: str, realm: str, bearer: str, scope_name: str
) -> dict[str, Any] | None:
    matches = [
        item
        for item in list_client_scopes(base_url, realm, bearer)
        if isinstance(item, dict) and item.get("name") == scope_name
    ]
    if len(matches) > 1:
        raise ReconciliationError(f"duplicate Keycloak client scope: {scope_name}")
    return matches[0] if matches else None


def scope_plan_action(
    base_url: str,
    realm: str,
    bearer: str,
    desired: dict[str, Any],
) -> tuple[str, dict[str, Any] | None]:
    summary = find_scope(base_url, realm, bearer, str(desired["name"]))
    if summary is None:
        return "create", None
    scope_id = str(summary.get("id") or "")
    if not scope_id:
        raise ReconciliationError("existing client scope has no internal ID")
    current = get_client_scope(base_url, realm, scope_id, bearer)
    current_projection = managed_projection(
        current, desired, CLIENT_SCOPE_MANAGED_KEYS
    )
    desired_projection = managed_projection(
        desired, desired, CLIENT_SCOPE_MANAGED_KEYS
    )
    return ("none" if current_projection == desired_projection else "update"), current


def apply_client_scope(
    base_url: str,
    realm: str,
    bearer: str,
    desired: dict[str, Any],
) -> tuple[str, str]:
    scope_name = str(desired["name"])
    action, current = scope_plan_action(base_url, realm, bearer, desired)
    if action == "create":
        _, headers, _ = http_request(
            "POST",
            f"{base_url}/admin/realms/{urllib.parse.quote(realm)}/client-scopes",
            bearer=bearer,
            json_body=desired,
            expected={201},
        )
        scope_id = headers.get("location", "").rstrip("/").rsplit("/", 1)[-1]
        if not scope_id:
            created = find_scope(base_url, realm, bearer, scope_name)
            scope_id = str((created or {}).get("id") or "")
        if not scope_id:
            raise ReconciliationError(f"created client scope cannot be resolved: {scope_name}")
        return scope_id, "created"
    assert current is not None
    scope_id = str(current.get("id") or "")
    if action == "none":
        return scope_id, "unchanged"
    merged = dict(current)
    for key in CLIENT_SCOPE_MANAGED_KEYS:
        merged[key] = desired.get(key)
    http_request(
        "PUT",
        f"{base_url}/admin/realms/{urllib.parse.quote(realm)}/client-scopes/"
        f"{urllib.parse.quote(scope_id)}",
        bearer=bearer,
        json_body=merged,
        expected={204},
    )
    return scope_id, "updated"


def apply_client(
    base_url: str, realm: str, bearer: str, desired: dict[str, Any]
) -> tuple[str, str]:
    desired_projection = managed_projection(desired, desired, CLIENT_MANAGED_KEYS)
    current_list = list_client(base_url, realm, bearer)
    if not current_list:
        _, headers, _ = http_request(
            "POST",
            f"{base_url}/admin/realms/{urllib.parse.quote(realm)}/clients",
            bearer=bearer,
            json_body=desired,
            expected={201},
        )
        internal_id = headers.get("location", "").rstrip("/").rsplit("/", 1)[-1]
        if not internal_id:
            created = list_client(base_url, realm, bearer)
            internal_id = str((created[0] if created else {}).get("id") or "")
        if not internal_id:
            raise ReconciliationError("created client ID cannot be resolved")
        return internal_id, "created"

    current = current_list[0]
    internal_id = str(current.get("id") or "")
    if not internal_id:
        raise ReconciliationError("current client has no internal ID")
    if managed_projection(current, desired, CLIENT_MANAGED_KEYS) == desired_projection:
        return internal_id, "unchanged"
    merged = dict(current)
    for key in CLIENT_MANAGED_KEYS:
        merged[key] = desired.get(key)
    http_request(
        "PUT",
        f"{base_url}/admin/realms/{urllib.parse.quote(realm)}/clients/"
        f"{urllib.parse.quote(internal_id)}",
        bearer=bearer,
        json_body=merged,
        expected={204},
    )
    return internal_id, "updated"


def optional_scope_links(
    base_url: str, realm: str, client_id: str, bearer: str
) -> list[dict[str, Any]]:
    _, _, body = http_request(
        "GET",
        f"{base_url}/admin/realms/{urllib.parse.quote(realm)}/clients/"
        f"{urllib.parse.quote(client_id)}/optional-client-scopes",
        bearer=bearer,
    )
    value = json_response(body, "optional client-scope links")
    if not isinstance(value, list):
        raise ReconciliationError("optional client-scope links are not a list")
    return value


def reconcile_optional_scope_links(
    base_url: str,
    realm: str,
    client_id: str,
    bearer: str,
    desired_scope_ids: dict[str, str],
) -> list[str]:
    actions: list[str] = []
    current = optional_scope_links(base_url, realm, client_id, bearer)
    current_by_name = {
        str(item.get("name")): str(item.get("id") or "")
        for item in current
        if isinstance(item, dict) and item.get("name")
    }
    for name, scope_id in current_by_name.items():
        if name not in desired_scope_ids:
            if not scope_id:
                raise ReconciliationError("unexpected optional client scope has no ID")
            http_request(
                "DELETE",
                f"{base_url}/admin/realms/{urllib.parse.quote(realm)}/clients/"
                f"{urllib.parse.quote(client_id)}/optional-client-scopes/"
                f"{urllib.parse.quote(scope_id)}",
                bearer=bearer,
                expected={204},
            )
            actions.append(f"removed:{name}")
    for name, scope_id in desired_scope_ids.items():
        if current_by_name.get(name) != scope_id:
            http_request(
                "PUT",
                f"{base_url}/admin/realms/{urllib.parse.quote(realm)}/clients/"
                f"{urllib.parse.quote(client_id)}/optional-client-scopes/"
                f"{urllib.parse.quote(scope_id)}",
                bearer=bearer,
                expected={204},
            )
            actions.append(f"linked:{name}")
    readback = optional_scope_links(base_url, realm, client_id, bearer)
    readback_names = sorted(
        str(item.get("name"))
        for item in readback
        if isinstance(item, dict) and item.get("name")
    )
    if readback_names != list(SCOPE_NAMES):
        raise ReconciliationError("monitoring optional client-scope links are not exact")
    return actions or ["unchanged"]


def client_secret(base_url: str, realm: str, internal_id: str, bearer: str) -> str:
    _, _, body = http_request(
        "GET",
        f"{base_url}/admin/realms/{urllib.parse.quote(realm)}/clients/"
        f"{urllib.parse.quote(internal_id)}/client-secret",
        bearer=bearer,
    )
    value = json_response(body, "client secret").get("value")
    if not isinstance(value, str) or len(value) < 20:
        raise ReconciliationError("monitoring client secret is missing")
    return value


def decode_token_metadata(token: str, expected_scope: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ReconciliationError("issued token is not a compact JWT")
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())
    except Exception as exc:
        raise ReconciliationError("issued token payload cannot be decoded") from exc
    issued = payload.get("iat")
    expires = payload.get("exp")
    if isinstance(issued, bool) or not isinstance(issued, (int, float)):
        raise ReconciliationError("issued token has no iat")
    if isinstance(expires, bool) or not isinstance(expires, (int, float)):
        raise ReconciliationError("issued token has no exp")
    ttl = int(expires - issued)
    audience = payload.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    scopes = set(payload.get("scope", "").split()) if isinstance(payload.get("scope"), str) else set()
    if payload.get("azp") != CLIENT_ID:
        raise ReconciliationError("issued token azp is incorrect")
    if audiences != ["middleware-api"]:
        raise ReconciliationError(
            "issued token audiences must equal only middleware-api"
        )
    if scopes != {expected_scope}:
        raise ReconciliationError(
            f"issued token scopes must equal only {expected_scope}"
        )
    if ttl < 60 or ttl > 300:
        raise ReconciliationError("issued token lifetime is outside 60-300 seconds")
    return {
        "client_id": CLIENT_ID,
        "audience": "middleware-api",
        "scopes": [expected_scope],
        "ttl_seconds": ttl,
        "issued_at": int(issued),
        "expires_at": int(expires),
        "token_sha256": sha256_bytes(token.encode()),
    }


def issue_token(
    public_url: str, realm: str, secret: str, expected_scope: str
) -> tuple[str, dict[str, Any]]:
    _, _, body = http_request(
        "POST",
        f"{public_url}/realms/{urllib.parse.quote(realm)}/protocol/openid-connect/token",
        form={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": secret,
            "scope": expected_scope,
        },
    )
    token = json_response(body, "monitoring token").get("access_token")
    if not isinstance(token, str) or not token:
        raise ReconciliationError("monitoring access token is missing")
    return token, decode_token_metadata(token, expected_scope)


def validate_runtime_urls(
    base_url: str,
    public_url: str,
    target_realm: str,
    *,
    allow_loopback_admin: bool,
) -> None:
    if public_url.rstrip("/") != PUBLIC_URL:
        raise ReconciliationError(
            "public Keycloak URL must be https://auth-staging.codestra.co"
        )
    if target_realm != TARGET_REALM:
        raise ReconciliationError("target realm must be codestra")
    parsed = urllib.parse.urlsplit(base_url)
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ReconciliationError("KC_BASE_URL contains forbidden URL components")
    normalized = base_url.rstrip("/")
    if normalized == PUBLIC_URL:
        if parsed.scheme != "https" or parsed.hostname != "auth-staging.codestra.co":
            raise ReconciliationError("canonical staging admin endpoint must use HTTPS")
        return
    loopback_hosts = {"127.0.0.1", "::1", "localhost"}
    if (
        allow_loopback_admin
        and parsed.scheme in {"http", "https"}
        and parsed.hostname in loopback_hosts
    ):
        return
    raise ReconciliationError(
        "KC_BASE_URL must be the canonical staging HTTPS endpoint or an explicitly allowed loopback endpoint"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("plan", "apply-and-issue"), required=True)
    parser.add_argument(
        "--desired-client",
        type=Path,
        default=Path("config/clients/monitoring-readonly.json"),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    output_dir = validate_output_dir(args.output_dir)
    desired = desired_client(args.desired_client)
    desired_scopes = {
        name: desired_client_scope(CLIENT_SCOPE_DIR / f"{name}.json", name)
        for name in SCOPE_NAMES
    }
    desired_projection = managed_projection(desired, desired, CLIENT_MANAGED_KEYS)
    base_url = os.environ.get("KC_BASE_URL", "").rstrip("/")
    public_url = os.environ.get("KC_PUBLIC_URL", "").rstrip("/")
    target_realm = os.environ.get("KC_TARGET_REALM", "")
    admin_realm = os.environ.get("KC_ADMIN_REALM", "")
    admin_client_id = os.environ.get("KC_ADMIN_CLIENT_ID", "")
    admin_client_secret = os.environ.get("KC_ADMIN_CLIENT_SECRET", "")
    allow_loopback_admin = (
        os.environ.get("KC_ALLOW_LOOPBACK_ADMIN", "false").strip().lower()
        == "true"
    )
    validate_runtime_urls(
        base_url,
        public_url,
        target_realm,
        allow_loopback_admin=allow_loopback_admin,
    )
    if not admin_realm or not admin_client_id or not admin_client_secret:
        raise ReconciliationError("protected Keycloak administrator inputs are incomplete")

    bearer = admin_token(base_url, admin_realm, admin_client_id, admin_client_secret)
    current = list_client(base_url, target_realm, bearer)
    before = (
        managed_projection(current[0], desired, CLIENT_MANAGED_KEYS)
        if current
        else None
    )
    client_action = (
        "create"
        if not current
        else ("none" if before == desired_projection else "update")
    )
    scope_actions: dict[str, str] = {}
    for name, scope in desired_scopes.items():
        scope_actions[name] = scope_plan_action(
            base_url, target_realm, bearer, scope
        )[0]
    plan = {
        "schema_version": "1.1",
        "environment": "staging",
        "realm": target_realm,
        "client_id": CLIENT_ID,
        "client_action": client_action,
        "client_scope_actions": scope_actions,
        "optional_client_scopes": list(SCOPE_NAMES),
        "current_managed_sha256": (
            canonical_hash(before) if before is not None else None
        ),
        "desired_managed_sha256": canonical_hash(desired_projection),
        "other_clients_modified": False,
        "token_values_recorded": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    private_write(
        output_dir / "monitoring-readonly-plan.json",
        json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n",
    )
    if args.mode == "plan":
        print("MONITORING_READONLY_PLAN=PASS")
        return 0

    scope_ids: dict[str, str] = {}
    scope_results: dict[str, str] = {}
    for name, scope in desired_scopes.items():
        scope_id, result = apply_client_scope(
            base_url, target_realm, bearer, scope
        )
        scope_ids[name] = scope_id
        scope_results[name] = result
    internal_id, client_result = apply_client(
        base_url, target_realm, bearer, desired
    )
    link_results = reconcile_optional_scope_links(
        base_url, target_realm, internal_id, bearer, scope_ids
    )

    applied = list_client(base_url, target_realm, bearer)
    if (
        len(applied) != 1
        or managed_projection(applied[0], desired, CLIENT_MANAGED_KEYS)
        != desired_projection
    ):
        raise ReconciliationError("monitoring client readback differs from desired source")
    for name, scope_id in scope_ids.items():
        readback = get_client_scope(
            base_url, target_realm, scope_id, bearer
        )
        if managed_projection(
            readback, desired_scopes[name], CLIENT_SCOPE_MANAGED_KEYS
        ) != managed_projection(
            desired_scopes[name], desired_scopes[name], CLIENT_SCOPE_MANAGED_KEYS
        ):
            raise ReconciliationError(
                f"monitoring client-scope readback differs: {name}"
            )

    secret = client_secret(base_url, target_realm, internal_id, bearer)
    metrics_token, metrics_metadata = issue_token(
        public_url, target_realm, secret, "metrics.read"
    )
    health_token, health_metadata = issue_token(
        public_url, target_realm, secret, "health.read"
    )
    if (
        metrics_token == health_token
        or metrics_metadata["token_sha256"] == health_metadata["token_sha256"]
    ):
        raise ReconciliationError("monitoring tokens were not independently issued")

    private_write(output_dir / "monitoring-client-secret", secret + "\n")
    private_write(output_dir / "metrics.token", metrics_token + "\n")
    private_write(output_dir / "health.token", health_token + "\n")
    evidence = {
        "schema_version": "1.1",
        "environment": "staging",
        "keycloak_public_url": PUBLIC_URL,
        "realm": target_realm,
        "client_id": CLIENT_ID,
        "client_apply_result": client_result,
        "client_scope_apply_results": scope_results,
        "optional_scope_link_results": link_results,
        "optional_client_scopes": list(SCOPE_NAMES),
        "desired_managed_sha256": canonical_hash(desired_projection),
        "metrics_token": metrics_metadata,
        "health_token": health_metadata,
        "independently_issued": True,
        "exact_scope_isolation": True,
        "token_values_recorded": False,
        "client_secret_recorded": False,
        "other_clients_modified": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    private_write(
        output_dir / "monitoring-token-evidence.json",
        json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
    )
    print("MONITORING_READONLY_APPLY_AND_ISSUE=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReconciliationError as exc:
        print(f"MONITORING_READONLY_RECONCILIATION=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
