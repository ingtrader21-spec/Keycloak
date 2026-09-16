#!/usr/bin/env python3
"""Narrow staging-only reconciliation for the TEST_SYN edge-certification identities.

Only the three ingress client scopes and the five ``test-syn-*`` clients from
``config/desired-state/edge-integration-certification/`` are managed. The
reconciler refuses every Keycloak endpoint except the canonical staging
instance (or an explicitly allowed loopback administrative endpoint), never
touches another client, verifies that no ingress scope is a realm default,
and writes client secrets only to 0600 files outside the Git checkout so the
Middleware certification runner can read them through
``CERTIFY_CLIENT_SECRET_FILE_<ROLE>``. Secrets and tokens are never printed.

Modes:
  plan      read live state and write a plan; no mutation.
  apply     create or update the scopes and clients, read back, export secrets.
  disable   set enabled=false on every certification client (rollback step one).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DESIRED_ROOT = ROOT / "config" / "desired-state" / "edge-integration-certification"
CONTRACT_PATH = DESIRED_ROOT / "contract.json"

sys.path.insert(0, str(ROOT / "scripts"))
_spec = importlib.util.spec_from_file_location(
    "monitoring_reconcile", ROOT / "scripts" / "reconcile_monitoring_readonly_staging.py"
)
assert _spec and _spec.loader
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
import edge_certification_desired_state as desired_state  # noqa: E402

ReconciliationError = _base.ReconciliationError
CLIENT_MANAGED_KEYS = _base.CLIENT_MANAGED_KEYS
CLIENT_SCOPE_MANAGED_KEYS = _base.CLIENT_SCOPE_MANAGED_KEYS


def http_request(*args: Any, **kwargs: Any):
    """Delegate to the Stage 6 transport so one patch point covers both modules."""
    return _base.http_request(*args, **kwargs)


json_response = _base.json_response
managed_projection = _base.managed_projection
validate_output_dir = _base.validate_output_dir
private_write = _base.private_write
admin_token = _base.admin_token
find_scope = _base.find_scope
get_client_scope = _base.get_client_scope
apply_client_scope = _base.apply_client_scope
scope_plan_action = _base.scope_plan_action
client_secret = _base.client_secret
validate_runtime_urls = _base.validate_runtime_urls
canonical_hash = _base.canonical_hash


def realm_path(base_url: str, realm: str, suffix: str) -> str:
    return f"{base_url}/admin/realms/{urllib.parse.quote(realm)}{suffix}"


def load_desired() -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Validated contract, client scopes by name, and clients by clientId."""
    try:
        contract, documents = desired_state.validate()
    except desired_state.DesiredStateError as exc:
        raise ReconciliationError(f"desired state is invalid: {exc}") from exc
    scopes = {
        value["name"]: value
        for path, value in documents
        if path.parent.name == "client-scopes"
    }
    clients = {
        value["clientId"]: value
        for path, value in documents
        if path.parent.name == "clients"
    }
    return contract, scopes, clients


# --- live reads -------------------------------------------------------------------


def find_client(base_url: str, realm: str, bearer: str, client_id: str) -> dict[str, Any] | None:
    _, _, body = http_request(
        "GET",
        realm_path(base_url, realm, f"/clients?clientId={urllib.parse.quote(client_id)}"),
        bearer=bearer,
    )
    value = json_response(body, "client query")
    if not isinstance(value, list) or len(value) > 1:
        raise ReconciliationError(f"client query is ambiguous: {client_id}")
    matches = [item for item in value if isinstance(item, dict) and item.get("clientId") == client_id]
    return matches[0] if matches else None


def realm_default_scope_names(base_url: str, realm: str, bearer: str) -> set[str]:
    names: set[str] = set()
    for collection in ("default-default-client-scopes", "default-optional-client-scopes"):
        _, _, body = http_request("GET", realm_path(base_url, realm, f"/{collection}"), bearer=bearer)
        value = json_response(body, collection)
        if not isinstance(value, list):
            raise ReconciliationError(f"{collection} did not return a list")
        names |= {str(item.get("name")) for item in value if isinstance(item, dict)}
    return names


def assert_no_realm_wide_ingress_grant(base_url: str, realm: str, bearer: str, ingress: set[str]) -> None:
    leaked = realm_default_scope_names(base_url, realm, bearer) & ingress
    if leaked:
        raise ReconciliationError(f"ingress scope is a realm default client scope: {sorted(leaked)}")


def default_scope_links(base_url: str, realm: str, internal_id: str, bearer: str) -> dict[str, str]:
    _, _, body = http_request(
        "GET",
        realm_path(base_url, realm, f"/clients/{urllib.parse.quote(internal_id)}/default-client-scopes"),
        bearer=bearer,
    )
    value = json_response(body, "default client-scope links")
    if not isinstance(value, list):
        raise ReconciliationError("default client-scope links are not a list")
    return {str(item.get("name")): str(item.get("id") or "") for item in value if isinstance(item, dict)}


# --- mutations ----------------------------------------------------------------------


def apply_client(base_url: str, realm: str, bearer: str, desired: dict[str, Any]) -> tuple[str, str]:
    client_id = str(desired["clientId"])
    desired_projection = managed_projection(desired, desired, CLIENT_MANAGED_KEYS)
    current = find_client(base_url, realm, bearer, client_id)
    if current is None:
        _, headers, _ = http_request(
            "POST", realm_path(base_url, realm, "/clients"), bearer=bearer, json_body=desired, expected={201}
        )
        internal_id = headers.get("location", "").rstrip("/").rsplit("/", 1)[-1]
        if not internal_id:
            created = find_client(base_url, realm, bearer, client_id)
            internal_id = str((created or {}).get("id") or "")
        if not internal_id:
            raise ReconciliationError(f"created client ID cannot be resolved: {client_id}")
        return internal_id, "created"
    internal_id = str(current.get("id") or "")
    if not internal_id:
        raise ReconciliationError(f"current client has no internal ID: {client_id}")
    removed = _base.remove_unexpected_client_mappers(base_url, realm, internal_id, bearer, current, desired)
    if removed:
        current = find_client(base_url, realm, bearer, client_id) or {}
    if managed_projection(current, desired, CLIENT_MANAGED_KEYS) == desired_projection:
        return internal_id, "updated" if removed else "unchanged"
    merged = dict(current)
    for key in CLIENT_MANAGED_KEYS:
        merged[key] = desired.get(key)
    http_request(
        "PUT",
        realm_path(base_url, realm, f"/clients/{urllib.parse.quote(internal_id)}"),
        bearer=bearer,
        json_body=merged,
        expected={204},
    )
    return internal_id, "updated"


def reconcile_default_scope_links(
    base_url: str,
    realm: str,
    internal_id: str,
    bearer: str,
    desired_names: list[str],
    scope_ids: dict[str, str],
) -> list[str]:
    actions: list[str] = []
    current = default_scope_links(base_url, realm, internal_id, bearer)
    for name, scope_id in current.items():
        if name not in desired_names:
            if not scope_id:
                raise ReconciliationError(f"unexpected default client scope has no ID: {name}")
            http_request(
                "DELETE",
                realm_path(base_url, realm, f"/clients/{urllib.parse.quote(internal_id)}/default-client-scopes/{urllib.parse.quote(scope_id)}"),
                bearer=bearer,
                expected={204},
            )
            actions.append(f"removed:{name}")
    for name in desired_names:
        scope_id = scope_ids.get(name)
        if not scope_id:
            raise ReconciliationError(f"desired default client scope is not resolvable: {name}")
        if current.get(name) != scope_id:
            http_request(
                "PUT",
                realm_path(base_url, realm, f"/clients/{urllib.parse.quote(internal_id)}/default-client-scopes/{urllib.parse.quote(scope_id)}"),
                bearer=bearer,
                expected={204},
            )
            actions.append(f"linked:{name}")
    readback = default_scope_links(base_url, realm, internal_id, bearer)
    if sorted(readback) != sorted(desired_names):
        raise ReconciliationError(f"default client-scope links are not exact after reconciliation: {sorted(readback)}")
    return actions or ["unchanged"]


def disable_client(base_url: str, realm: str, bearer: str, client_id: str) -> str:
    current = find_client(base_url, realm, bearer, client_id)
    if current is None:
        return "absent"
    if current.get("enabled") is False:
        return "already-disabled"
    merged = dict(current)
    merged["enabled"] = False
    http_request(
        "PUT",
        realm_path(base_url, realm, f"/clients/{urllib.parse.quote(str(current['id']))}"),
        bearer=bearer,
        json_body=merged,
        expected={204},
    )
    readback = find_client(base_url, realm, bearer, client_id)
    if readback is None or readback.get("enabled") is not False:
        raise ReconciliationError(f"client did not read back as disabled: {client_id}")
    return "disabled"


# --- entry point --------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("plan", "apply", "disable"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="absolute 0700 directory outside the checkout")
    args = parser.parse_args()

    if os.environ.get("CERTIFY_ENVIRONMENT", "") != desired_state.ENVIRONMENT:
        raise ReconciliationError("CERTIFY_ENVIRONMENT must be 'staging'")
    if os.environ.get("CERTIFY_CAMPAIGN_ID", "") != desired_state.CAMPAIGN:
        raise ReconciliationError("CERTIFY_CAMPAIGN_ID must be 'TEST_SYN'")
    output_dir = validate_output_dir(args.output_dir)
    contract, scopes, clients = load_desired()
    ingress = set(contract["ingressScopes"])

    base_url = os.environ.get("KC_BASE_URL", "").rstrip("/")
    public_url = os.environ.get("KC_PUBLIC_URL", "").rstrip("/")
    target_realm = os.environ.get("KC_TARGET_REALM", "")
    admin_realm = os.environ.get("KC_ADMIN_REALM", "")
    admin_client_id = os.environ.get("KC_ADMIN_CLIENT_ID", "")
    admin_secret_file = os.environ.get("KC_ADMIN_CLIENT_SECRET_FILE", "")
    allow_loopback = os.environ.get("KC_ALLOW_LOOPBACK_ADMIN", "false").strip().lower() == "true"
    validate_runtime_urls(base_url, public_url, target_realm, allow_loopback_admin=allow_loopback)
    if public_url != contract["issuer"].rsplit("/realms/", 1)[0]:
        raise ReconciliationError("KC_PUBLIC_URL must be the staging issuer host from the certification contract")
    if not admin_realm or not admin_client_id or not admin_secret_file:
        raise ReconciliationError("protected Keycloak administrator inputs are incomplete")
    admin_path = Path(admin_secret_file)
    if not admin_path.is_absolute() or admin_path.is_symlink() or not admin_path.is_file():
        raise ReconciliationError("KC_ADMIN_CLIENT_SECRET_FILE must be an absolute regular file")
    admin_secret = admin_path.read_text(encoding="utf-8").strip()
    if not admin_secret:
        raise ReconciliationError("KC_ADMIN_CLIENT_SECRET_FILE is empty")

    bearer = admin_token(base_url, admin_realm, admin_client_id, admin_secret)
    del admin_secret
    assert_no_realm_wide_ingress_grant(base_url, target_realm, bearer, ingress)

    plan: dict[str, Any] = {
        "schema_version": "1.0",
        "environment": desired_state.ENVIRONMENT,
        "campaign": desired_state.CAMPAIGN,
        "realm": target_realm,
        "issuer": contract["issuer"],
        "edge_contract_sha256": contract["edgeContract"]["sha256"],
        "client_scope_actions": {},
        "client_actions": {},
        "other_clients_modified": False,
        "token_values_recorded": False,
        "secret_values_recorded": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    for name, scope in scopes.items():
        plan["client_scope_actions"][name] = scope_plan_action(base_url, target_realm, bearer, scope)[0]
    for client_id, desired in clients.items():
        current = find_client(base_url, target_realm, bearer, client_id)
        before = managed_projection(current, desired, CLIENT_MANAGED_KEYS) if current else None
        desired_projection = managed_projection(desired, desired, CLIENT_MANAGED_KEYS)
        plan["client_actions"][client_id] = {
            "action": "create" if current is None else ("none" if before == desired_projection else "update"),
            "current_managed_sha256": canonical_hash(before) if before is not None else None,
            "desired_managed_sha256": canonical_hash(desired_projection),
        }
    private_write(output_dir / "edge-certification-plan.json", json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n")
    if args.mode == "plan":
        print("EDGE_CERTIFICATION_PLAN=PASS")
        print(f"EDGE_CERTIFICATION_PLAN_FILE={output_dir / 'edge-certification-plan.json'}")
        return 0

    if args.mode == "disable":
        results = {client_id: disable_client(base_url, target_realm, bearer, client_id) for client_id in clients}
        private_write(
            output_dir / "edge-certification-disable.json",
            json.dumps({"results": results, "disabled_at": datetime.now(timezone.utc).isoformat()}, sort_keys=True) + "\n",
        )
        print("EDGE_CERTIFICATION_DISABLE=PASS")
        for client_id, result in results.items():
            print(f"CLIENT={client_id}|{result}")
        return 0

    scope_ids: dict[str, str] = {}
    scope_results: dict[str, str] = {}
    for name, scope in scopes.items():
        scope_id, result = apply_client_scope(base_url, target_realm, bearer, scope)
        scope_ids[name] = scope_id
        scope_results[name] = result
        readback = get_client_scope(base_url, target_realm, scope_id, bearer)
        if managed_projection(readback, scope, CLIENT_SCOPE_MANAGED_KEYS) != managed_projection(scope, scope, CLIENT_SCOPE_MANAGED_KEYS):
            raise ReconciliationError(f"client-scope readback differs from desired source: {name}")
    basic = find_scope(base_url, target_realm, bearer, "basic")
    if basic is None or not basic.get("id"):
        raise ReconciliationError("the built-in 'basic' client scope is missing from the staging realm")
    scope_ids["basic"] = str(basic["id"])

    client_results: dict[str, dict[str, Any]] = {}
    for client_id, desired in clients.items():
        internal_id, result = apply_client(base_url, target_realm, bearer, desired)
        links = reconcile_default_scope_links(
            base_url, target_realm, internal_id, bearer, list(desired["defaultClientScopes"]), scope_ids
        )
        readback = find_client(base_url, target_realm, bearer, client_id)
        if readback is None or managed_projection(readback, desired, CLIENT_MANAGED_KEYS) != managed_projection(desired, desired, CLIENT_MANAGED_KEYS):
            raise ReconciliationError(f"client readback differs from desired source: {client_id}")
        secret = client_secret(base_url, target_realm, internal_id, bearer)
        private_write(output_dir / f"{client_id}.secret", secret + "\n")
        del secret
        client_results[client_id] = {
            "result": result,
            "default_scope_links": links,
            "secret_file": str(output_dir / f"{client_id}.secret"),
            "runner_variable": f"CERTIFY_CLIENT_SECRET_FILE_{next(i['role'] for i in contract['identities'] if i['clientId'] == client_id).upper()}",
        }
    assert_no_realm_wide_ingress_grant(base_url, target_realm, bearer, ingress)

    evidence = {
        "schema_version": "1.0",
        "environment": desired_state.ENVIRONMENT,
        "campaign": desired_state.CAMPAIGN,
        "realm": target_realm,
        "issuer": contract["issuer"],
        "edge_contract_sha256": contract["edgeContract"]["sha256"],
        "client_scopes": scope_results,
        "clients": client_results,
        "realm_wide_ingress_grant": False,
        "other_clients_modified": False,
        "token_values_recorded": False,
        "secret_values_recorded": False,
        "applied_at": datetime.now(timezone.utc).isoformat(),
    }
    private_write(output_dir / "edge-certification-apply.json", json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("EDGE_CERTIFICATION_APPLY=PASS")
    for name, result in scope_results.items():
        print(f"CLIENT_SCOPE={name}|{result}")
    for client_id, entry in client_results.items():
        print(f"CLIENT={client_id}|{entry['result']}|{entry['runner_variable']}={entry['secret_file']}")
    print("SECRET_VALUES_RECORDED=false")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReconciliationError as exc:
        print(f"EDGE_CERTIFICATION_RECONCILE=FAIL\nERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
