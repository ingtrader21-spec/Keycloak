#!/usr/bin/env python3
"""Narrow staging-only reconciliation of the OpenBao workload-identity desired state.

Manages exactly: the ``openbao.workload`` optional client scope (with the
``codestra_environment`` claim rendered to ``staging``), the new monitoring-plane
confidential clients declared in
``config/desired-state/openbao-workload-identity/contract.json``, and the
optional-scope link on the already managed clients that OpenBao admits.

It refuses every Keycloak endpoint except the canonical staging instance (or
an explicitly allowed loopback administrative endpoint), never removes another
optional scope from a managed client, verifies that the scope is not a realm
default, verifies that no browser client or ``monitoring-readonly`` carries the
scope after reconciliation, and writes new client secrets only to 0600 files
outside the Git checkout. Secrets and tokens are never printed.

Modes:
  plan      read live state and write a plan; no mutation.
  apply     create or update the scope, the new clients and the links; read back; export secrets.
  disable   set enabled=false on every new client and unlink the scope from every bound client.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DESIRED_ROOT = ROOT / "config" / "desired-state" / "openbao-workload-identity"

sys.path.insert(0, str(ROOT / "scripts"))
_spec = importlib.util.spec_from_file_location(
    "monitoring_reconcile", ROOT / "scripts" / "reconcile_monitoring_readonly_staging.py"
)
assert _spec and _spec.loader
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
_edge_spec = importlib.util.spec_from_file_location(
    "edge_reconcile", ROOT / "scripts" / "reconcile_edge_certification_staging.py"
)
assert _edge_spec and _edge_spec.loader
_edge = importlib.util.module_from_spec(_edge_spec)
_edge_spec.loader.exec_module(_edge)
# One transport for both helper modules so a single patch point (and one live session) covers every call.
_edge._base = _base
import openbao_workload_identity_desired_state as desired_state  # noqa: E402

ReconciliationError = _base.ReconciliationError
CLIENT_MANAGED_KEYS = _base.CLIENT_MANAGED_KEYS
CLIENT_SCOPE_MANAGED_KEYS = _base.CLIENT_SCOPE_MANAGED_KEYS
ENVIRONMENT = "staging"


def http_request(*args: Any, **kwargs: Any):
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
find_client = _edge.find_client
realm_default_scope_names = _edge.realm_default_scope_names
apply_client = _edge.apply_client
disable_client = _edge.disable_client


def realm_path(base_url: str, realm: str, suffix: str) -> str:
    return f"{base_url}/admin/realms/{urllib.parse.quote(realm)}{suffix}"


def render_scope(scope: dict[str, Any], environment: str) -> dict[str, Any]:
    """Replace the environment placeholder with the exact target environment."""
    rendered = copy.deepcopy(scope)
    for mapper in rendered.get("protocolMappers", []):
        config = mapper.get("config", {})
        if config.get("claim.name") == desired_state.CLAIM:
            if config.get("claim.value") != desired_state.PLACEHOLDER:
                raise ReconciliationError("environment claim mapper does not carry the placeholder")
            config["claim.value"] = environment
    return rendered


def load_desired() -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    try:
        contract, _, documents = desired_state.validate()
    except desired_state.DesiredStateError as exc:
        raise ReconciliationError(f"desired state is invalid: {exc}") from exc
    scope = next(value for path, value in documents if path == desired_state.SCOPE_PATH)
    clients = {value["clientId"]: value for path, value in documents if path.parent == desired_state.CLIENT_DIR}
    return contract, render_scope(scope, ENVIRONMENT), clients


def optional_links(base_url: str, realm: str, internal_id: str, bearer: str) -> dict[str, str]:
    _, _, body = http_request(
        "GET",
        realm_path(base_url, realm, f"/clients/{urllib.parse.quote(internal_id)}/optional-client-scopes"),
        bearer=bearer,
    )
    value = json_response(body, "optional client-scope links")
    if not isinstance(value, list):
        raise ReconciliationError("optional client-scope links are not a list")
    return {str(item.get("name")): str(item.get("id") or "") for item in value if isinstance(item, dict)}


def ensure_optional_link(base_url: str, realm: str, internal_id: str, bearer: str, scope_id: str) -> str:
    """Add the openbao.workload optional link; never remove another optional scope."""
    current = optional_links(base_url, realm, internal_id, bearer)
    if current.get(desired_state.SCOPE_NAME) == scope_id:
        return "unchanged"
    http_request(
        "PUT",
        realm_path(base_url, realm, f"/clients/{urllib.parse.quote(internal_id)}/optional-client-scopes/{urllib.parse.quote(scope_id)}"),
        bearer=bearer,
        expected={204},
    )
    readback = optional_links(base_url, realm, internal_id, bearer)
    if readback.get(desired_state.SCOPE_NAME) != scope_id:
        raise ReconciliationError("optional client-scope link did not read back")
    return "linked"


def remove_optional_link(base_url: str, realm: str, internal_id: str, bearer: str) -> str:
    current = optional_links(base_url, realm, internal_id, bearer)
    scope_id = current.get(desired_state.SCOPE_NAME)
    if not scope_id:
        return "absent"
    http_request(
        "DELETE",
        realm_path(base_url, realm, f"/clients/{urllib.parse.quote(internal_id)}/optional-client-scopes/{urllib.parse.quote(scope_id)}"),
        bearer=bearer,
        expected={204},
    )
    if desired_state.SCOPE_NAME in optional_links(base_url, realm, internal_id, bearer):
        raise ReconciliationError("optional client-scope link was not removed")
    return "unlinked"


def assert_scope_boundary(base_url: str, realm: str, bearer: str, contract: dict[str, Any]) -> None:
    if desired_state.SCOPE_NAME in realm_default_scope_names(base_url, realm, bearer):
        raise ReconciliationError(f"{desired_state.SCOPE_NAME} is a realm default client scope")
    for never in contract["neverBound"]:
        client = find_client(base_url, realm, bearer, never["clientId"])
        if client is None:
            continue
        links = optional_links(base_url, realm, str(client["id"]), bearer)
        if desired_state.SCOPE_NAME in links:
            raise ReconciliationError(f"never-bound client carries {desired_state.SCOPE_NAME}: {never['clientId']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("plan", "apply", "disable"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="absolute 0700 directory outside the checkout")
    args = parser.parse_args()

    if os.environ.get("CERTIFY_ENVIRONMENT", "") != ENVIRONMENT:
        raise ReconciliationError("CERTIFY_ENVIRONMENT must be 'staging'")
    output_dir = validate_output_dir(args.output_dir)
    contract, scope, clients = load_desired()
    if ENVIRONMENT not in contract["reconcilerEnvironments"]:
        raise ReconciliationError("staging is not an authorized reconciler environment")

    base_url = os.environ.get("KC_BASE_URL", "").rstrip("/")
    public_url = os.environ.get("KC_PUBLIC_URL", "").rstrip("/")
    target_realm = os.environ.get("KC_TARGET_REALM", "")
    admin_realm = os.environ.get("KC_ADMIN_REALM", "")
    admin_client_id = os.environ.get("KC_ADMIN_CLIENT_ID", "")
    admin_secret_file = os.environ.get("KC_ADMIN_CLIENT_SECRET_FILE", "")
    allow_loopback = os.environ.get("KC_ALLOW_LOOPBACK_ADMIN", "false").strip().lower() == "true"
    validate_runtime_urls(base_url, public_url, target_realm, allow_loopback_admin=allow_loopback)
    if public_url != contract["issuers"][ENVIRONMENT].rsplit("/realms/", 1)[0]:
        raise ReconciliationError("KC_PUBLIC_URL must be the staging issuer host from the contract")
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

    bound_existing = [entry["clientId"] for entry in contract["existingClientBindings"]]
    plan: dict[str, Any] = {
        "schema_version": "1.0",
        "environment": ENVIRONMENT,
        "realm": target_realm,
        "issuer": contract["issuers"][ENVIRONMENT],
        "openbao_authority_sha256": contract["openbaoAuthority"]["sha256"],
        "client_scope_action": scope_plan_action(base_url, target_realm, bearer, scope)[0],
        "client_actions": {},
        "existing_client_links": {},
        "other_clients_modified": False,
        "token_values_recorded": False,
        "secret_values_recorded": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    for client_id, desired in clients.items():
        current = find_client(base_url, target_realm, bearer, client_id)
        before = managed_projection(current, desired, CLIENT_MANAGED_KEYS) if current else None
        desired_projection = managed_projection(desired, desired, CLIENT_MANAGED_KEYS)
        plan["client_actions"][client_id] = {
            "action": "create" if current is None else ("none" if before == desired_projection else "update"),
            "current_managed_sha256": canonical_hash(before) if before is not None else None,
            "desired_managed_sha256": canonical_hash(desired_projection),
        }
    for client_id in bound_existing:
        current = find_client(base_url, target_realm, bearer, client_id)
        if current is None:
            plan["existing_client_links"][client_id] = "client-missing"
            continue
        links = optional_links(base_url, target_realm, str(current["id"]), bearer)
        plan["existing_client_links"][client_id] = "none" if desired_state.SCOPE_NAME in links else "link"
    private_write(output_dir / "openbao-workload-identity-plan.json", json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n")
    if args.mode == "plan":
        print("OPENBAO_WORKLOAD_IDENTITY_PLAN=PASS")
        print(f"OPENBAO_WORKLOAD_IDENTITY_PLAN_FILE={output_dir / 'openbao-workload-identity-plan.json'}")
        return 0

    if args.mode == "disable":
        results: dict[str, str] = {}
        for client_id in clients:
            results[client_id] = disable_client(base_url, target_realm, bearer, client_id)
        for client_id in list(clients) + bound_existing:
            current = find_client(base_url, target_realm, bearer, client_id)
            if current is not None:
                results[f"{client_id}:scope"] = remove_optional_link(base_url, target_realm, str(current["id"]), bearer)
        private_write(
            output_dir / "openbao-workload-identity-disable.json",
            json.dumps({"results": results, "disabled_at": datetime.now(timezone.utc).isoformat()}, sort_keys=True) + "\n",
        )
        print("OPENBAO_WORKLOAD_IDENTITY_DISABLE=PASS")
        for key, result in results.items():
            print(f"CLIENT={key}|{result}")
        return 0

    scope_id, scope_result = apply_client_scope(base_url, target_realm, bearer, scope)
    readback = get_client_scope(base_url, target_realm, scope_id, bearer)
    if managed_projection(readback, scope, CLIENT_SCOPE_MANAGED_KEYS) != managed_projection(scope, scope, CLIENT_SCOPE_MANAGED_KEYS):
        raise ReconciliationError("client-scope readback differs from the rendered desired scope")
    rendered_claim = next(
        m["config"]["claim.value"] for m in readback.get("protocolMappers", []) if m.get("config", {}).get("claim.name") == desired_state.CLAIM
    )
    if rendered_claim != ENVIRONMENT:
        raise ReconciliationError("environment claim did not read back as staging")

    client_results: dict[str, dict[str, Any]] = {}
    for client_id, desired in clients.items():
        internal_id, result = apply_client(base_url, target_realm, bearer, desired)
        link = ensure_optional_link(base_url, target_realm, internal_id, bearer, scope_id)
        readback_client = find_client(base_url, target_realm, bearer, client_id)
        if readback_client is None or managed_projection(readback_client, desired, CLIENT_MANAGED_KEYS) != managed_projection(desired, desired, CLIENT_MANAGED_KEYS):
            raise ReconciliationError(f"client readback differs from desired source: {client_id}")
        secret = client_secret(base_url, target_realm, internal_id, bearer)
        private_write(output_dir / f"{client_id}.secret", secret + "\n")
        del secret
        client_results[client_id] = {"result": result, "scope_link": link, "secret_file": str(output_dir / f"{client_id}.secret")}
    existing_results: dict[str, str] = {}
    for client_id in bound_existing:
        current = find_client(base_url, target_realm, bearer, client_id)
        if current is None:
            raise ReconciliationError(f"managed client to bind is missing in staging: {client_id}")
        existing_results[client_id] = ensure_optional_link(base_url, target_realm, str(current["id"]), bearer, scope_id)
    assert_scope_boundary(base_url, target_realm, bearer, contract)

    evidence = {
        "schema_version": "1.0",
        "environment": ENVIRONMENT,
        "realm": target_realm,
        "issuer": contract["issuers"][ENVIRONMENT],
        "openbao_authority_sha256": contract["openbaoAuthority"]["sha256"],
        "client_scope": scope_result,
        "environment_claim_rendered": ENVIRONMENT,
        "clients": client_results,
        "existing_client_links": existing_results,
        "realm_default_scope": False,
        "never_bound_clients_clean": True,
        "other_clients_modified": False,
        "token_values_recorded": False,
        "secret_values_recorded": False,
        "applied_at": datetime.now(timezone.utc).isoformat(),
    }
    private_write(output_dir / "openbao-workload-identity-apply.json", json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("OPENBAO_WORKLOAD_IDENTITY_APPLY=PASS")
    print(f"CLIENT_SCOPE={desired_state.SCOPE_NAME}|{scope_result}")
    for client_id, entry in client_results.items():
        print(f"CLIENT={client_id}|{entry['result']}|scope={entry['scope_link']}|secret_file={entry['secret_file']}")
    for client_id, result in existing_results.items():
        print(f"EXISTING_CLIENT={client_id}|scope={result}")
    print("SECRET_VALUES_RECORDED=false")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReconciliationError as exc:
        print(f"OPENBAO_WORKLOAD_IDENTITY_RECONCILE=FAIL\nERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
