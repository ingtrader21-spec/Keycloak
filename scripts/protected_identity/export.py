from __future__ import annotations

import argparse
import copy
import urllib.parse
from pathlib import Path
from typing import Any

from .api import Environment, KeycloakAdmin
from .common import (EXPORT_ALLOWLIST_DIR, ROLE_EXPORT_ALLOWLIST_DIR, ROOT, SECRET_EXPORT_POLICY, assert_no_sensitive_fields, canonical_hash, ensure_regular, fail, load_json, load_policy, normalize, sanitize, write_json)
from .state import desired_state

def allowlisted_projection(value: dict[str, Any], allowlist: dict[str, Any], *, id_field: str) -> dict[str, Any]:
    top = allowlist.get("topLevelFields")
    attrs = allowlist.get("attributeFields")
    if not isinstance(top, list) or not isinstance(attrs, list):
        fail("invalid export allowlist")
    result = {field: copy.deepcopy(value[field]) for field in top if field in value}
    if "attributes" in result:
        source = result.get("attributes") if isinstance(result.get("attributes"), dict) else {}
        result["attributes"] = {field: copy.deepcopy(source[field]) for field in attrs if field in source}
    if id_field not in result:
        fail(f"export lost {id_field}")
    return sanitize(result)


def export_rollback(output: Path, requested_clients: list[str], include_roles: bool) -> dict[str, Any]:
    if not output.is_absolute() or output.is_symlink():
        fail("--output must be an absolute non-symlink path")
    env = Environment.from_os()
    admin = KeycloakAdmin(env)
    _clients, _roles, managed_clients, creatable_clients, managed_roles, creatable_roles = desired_state()
    requested = requested_clients or managed_clients
    if len(requested) != len(set(requested)) or not set(requested).issubset(managed_clients):
        fail("rollback export requested an unmanaged or duplicate client")
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    client_dir = output / "config" / "clients"
    role_dir = output / "config" / "realm-roles"
    client_dir.mkdir(parents=True, exist_ok=True)
    client_dir.chmod(0o700)
    if include_roles:
        role_dir.mkdir(parents=True, exist_ok=True)
        role_dir.chmod(0o700)
    client_metadata: list[dict[str, Any]] = []
    role_metadata: list[dict[str, Any]] = []
    for client_id in sorted(requested):
        live = admin.get_client(client_id)
        if live is None:
            if client_id not in creatable_clients:
                fail(f"missing non-creatable client cannot be exported: {client_id}")
            client_metadata.append({
                "clientId": client_id,
                "preApplyState": "absent",
                "evidenceKind": "reviewed-create-candidate",
                "rollback": {"strategy": "disable_then_reviewed_delete", "disablePatch": {"enabled": False}, "disableFirst": True, "deletionRequiresSeparateReviewedRollback": True, "requiresReviewedPlan": True},
            })
            continue
        allowlist = load_json(EXPORT_ALLOWLIST_DIR / f"{client_id}.json")
        if allowlist.get("clientId") != client_id:
            fail(f"client export allowlist mismatch for {client_id}")
        exported = allowlisted_projection(live, allowlist, id_field="clientId")
        destination = client_dir / f"{client_id}.json"
        write_json(destination, exported)
        client_metadata.append({
            "clientId": client_id,
            "preApplyState": "existing",
            "evidenceKind": "allowlisted-before-overlay",
            "beforeSha256": canonical_hash(normalize(exported, "client")),
            "rollback": {"strategy": "restore_allowlisted_overlay_via_reviewed_plan", "overlayPath": f"config/clients/{client_id}.json", "requiresReviewedPlan": True},
        })
    if include_roles:
        for role_name in sorted(managed_roles):
            live = admin.get_role(role_name)
            if live is None:
                if role_name not in creatable_roles:
                    fail(f"missing non-creatable role cannot be exported: {role_name}")
                role_metadata.append({
                    "roleName": role_name,
                    "preApplyState": "absent",
                    "evidenceKind": "reviewed-create-candidate",
                    "rollback": {"strategy": "remove_assignments_then_reviewed_delete", "removeAssignmentsFirst": True, "deletionRequiresSeparateReviewedRollback": True, "requiresReviewedPlan": True},
                })
                continue
            allowlist = load_json(ROLE_EXPORT_ALLOWLIST_DIR / f"{role_name}.json")
            if allowlist.get("roleName") != role_name:
                fail(f"role export allowlist mismatch for {role_name}")
            exported = allowlisted_projection(live, allowlist, id_field="name")
            destination = role_dir / f"{role_name}.json"
            write_json(destination, exported)
            role_metadata.append({
                "roleName": role_name,
                "preApplyState": "existing",
                "evidenceKind": "allowlisted-before-overlay",
                "beforeSha256": canonical_hash(normalize(exported, "realmRole")),
                "rollback": {"strategy": "restore_allowlisted_overlay_via_reviewed_plan", "overlayPath": f"config/realm-roles/{role_name}.json", "requiresReviewedPlan": True},
            })
    metadata = {
        "schemaVersion": 2,
        "targetRealm": env.target_realm,
        "clients": client_metadata,
        "realmRoles": role_metadata,
        "existingClientCount": sum(item["preApplyState"] == "existing" for item in client_metadata),
        "absentCreatableClientCount": sum(item["preApplyState"] == "absent" for item in client_metadata),
        "existingRealmRoleCount": sum(item["preApplyState"] == "existing" for item in role_metadata),
        "absentCreatableRealmRoleCount": sum(item["preApplyState"] == "absent" for item in role_metadata),
    }
    assert_no_sensitive_fields(metadata, "rollback metadata")
    write_json(output / "rollback-metadata.json", metadata)
    return metadata


def cmd_export_rollback(args: argparse.Namespace) -> None:
    metadata = export_rollback(Path(args.output), args.clients, args.include_managed_realm_roles)
    print(f"ROLLBACK_METADATA={Path(args.output) / 'rollback-metadata.json'}")
    print(f"EXISTING_CLIENT_ROLLBACKS={metadata['existingClientCount']}")
    print(f"CREATED_CLIENT_ROLLBACKS={metadata['absentCreatableClientCount']}")
    print(f"EXISTING_REALM_ROLE_ROLLBACKS={metadata['existingRealmRoleCount']}")
    print(f"CREATED_REALM_ROLE_ROLLBACKS={metadata['absentCreatableRealmRoleCount']}")
    print("ROLLBACK_EVIDENCE=READY")


def cmd_prepare_rollback(args: argparse.Namespace) -> None:
    plan_path = Path(args.plan)
    ensure_regular(plan_path)
    plan = load_json(plan_path)
    if not isinstance(plan, dict) or plan.get("schemaVersion") != 2 or plan.get("blockedCount") != 0:
        fail("reviewed plan is not rollback-evidence eligible")
    metadata = export_rollback(Path(args.output), [item["clientId"] for item in plan.get("clients", [])], True)
    metadata["repositorySha"] = plan.get("repositorySha")
    metadata["environment"] = plan.get("environment")
    metadata["planSha256"] = canonical_hash(plan)
    write_json(Path(args.output) / "rollback-metadata.json", metadata)
    print(f"ROLLBACK_EVIDENCE={args.output}")
    print(f"ROLLBACK_PLAN_SHA256={metadata['planSha256']}")
    print("ROLLBACK_EVIDENCE=READY")


def cmd_export_secrets(args: argparse.Namespace) -> None:
    output = Path(args.output_dir)
    if not output.is_absolute() or output.is_symlink():
        fail("--output-dir must be an absolute non-symlink path")
    try:
        output.resolve().relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        fail("client secrets must never be written inside the repository")
    allowed = load_policy(SECRET_EXPORT_POLICY, "clients")
    requested = args.clients or allowed
    if len(requested) != len(set(requested)) or not set(requested).issubset(allowed):
        fail("secret export requested a non-allowlisted client")
    admin = KeycloakAdmin(Environment.from_os())
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    manifest: list[dict[str, str]] = []
    for client_id in sorted(requested):
        client_uuid = admin.get_client_uuid(client_id)
        if client_uuid is None:
            fail(f"cannot export secret for absent client {client_id}")
        response = admin.request("GET", f"{admin.realm_path}/clients/{urllib.parse.quote(client_uuid, safe='')}/client-secret")
        if not isinstance(response, dict) or not isinstance(response.get("value"), str) or len(response["value"]) < 16:
            fail(f"Keycloak did not return a usable secret for {client_id}")
        destination = output / f"{client_id}.secret"
        if destination.is_symlink():
            fail(f"secret destination is a symlink: {destination}")
        destination.write_text(response["value"] + "\n", encoding="utf-8")
        destination.chmod(0o600)
        manifest.append({"clientId": client_id, "file": destination.name})
        print(f"SECRET_FILE_WRITTEN={destination}")
    write_json(output / "manifest.json", {"schemaVersion": 1, "clients": manifest})
    print(f"SECRET_EXPORT_COUNT={len(manifest)}")
    print("CLIENT_SECRET_HANDOFF=READY")
