from __future__ import annotations

from typing import Any

from observability_identity_policy import PolicyError as ObservabilityPolicyError, validate_source as validate_observability_source

from .api import KeycloakAdmin
from .common import (
    CLIENT_DIR, CLIENT_POLICY, CONFIG, CREATABLE_CLIENT_POLICY,
    CREATABLE_ROLE_POLICY, ENDPOINTS, ROLE_DIR, ROLE_POLICY,
    assert_no_sensitive_fields, canonical_hash, fail, load_desired,
    load_json, load_policy, normalize, project,
)

def desired_state() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str], list[str], list[str], list[str]]:
    try:
        validate_observability_source(CONFIG)
    except ObservabilityPolicyError as exc:
        fail(f"observability identity policy failed: {exc}")
    clients = load_desired(CLIENT_DIR, "clientId")
    roles = load_desired(ROLE_DIR, "name")
    managed_clients = load_policy(CLIENT_POLICY, "clients")
    creatable_clients = load_policy(CREATABLE_CLIENT_POLICY, "clients")
    managed_roles = load_policy(ROLE_POLICY, "roles")
    creatable_roles = load_policy(CREATABLE_ROLE_POLICY, "roles")
    if set(managed_clients) != set(clients):
        fail("managed client policy must exactly match client desired-state files")
    if not set(creatable_clients).issubset(managed_clients):
        fail("creatable client policy must be a subset of managed clients")
    if set(managed_roles) != set(roles):
        fail("managed realm-role policy must exactly match role desired-state files")
    if not set(creatable_roles).issubset(managed_roles):
        fail("creatable realm-role policy must be a subset of managed roles")
    return clients, roles, managed_clients, creatable_clients, managed_roles, creatable_roles


def rollback_for(resource_type: str, *, existing: bool, creatable: bool) -> tuple[str, dict[str, Any]]:
    if existing:
        return "noop", {
            "kind": "restore_allowlisted_overlay",
            "preApplyState": "existing",
            "requiresReviewedPlan": True,
        }
    if not creatable:
        return "blocked_missing", {
            "kind": "blocked_missing",
            "preApplyState": "absent",
            "requiresReviewedPlan": True,
        }
    if resource_type == "client":
        return "create", {
            "kind": "disable_then_reviewed_delete",
            "preApplyState": "absent",
            "disableFirst": True,
            "deleteRequiresSeparateReviewedRollback": True,
            "requiresReviewedPlan": True,
        }
    return "create", {
        "kind": "remove_assignments_then_reviewed_delete",
        "preApplyState": "absent",
        "removeAssignmentsFirst": True,
        "deleteRequiresSeparateReviewedRollback": True,
        "requiresReviewedPlan": True,
    }


def build_plan(admin: KeycloakAdmin, repository_sha: str) -> dict[str, Any]:
    clients, roles, managed_clients, creatable_clients, managed_roles, creatable_roles = desired_state()
    client_resources: list[dict[str, Any]] = []
    role_resources: list[dict[str, Any]] = []
    for client_id in sorted(managed_clients):
        desired = normalize(clients[client_id], "client")
        live = admin.get_client(client_id)
        base_action, rollback = rollback_for("client", existing=live is not None, creatable=client_id in creatable_clients)
        before: dict[str, Any] = {}
        action = base_action
        if live is not None:
            before = normalize(project(live, desired), "client")
            action = "noop" if before == desired else "update"
        resource = {
            "resourceType": "client",
            "resourceId": client_id,
            "clientId": client_id,
            "action": action,
            "beforeSha256": canonical_hash(before),
            "desiredSha256": canonical_hash(desired),
            "before": before,
            "desired": desired,
            "rollback": rollback,
        }
        assert_no_sensitive_fields(resource, f"client plan {client_id}")
        client_resources.append(resource)

    for role_name in sorted(managed_roles):
        desired = normalize(roles[role_name], "realmRole")
        live = admin.get_role(role_name)
        base_action, rollback = rollback_for("realmRole", existing=live is not None, creatable=role_name in creatable_roles)
        before: dict[str, Any] = {}
        action = base_action
        if live is not None:
            before = normalize(project(live, desired), "realmRole")
            action = "noop" if before == desired else "update"
        resource = {
            "resourceType": "realmRole",
            "resourceId": role_name,
            "roleName": role_name,
            "action": action,
            "beforeSha256": canonical_hash(before),
            "desiredSha256": canonical_hash(desired),
            "before": before,
            "desired": desired,
            "rollback": rollback,
        }
        assert_no_sensitive_fields(resource, f"role plan {role_name}")
        role_resources.append(resource)

    resources = [*client_resources, *role_resources]
    plan = {
        "schemaVersion": 2,
        "repositorySha": repository_sha,
        "environment": admin.env.deployment_environment,
        "targetRealm": admin.env.target_realm,
        "api": load_json(ENDPOINTS),
        "clients": client_resources,
        "realmRoles": role_resources,
        "resourceCount": len(resources),
        "clientCount": len(client_resources),
        "realmRoleCount": len(role_resources),
        "driftCount": sum(item["action"] != "noop" for item in resources),
        "blockedCount": sum(item["action"] == "blocked_missing" for item in resources),
        "createCount": sum(item["action"] == "create" for item in resources),
        "updateCount": sum(item["action"] == "update" for item in resources),
        "clientCreateCount": sum(item["action"] == "create" for item in client_resources),
        "realmRoleCreateCount": sum(item["action"] == "create" for item in role_resources),
    }
    assert_no_sensitive_fields(plan, "plan")
    return plan
