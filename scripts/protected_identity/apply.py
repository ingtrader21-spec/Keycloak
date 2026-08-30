from __future__ import annotations

import argparse
import urllib.parse
from pathlib import Path
from typing import Any

from .api import Environment, KeycloakAdmin
from .common import SHA40, SHA256, canonical_hash, fail, merge_overlay, normalize, project, resource_actions, sanitize
from .plan_review import load_and_verify_plan, verify_review
from .state import build_plan, desired_state

def assert_rollback(resource: dict[str, Any]) -> None:
    rollback = resource.get("rollback")
    if not isinstance(rollback, dict) or rollback.get("requiresReviewedPlan") is not True:
        fail(f"invalid rollback metadata for {resource.get('resourceId')}")
    action = resource.get("action")
    resource_type = resource.get("resourceType")
    if action in {"noop", "update"}:
        if rollback.get("kind") != "restore_allowlisted_overlay" or rollback.get("preApplyState") != "existing":
            fail(f"existing-resource rollback metadata is invalid for {resource.get('resourceId')}")
    elif action == "create" and resource_type == "client":
        if not (rollback.get("kind") == "disable_then_reviewed_delete" and rollback.get("disableFirst") is True and rollback.get("deleteRequiresSeparateReviewedRollback") is True):
            fail(f"created-client rollback metadata is invalid for {resource.get('resourceId')}")
    elif action == "create" and resource_type == "realmRole":
        if not (rollback.get("kind") == "remove_assignments_then_reviewed_delete" and rollback.get("removeAssignmentsFirst") is True and rollback.get("deleteRequiresSeparateReviewedRollback") is True):
            fail(f"created-role rollback metadata is invalid for {resource.get('resourceId')}")


def cmd_apply(args: argparse.Namespace) -> None:
    if not SHA256.fullmatch(args.expected_plan_sha) or not SHA256.fullmatch(args.expected_review_sha) or not SHA40.fullmatch(args.expected_deploy_sha):
        fail("invalid apply hashes")
    env = Environment.from_os()
    plan = load_and_verify_plan(Path(args.plan), args.expected_plan_sha, args.expected_deploy_sha, env.deployment_environment)
    verify_review(Path(args.review), args.expected_review_sha, plan, args.expected_plan_sha, args.expected_deploy_sha, env.deployment_environment)
    clients, roles, managed_clients, creatable_clients, managed_roles, creatable_roles = desired_state()
    plan_clients = {item["clientId"] for item in plan["clients"]}
    plan_roles = {item["roleName"] for item in plan["realmRoles"]}
    if plan_clients != set(managed_clients) or plan_roles != set(managed_roles):
        fail("plan resource sets do not match protected policies")
    admin = KeycloakAdmin(env)
    operations: list[dict[str, Any]] = []
    for resource in resource_actions(plan):
        assert_rollback(resource)
        resource_type = resource["resourceType"]
        resource_id = resource["resourceId"]
        desired_map = clients if resource_type == "client" else roles
        desired = normalize(desired_map[resource_id], resource_type)
        if canonical_hash(desired) != resource["desiredSha256"]:
            fail(f"desired state changed after review for {resource_type}:{resource_id}")
        live = admin.get_client(resource_id) if resource_type == "client" else admin.get_role(resource_id)
        action = resource["action"]
        creatable = resource_id in (creatable_clients if resource_type == "client" else creatable_roles)
        if action == "create":
            if not creatable or live is not None or resource["before"] != {} or resource["beforeSha256"] != canonical_hash({}):
                fail(f"create precondition failed for {resource_type}:{resource_id}")
        else:
            if live is None:
                fail(f"expected existing resource is absent: {resource_type}:{resource_id}")
            before = normalize(project(live, desired), resource_type)
            if canonical_hash(before) != resource["beforeSha256"]:
                fail(f"live state changed after review for {resource_type}:{resource_id}")
            if action == "noop" and before != desired:
                fail(f"noop resource drifted: {resource_type}:{resource_id}")
            if action == "update" and before == desired:
                fail(f"update resource already converged: {resource_type}:{resource_id}")
        operations.append({"resourceType": resource_type, "resourceId": resource_id, "action": action, "desired": desired, "live": live})

    for operation in operations:
        if operation["action"] != "create":
            continue
        current = admin.get_client(operation["resourceId"]) if operation["resourceType"] == "client" else admin.get_role(operation["resourceId"])
        if current is not None:
            fail(f"pre-write absence recheck failed for {operation['resourceType']}:{operation['resourceId']}")

    order = {"realmRole": 0, "client": 1}
    created = 0
    updated = 0
    unchanged = 0
    for operation in sorted(operations, key=lambda item: (order[item["resourceType"]], item["resourceId"])):
        resource_type = operation["resourceType"]
        resource_id = operation["resourceId"]
        action = operation["action"]
        if action == "noop":
            unchanged += 1
            print(f"UNCHANGED={resource_type}:{resource_id}")
            continue
        if action == "create":
            if resource_type == "client":
                admin.request("POST", f"{admin.realm_path}/clients", operation["desired"])
            else:
                admin.request("POST", f"{admin.realm_path}/roles", operation["desired"])
            created += 1
            print(f"CREATED={resource_type}:{resource_id}")
            continue
        merged = sanitize(merge_overlay(operation["live"], operation["desired"]))
        if resource_type == "client":
            merged.pop("id", None)
            merged.pop("access", None)
            client_uuid = admin.get_client_uuid(resource_id)
            if client_uuid is None:
                fail(f"client disappeared before update: {resource_id}")
            admin.request("PUT", f"{admin.realm_path}/clients/{urllib.parse.quote(client_uuid, safe='')}", merged)
        else:
            merged.pop("id", None)
            merged.pop("containerId", None)
            admin.request("PUT", f"{admin.realm_path}/roles/{urllib.parse.quote(resource_id, safe='')}", merged)
        updated += 1
        print(f"UPDATED={resource_type}:{resource_id}")

    converged = build_plan(admin, args.expected_deploy_sha)
    if any(converged[key] != 0 for key in ("driftCount", "blockedCount", "createCount", "updateCount")):
        fail("applied configuration did not converge")
    print(f"EXPECTED_PLAN_SHA256={args.expected_plan_sha}")
    print(f"EXPECTED_REVIEW_SHA256={args.expected_review_sha}")
    print(f"CREATED_COUNT={created}")
    print(f"UPDATED_COUNT={updated}")
    print(f"UNCHANGED_COUNT={unchanged}")
    print("DRIFT_COUNT=0")
    print("BLOCKED_COUNT=0")
    print("RECONCILE=APPLIED_AND_VERIFIED")
