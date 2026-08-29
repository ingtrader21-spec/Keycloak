from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
from typing import Any

from .api import Environment, KeycloakAdmin
from .common import (SHA40, SHA256, SAFE_ID, SAFE_TICKET, assert_no_sensitive_fields, canonical_bytes, canonical_hash, ensure_regular, fail, load_json, resource_actions, reviewed_action, write_json)
from .state import build_plan

def cmd_plan(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute() or output_dir.is_symlink():
        fail("--output-dir must be an absolute non-symlink path")
    if not SHA40.fullmatch(args.expected_deploy_sha):
        fail("expected deployment SHA must be 40 lowercase hexadecimal characters")
    admin = KeycloakAdmin(Environment.from_os())
    plan = build_plan(admin, args.expected_deploy_sha)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o700)
    plan_path = output_dir / "plan.json"
    canonical_path = output_dir / "plan.canonical.json"
    hash_path = output_dir / "plan.sha256"
    write_json(plan_path, plan)
    canonical = canonical_bytes(plan)
    canonical_path.write_bytes(canonical)
    canonical_path.chmod(0o600)
    digest = hashlib.sha256(canonical).hexdigest()
    hash_path.write_text(f"{digest}  plan.canonical.json\n", encoding="utf-8")
    hash_path.chmod(0o600)
    print(f"PLAN_FILE={plan_path}")
    print(f"PLAN_CANONICAL_FILE={canonical_path}")
    print(f"PLAN_SHA256={digest}")
    print(f"RESOURCE_COUNT={plan['resourceCount']}")
    print(f"DRIFT_COUNT={plan['driftCount']}")
    print(f"BLOCKED_COUNT={plan['blockedCount']}")
    print(f"CREATE_COUNT={plan['createCount']}")
    print(f"UPDATE_COUNT={plan['updateCount']}")
    print("PLAN=READY_FOR_REVIEW")


def load_and_verify_plan(path: Path, expected_sha: str, expected_deploy_sha: str, environment: str) -> dict[str, Any]:
    ensure_regular(path)
    plan = load_json(path)
    if not isinstance(plan, dict) or plan.get("schemaVersion") != 2:
        fail("unsupported plan schema")
    if canonical_hash(plan) != expected_sha:
        fail("plan hash mismatch")
    if plan.get("repositorySha") != expected_deploy_sha or plan.get("environment") != environment or plan.get("targetRealm") != "codestra":
        fail("plan identity does not match the selected deployment")
    resources = resource_actions(plan)
    if not resources or plan.get("resourceCount") != len(resources):
        fail("plan resource counters are invalid")
    blocked = sum(item.get("action") == "blocked_missing" for item in resources)
    creates = sum(item.get("action") == "create" for item in resources)
    updates = sum(item.get("action") == "update" for item in resources)
    drift = sum(item.get("action") != "noop" for item in resources)
    if (plan.get("blockedCount"), plan.get("createCount"), plan.get("updateCount"), plan.get("driftCount")) != (blocked, creates, updates, drift):
        fail("plan counters are inconsistent")
    if blocked:
        fail("plan contains blocked resources")
    assert_no_sensitive_fields(plan, "plan")
    return plan


def cmd_review(args: argparse.Namespace) -> None:
    plan_path = Path(args.plan)
    output = Path(args.output)
    if not output.is_absolute() or output.is_symlink():
        fail("--output must be an absolute non-symlink path")
    if not SHA256.fullmatch(args.expected_plan_sha) or not SHA40.fullmatch(args.expected_deploy_sha):
        fail("invalid plan hash or deployment SHA")
    environment = os.environ.get("DEPLOY_ENVIRONMENT", "")
    if environment not in {"staging", "production"}:
        fail("DEPLOY_ENVIRONMENT must be staging or production")
    reviewer = os.environ.get("KEYCLOAK_REVIEWER_ID", "")
    author = os.environ.get("KEYCLOAK_CHANGE_AUTHOR_ID", "")
    ticket = os.environ.get("KEYCLOAK_CHANGE_TICKET", "")
    if not SAFE_ID.fullmatch(reviewer) or not SAFE_ID.fullmatch(author) or reviewer == author:
        fail("independent reviewer and change author IDs are required")
    if not SAFE_TICKET.fullmatch(ticket):
        fail("KEYCLOAK_CHANGE_TICKET is required")
    plan = load_and_verify_plan(plan_path, args.expected_plan_sha, args.expected_deploy_sha, environment)
    review = {
        "schemaVersion": 2,
        "decision": "approved",
        "planSha256": args.expected_plan_sha,
        "repositorySha": args.expected_deploy_sha,
        "environment": environment,
        "targetRealm": "codestra",
        "reviewerId": reviewer,
        "changeAuthorId": author,
        "changeTicket": ticket,
        "reviewedActions": [reviewed_action(item) for item in resource_actions(plan)],
    }
    write_json(output, review, compact=True)
    digest = canonical_hash(review)
    hash_path = Path(str(output) + ".sha256")
    hash_path.write_text(f"{digest}  {output.name}\n", encoding="utf-8")
    hash_path.chmod(0o600)
    print(f"REVIEW_FILE={output}")
    print(f"REVIEW_SHA256={digest}")
    print(f"PLAN_SHA256={args.expected_plan_sha}")
    print("DRIFT_REVIEW=APPROVED")


def verify_review(path: Path, expected_hash: str, plan: dict[str, Any], expected_plan_hash: str, expected_deploy_sha: str, environment: str) -> dict[str, Any]:
    ensure_regular(path)
    review = load_json(path)
    if not isinstance(review, dict) or review.get("schemaVersion") != 2:
        fail("unsupported review schema")
    if canonical_hash(review) != expected_hash:
        fail("review hash mismatch")
    expected_actions = [reviewed_action(item) for item in resource_actions(plan)]
    if not (
        review.get("decision") == "approved"
        and review.get("planSha256") == expected_plan_hash
        and review.get("repositorySha") == expected_deploy_sha
        and review.get("environment") == environment
        and review.get("targetRealm") == "codestra"
        and isinstance(review.get("reviewerId"), str)
        and review.get("reviewerId") != review.get("changeAuthorId")
        and review.get("reviewedActions") == expected_actions
    ):
        fail("independent review evidence is invalid")
    assert_no_sensitive_fields(review, "review")
    return review
