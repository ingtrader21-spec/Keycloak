#!/usr/bin/env python3
"""Validate the protected password-reset staging acceptance workflow."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "password-reset-staging-e2e.yml"
SCRIPT = ROOT / "scripts" / "password-reset-e2e.py"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"


class ValidationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a mapping")
    return value


def sequence(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be a sequence")
    return value


def validate() -> None:
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    document = mapping(document, "workflow")

    triggers = mapping(document.get("on") or document.get(True), "workflow.on")
    if set(triggers) != {"workflow_dispatch"}:
        fail("password-reset acceptance must be workflow_dispatch-only")

    permissions = mapping(document.get("permissions"), "workflow.permissions")
    if permissions != {"contents": "read"}:
        fail("workflow permissions must be exactly contents: read")

    jobs = mapping(document.get("jobs"), "workflow.jobs")
    if set(jobs) != {"acceptance"}:
        fail("workflow must contain exactly one acceptance job")
    job = mapping(jobs["acceptance"], "acceptance job")

    condition = str(job.get("if", ""))
    if condition != "${{ false }}":
        fail("acceptance job must be unconditionally disabled")
    if "RUNTIME_MUTATION_DISABLED=true" not in WORKFLOW.read_text(encoding="utf-8"):
        fail("acceptance job is missing the runtime-mutation disable marker")

    runners = sequence(job.get("runs-on"), "acceptance.runs-on")
    if runners != ["self-hosted", "linux", "x64", "codestra-staging"]:
        fail("acceptance job must use the restricted codestra-staging runner")
    if job.get("environment") != "password-reset-staging":
        fail("acceptance job must use the password-reset-staging environment")
    timeout = job.get("timeout-minutes")
    if not isinstance(timeout, int) or not 5 <= timeout <= 30:
        fail("acceptance timeout must be between 5 and 30 minutes")

    environment = mapping(job.get("env"), "acceptance.env")
    required_environment = {
        "KEYCLOAK_ISSUER",
        "KEYCLOAK_CLIENT_ID",
        "KEYCLOAK_REDIRECT_URI",
        "EXPECTED_KEYCLOAK_SHA",
        "EXPECTED_KLYROW_SHA",
        "KEYCLOAK_VERSION_URL",
        "KLYROW_VERSION_URL",
        "KEYCLOAK_E2E_ADMIN_CLIENT_ID",
        "KEYCLOAK_E2E_ADMIN_CLIENT_SECRET",
        "E2E_RECIPIENT_TEMPLATE",
        "E2E_IMAP_HOST",
        "E2E_IMAP_USERNAME",
        "E2E_IMAP_PASSWORD",
        "KLYROW_E2E_DATABASE_URL",
        "MIDDLEWARE_E2E_AUDIT_URL",
        "MIDDLEWARE_E2E_AUDIT_TOKEN",
    }
    missing = sorted(required_environment - set(environment))
    if missing:
        fail(f"acceptance environment is incomplete: {missing}")
    if environment["KEYCLOAK_ISSUER"] != "https://auth.codestra.co/realms/codestra":
        fail("canonical issuer changed")

    steps = sequence(job.get("steps"), "acceptance.steps")
    action_uses = [
        str(step.get("uses"))
        for step in steps
        if isinstance(step, dict) and step.get("uses")
    ]
    expected_actions = {
        f"actions/checkout@{CHECKOUT_SHA}",
        f"actions/upload-artifact@{UPLOAD_SHA}",
    }
    if set(action_uses) != expected_actions:
        fail(f"external actions changed: {action_uses}")

    rendered = WORKFLOW.read_text(encoding="utf-8")
    prohibited = (
        "pull_request:",
        "push:",
        "schedule:",
        "environment: production",
        "production / apply",
        "docker compose up",
        "kubectl apply",
        "ssh ",
        "sudo ",
        "KLYROW_SECURITY_SMTP_LIVE_ENABLED=true",
    )
    for marker in prohibited:
        if marker in rendered:
            fail(f"workflow contains prohibited activation marker: {marker}")

    script = SCRIPT.read_text(encoding="utf-8")
    required_gates = (
        "forgot_password_ui",
        "keycloak_reset_action_generated",
        "keycloak_smtp_authentication",
        "klyrow_security_acceptance",
        "postal_sent",
        "controlled_inbox_received",
        "reset_link_first_use",
        "reset_link_replay_rejected",
        "reset_link_expiration_enforced",
        "existing_sessions_invalidated",
        "middleware_receives_no_reset_secret",
    )
    for gate in required_gates:
        if gate not in script:
            fail(f"acceptance script is missing gate: {gate}")

    for secret_marker in (
        '"access_token":',
        '"password": initial_password',
        '"password": reset_password',
        '"action_url":',
        '"admin_client_secret":',
        '"imap_password":',
        '"middleware_audit_token":',
    ):
        if secret_marker in script:
            fail(f"acceptance report may expose a secret: {secret_marker}")

    if not re.search(r"os\.chmod\(temporary, 0o600\)", script):
        fail("acceptance evidence must be written with mode 0600")


def main() -> int:
    try:
        validate()
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        print(f"PASSWORD_RESET_E2E_POLICY_ERROR={exc}", file=sys.stderr)
        return 1
    print("PASSWORD_RESET_E2E_WORKFLOW_POLICY=PASS")
    print("PASSWORD_RESET_E2E_GATES=11")
    print("PASSWORD_RESET_E2E_TRIGGER=WORKFLOW_DISPATCH_ONLY")
    print("PASSWORD_RESET_E2E_RUNNER=CODESTRA_STAGING_ONLY")
    print("PASSWORD_RESET_E2E_EXECUTION=DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
