#!/usr/bin/env python3
"""Validate the read-only Keycloak pull-request authority workflows."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
CORE_PATH = ROOT / "scripts" / "validate-workflows-core.py"
PR_WORKFLOWS = {
    "keycloak-pr-authority-audit.yml",
    "keycloak-pr-authority-pr.yml",
}


def load_core() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "keycloak_pr_authority_workflow_core",
        CORE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("workflow policy core cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CORE = load_core()
PolicyError = CORE.PolicyError


def fail(message: str) -> None:
    raise PolicyError(message)


def text(workflow: dict[str, Any]) -> str:
    return "\n".join(CORE.recursive_strings(workflow))


def validate_common(path: Path, workflow: dict[str, Any]) -> tuple[dict[str, Any], str]:
    CORE.validate_permissions(
        workflow.get("permissions"),
        f"{path}.permissions",
        {
            "contents": "read",
            "pull-requests": "read",
            "checks": "read",
        },
    )
    jobs = CORE.as_mapping(workflow.get("jobs"), f"{path}.jobs")
    if set(jobs) != {"audit"}:
        fail(f"{path}: PR authority workflow must contain only audit")
    job = CORE.as_mapping(jobs["audit"], f"{path}.jobs.audit")
    if "permissions" in job or "environment" in job:
        fail(f"{path}: read-only audit cannot override permissions or use an Environment")
    if CORE.normalize_runs_on(job.get("runs-on")) != ["ubuntu-24.04"]:
        fail(f"{path}: audit must use ubuntu-24.04")
    if any(CORE.SECRET_EXPRESSION.search(item) for item in CORE.recursive_strings(job)):
        fail(f"{path}: repository secrets are prohibited")
    CORE.validate_steps(job, f"{path}.jobs.audit")
    workflow_text = text(workflow)
    for fragment in (
        "scripts/ci/audit_keycloak_pull_requests.py",
        "tests/test_audit_keycloak_pull_requests.py",
        "--json-output",
        "--markdown-output",
        "actions/upload-artifact",
        "retention-days",
        "github.token",
    ):
        if fragment not in workflow_text:
            fail(f"{path}: incomplete PR audit evidence; missing {fragment}")
    return job, workflow_text


def validate_exact_head(path: Path, workflow: dict[str, Any]) -> None:
    job, workflow_text = validate_common(path, workflow)
    triggers = CORE.as_mapping(workflow.get("on"), f"{path}.on")
    if set(triggers) != {"pull_request"}:
        fail(f"{path}: exact-head audit must be pull_request-only")
    pull_request = CORE.as_mapping(
        triggers["pull_request"],
        f"{path}.on.pull_request",
    )
    branches = CORE.as_sequence(
        pull_request.get("branches"),
        f"{path}.on.pull_request.branches",
    )
    if branches != ["development", "test", "staging", "production", "main"]:
        fail(f"{path}: protected promotion branch order changed")
    paths = CORE.as_sequence(
        pull_request.get("paths"),
        f"{path}.on.pull_request.paths",
    )
    if paths != [
        "scripts/ci/audit_keycloak_pull_requests.py",
        "tests/test_audit_keycloak_pull_requests.py",
        ".github/workflows/keycloak-pr-authority-*.yml",
    ]:
        fail(f"{path}: exact-head audit path boundary changed")
    if "github.event.pull_request.head.sha" not in workflow_text:
        fail(f"{path}: audit must bind to the exact PR head SHA")
    concurrency = CORE.as_mapping(workflow.get("concurrency"), f"{path}.concurrency")
    if concurrency.get("cancel-in-progress") != "true":
        fail(f"{path}: superseded exact-head audits must be cancelled")
    upload_steps = [
        step
        for step in CORE.as_sequence(job.get("steps"), f"{path}.jobs.audit.steps")
        if isinstance(step, dict)
        and str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    if len(upload_steps) != 1 or upload_steps[0].get("if") != "always()":
        fail(f"{path}: exact-head evidence must upload with always()")


def validate_repository_audit(path: Path, workflow: dict[str, Any]) -> None:
    _, workflow_text = validate_common(path, workflow)
    triggers = CORE.as_mapping(workflow.get("on"), f"{path}.on")
    if set(triggers) != {"workflow_dispatch", "schedule"}:
        fail(f"{path}: repository audit must be manual and scheduled only")
    schedule = CORE.as_sequence(triggers["schedule"], f"{path}.on.schedule")
    if len(schedule) != 1:
        fail(f"{path}: exactly one bounded schedule is required")
    if CORE.as_mapping(schedule[0], f"{path}.on.schedule[0]") != {
        "cron": "17 5 * * *"
    }:
        fail(f"{path}: audit schedule changed without review")
    if "github.sha" not in workflow_text:
        fail(f"{path}: scheduled audit must bind to github.sha")
    concurrency = CORE.as_mapping(workflow.get("concurrency"), f"{path}.concurrency")
    if concurrency.get("cancel-in-progress") != "false":
        fail(f"{path}: scheduled audit must preserve active evidence")


def validate() -> None:
    actual = {path.name for path in WORKFLOW_DIR.glob("keycloak-pr-authority-*.yml")}
    if actual != PR_WORKFLOWS:
        fail(f"Expected PR authority workflows {sorted(PR_WORKFLOWS)}, found {sorted(actual)}")
    validate_repository_audit(
        WORKFLOW_DIR / "keycloak-pr-authority-audit.yml",
        CORE.load_workflow(WORKFLOW_DIR / "keycloak-pr-authority-audit.yml"),
    )
    validate_exact_head(
        WORKFLOW_DIR / "keycloak-pr-authority-pr.yml",
        CORE.load_workflow(WORKFLOW_DIR / "keycloak-pr-authority-pr.yml"),
    )
    print("KEYCLOAK_PR_AUTHORITY_WORKFLOW_POLICY=PASS")


if __name__ == "__main__":
    try:
        validate()
    except PolicyError as exc:
        print(f"KEYCLOAK_PR_AUTHORITY_WORKFLOW_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
