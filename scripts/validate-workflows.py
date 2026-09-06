#!/usr/bin/env python3
"""Validate all Keycloak workflow, repository, PR, and release authorities."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
CORE_PATH = ROOT / "scripts" / "validate-workflows-core.py"
PR_AUTHORITY_POLICY = ROOT / "scripts" / "validate-pr-authority-workflows.py"
RELEASE_CONTRACT = ROOT / ".codestra" / "production-orchestrator-contract.v1.json"

LEGACY_WORKFLOWS = {
    "deploy.yml",
    "drift-review.yml",
    "runtime-preflight.yml",
    "validate.yml",
}
AUTHORITY_WORKFLOW = "repository-name-authority.yml"
LIVE_AUTHORITY_WORKFLOW = "repository-name-live-authority.yml"
MANUAL_RELEASE_WORKFLOW = "manual-release-intent.yml"
ADDITIONAL_REVIEWED_WORKFLOWS = {"orbit-theme.yml", "scrapper-identity-contract.yml"}
PR_AUTHORITY_WORKFLOWS = {
    "keycloak-pr-authority-audit.yml",
    "keycloak-pr-authority-pr.yml",
}
EXPECTED_WORKFLOWS = (
    LEGACY_WORKFLOWS
    | {AUTHORITY_WORKFLOW, LIVE_AUTHORITY_WORKFLOW, MANUAL_RELEASE_WORKFLOW}
    | PR_AUTHORITY_WORKFLOWS
    | ADDITIONAL_REVIEWED_WORKFLOWS
)


def load_core() -> ModuleType:
    spec = importlib.util.spec_from_file_location("keycloak_workflow_policy_core", CORE_PATH)
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


def workflow_text(workflow: dict[str, Any]) -> str:
    return "\n".join(CORE.recursive_strings(workflow))


def validate_repository_name_authority(path: Path, workflow: dict[str, Any]) -> None:
    triggers = CORE.as_mapping(workflow.get("on"), f"{path}.on")
    if set(triggers) != {"pull_request", "push"}:
        fail(f"{path}: authority validation must trigger only on pull_request and push")

    pull_request = CORE.as_mapping(triggers["pull_request"], f"{path}.on.pull_request")
    push = CORE.as_mapping(triggers["push"], f"{path}.on.push")
    if CORE.as_sequence(
        pull_request.get("branches"), f"{path}.on.pull_request.branches"
    ) != ["main"]:
        fail(f"{path}: pull-request validation must target main only")
    if CORE.as_sequence(push.get("branches"), f"{path}.on.push.branches") != [
        "main"
    ]:
        fail(f"{path}: push validation must target main only")

    CORE.validate_permissions(
        workflow.get("permissions"), f"{path}.permissions", {"contents": "read"}
    )
    jobs = CORE.as_mapping(workflow.get("jobs"), f"{path}.jobs")
    if set(jobs) != {"repository-name-authority"}:
        fail(f"{path}: unexpected authority job set")

    job = CORE.as_mapping(
        jobs["repository-name-authority"], f"{path}.jobs.repository-name-authority"
    )
    if "permissions" in job or "environment" in job:
        fail(f"{path}: offline authority job cannot override permissions or use an Environment")
    if "self-hosted" in CORE.normalize_runs_on(job.get("runs-on")):
        fail(f"{path}: offline authority validation cannot use a self-hosted runner")
    if any(CORE.SECRET_EXPRESSION.search(text) for text in CORE.recursive_strings(job)):
        fail(f"{path}: offline authority validation cannot reference secrets")

    CORE.validate_steps(job, f"{path}.jobs.repository-name-authority")
    text = workflow_text(workflow)
    for required in (
        "github.event.pull_request.head.sha",
        "github.sha",
        "git rev-parse HEAD",
        "validate-repository-name-authority.py",
        "test_repository_name_authority.py",
    ):
        if required not in text:
            fail(f"{path}: offline authority validation is missing {required}")
    if "--live" in text or "CODESTRA_REPOSITORY_READ_TOKEN" in text:
        fail(f"{path}: offline pull-request validation must not invoke the live token gate")


def validate_repository_name_live_authority(
    path: Path, workflow: dict[str, Any]
) -> None:
    triggers = CORE.as_mapping(workflow.get("on"), f"{path}.on")
    if set(triggers) != {"workflow_dispatch"}:
        fail(f"{path}: live repository identity must be workflow_dispatch-only")

    dispatch = CORE.as_mapping(
        triggers["workflow_dispatch"], f"{path}.on.workflow_dispatch"
    )
    inputs = CORE.as_mapping(dispatch.get("inputs"), f"{path}.on.workflow_dispatch.inputs")
    if set(inputs) != {"confirm_sha"}:
        fail(f"{path}: live authority must require only confirm_sha")
    confirm_sha = CORE.as_mapping(inputs["confirm_sha"], f"{path}.confirm_sha")
    if confirm_sha.get("required") != "true" or confirm_sha.get("type") != "string":
        fail(f"{path}: confirm_sha must be a required string")

    CORE.validate_permissions(
        workflow.get("permissions"), f"{path}.permissions", {"contents": "read"}
    )
    jobs = CORE.as_mapping(workflow.get("jobs"), f"{path}.jobs")
    if set(jobs) != {"validate-live-repository-ids"}:
        fail(f"{path}: unexpected live authority job set")

    job = CORE.as_mapping(
        jobs["validate-live-repository-ids"],
        f"{path}.jobs.validate-live-repository-ids",
    )
    if "permissions" in job:
        fail(f"{path}: live authority job cannot override permissions")
    if str(job.get("if", "")) != "github.ref == 'refs/heads/main'":
        fail(f"{path}: live authority must be restricted to main")
    if str(job.get("environment", "")) != "production":
        fail(f"{path}: live authority must use the protected production Environment")
    if "self-hosted" in CORE.normalize_runs_on(job.get("runs-on")):
        fail(f"{path}: metadata-only live authority cannot use a self-hosted runner")

    secret_values = {
        text
        for text in CORE.recursive_strings(job)
        if CORE.SECRET_EXPRESSION.search(text)
    }
    if secret_values != {"${{ secrets.CODESTRA_REPOSITORY_READ_TOKEN }}"}:
        fail(
            f"{path}: live authority may reference only "
            "CODESTRA_REPOSITORY_READ_TOKEN"
        )

    CORE.validate_steps(job, f"{path}.jobs.validate-live-repository-ids")
    text = workflow_text(workflow)
    for required in (
        "refs/heads/main",
        "inputs.confirm_sha",
        "CODESTRA_REPOSITORY_READ_TOKEN",
        "git rev-parse HEAD",
        "validate-repository-name-authority.py --live",
    ):
        if required not in text:
            fail(f"{path}: live authority is missing {required}")

    prohibited = re.compile(
        r"(?i)(docker\s|kubectl|helm\s|terraform|tofu\s|ssh\s|"
        r"apply-plan|keycloak-config-cli|docker-compose|docker\s+compose)"
    )
    if any(prohibited.search(text) for text in CORE.recursive_strings(job)):
        fail(f"{path}: live repository identity workflow must remain metadata-only")


def validate_legacy_workflows() -> None:
    """Run the unchanged legacy policy against only the original workflows."""

    with tempfile.TemporaryDirectory(prefix="keycloak-workflow-policy-") as directory:
        legacy_directory = Path(directory)
        for name in sorted(LEGACY_WORKFLOWS):
            source = WORKFLOW_DIR / name
            if not source.is_file():
                fail(f"legacy workflow is missing: {source}")
            shutil.copy2(source, legacy_directory / name)
        original_directory = CORE.WORKFLOW_DIR
        try:
            CORE.WORKFLOW_DIR = legacy_directory
            CORE.validate()
        finally:
            CORE.WORKFLOW_DIR = original_directory


def validate_additional_reviewed_workflows() -> None:
    for name in sorted(ADDITIONAL_REVIEWED_WORKFLOWS):
        path = WORKFLOW_DIR / name
        workflow = CORE.load_workflow(path)
        CORE.validate_permissions(
            workflow.get("permissions"), f"{path}.permissions", {"contents": "read"}
        )
        jobs = CORE.as_mapping(workflow.get("jobs"), f"{path}.jobs")
        if not jobs:
            fail(f"{path}: workflow must define at least one job")
        for job_name, value in jobs.items():
            job = CORE.as_mapping(value, f"{path}.jobs.{job_name}")
            if "permissions" in job or "environment" in job:
                fail(f"{path}: reviewed validation jobs cannot elevate permissions")
            if "self-hosted" in CORE.normalize_runs_on(job.get("runs-on")):
                fail(f"{path}: reviewed validation jobs cannot use self-hosted runners")
            if any(
                CORE.SECRET_EXPRESSION.search(text)
                for text in CORE.recursive_strings(job)
            ):
                fail(f"{path}: reviewed validation jobs cannot reference secrets")
            CORE.validate_steps(job, f"{path}.jobs.{job_name}")


def validate_pr_authority_workflows() -> None:
    completed = subprocess.run(
        [sys.executable, str(PR_AUTHORITY_POLICY)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        fail(f"PR authority workflow validation failed: {detail}")
    if "KEYCLOAK_PR_AUTHORITY_WORKFLOW_POLICY=PASS" not in completed.stdout:
        fail("PR authority workflow validator did not emit its PASS marker")


def validate_release_contract() -> None:
    if not RELEASE_CONTRACT.is_file() or RELEASE_CONTRACT.is_symlink():
        fail("release-intent contract is missing or unsafe")
    try:
        contract = json.loads(RELEASE_CONTRACT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"release-intent contract is invalid: {exc}")
    if not isinstance(contract, dict):
        fail("release-intent contract root must be an object")

    exact_keys = {
        "schema_version",
        "repository",
        "repository_id",
        "default_branch",
        "role",
        "release_intent_workflow",
        "deployment_authority",
        "require_verified_commit",
        "required_checks",
        "supported_phases",
        "artifact_policy",
        "environments",
        "native_workflows",
        "safety",
        "blockers",
    }
    if set(contract) != exact_keys:
        fail("release-intent contract key set drift")

    expected_scalars = {
        "schema_version": "codestra.production-orchestrator-contract.v1",
        "repository": "appolon1908-hue/Keycloak",
        "repository_id": 1347523366,
        "default_branch": "main",
        "role": "identity",
        "release_intent_workflow": ".github/workflows/manual-release-intent.yml",
        "deployment_authority": True,
        "require_verified_commit": True,
    }
    for key, expected in expected_scalars.items():
        if contract.get(key) != expected:
            fail(f"release-intent contract drift: {key}")

    if contract.get("required_checks") != ["validate"]:
        fail("release-intent required-check authority drift")
    if contract.get("supported_phases") != ["plan", "staging", "canary", "production"]:
        fail("release-intent phase authority drift")
    if contract.get("artifact_policy") != {
        "minimum_images": 0,
        "maximum_images": 0,
        "require_digest": True,
        "allow_rebuild_after_staging": False,
        "allow_retag_after_staging": False,
        "require_sbom": False,
        "require_provenance": False,
        "require_signature": False,
    }:
        fail("release-intent artifact policy drift")
    if contract.get("environments") != {
        "staging": "staging-readonly",
        "canary": "production-readonly-canary",
        "production": "production",
    }:
        fail("release-intent environment mapping drift")
    if contract.get("native_workflows") != {
        "plan_apply": ".github/workflows/deploy.yml",
        "drift_review": ".github/workflows/drift-review.yml",
    }:
        fail("release-intent native workflow mapping drift")

    expected_safety = {
        "external_effects_default": False,
        "live_email_delivery": False,
        "live_sms_delivery": False,
        "live_pstn_dialing": False,
        "odoo_write": False,
        "n8n_external_delivery": False,
        "live_trading": False,
        "payment_execution": False,
    }
    if contract.get("safety") != expected_safety:
        fail("release-intent safety defaults must remain exact and false")
    if contract.get("blockers") != []:
        fail("release-intent blocker field must be an explicit empty list")


def validate_manual_release_intent(path: Path, workflow: dict[str, Any]) -> None:
    triggers = CORE.as_mapping(workflow.get("on"), f"{path}.on")
    if set(triggers) != {"workflow_dispatch"}:
        fail(f"{path}: release intent must be workflow_dispatch-only")
    dispatch = CORE.as_mapping(
        triggers["workflow_dispatch"], f"{path}.on.workflow_dispatch"
    )
    inputs = CORE.as_mapping(dispatch.get("inputs"), f"{path}.on.workflow_dispatch.inputs")
    expected_inputs = {
        "phase",
        "source_sha",
        "release_id",
        "candidate_sha256",
        "images_json",
        "previous_images_json",
        "prior_evidence_sha256",
        "confirmation",
    }
    if set(inputs) != expected_inputs:
        fail(f"{path}: release-intent inputs must be exact and bounded")
    for name, raw in inputs.items():
        item = CORE.as_mapping(raw, f"{path}.inputs.{name}")
        if item.get("required") != "true":
            fail(f"{path}: input {name} must be required")
    phase = CORE.as_mapping(inputs["phase"], f"{path}.inputs.phase")
    if phase.get("type") != "choice" or CORE.as_sequence(
        phase.get("options"), f"{path}.inputs.phase.options"
    ) != ["plan", "staging", "canary", "production"]:
        fail(f"{path}: phase input must use the exact bounded choice set")
    for name in expected_inputs - {"phase"}:
        item = CORE.as_mapping(inputs[name], f"{path}.inputs.{name}")
        if item.get("type") != "string":
            fail(f"{path}: input {name} must be a string")

    CORE.validate_permissions(
        workflow.get("permissions"),
        f"{path}.permissions",
        {"actions": "read", "checks": "read", "contents": "read"},
    )
    jobs = CORE.as_mapping(workflow.get("jobs"), f"{path}.jobs")
    if set(jobs) != {"verify", "plan-intent", "protected-intent"}:
        fail(f"{path}: unexpected release-intent job set")

    for name, raw_job in jobs.items():
        job = CORE.as_mapping(raw_job, f"{path}.jobs.{name}")
        if "permissions" in job:
            fail(f"{path}: release-intent jobs cannot override permissions")
        if "self-hosted" in CORE.normalize_runs_on(job.get("runs-on")):
            fail(f"{path}: release-intent policy cannot use a self-hosted runner")
        if any(
            CORE.SECRET_EXPRESSION.search(text)
            for text in CORE.recursive_strings(job)
        ):
            fail(f"{path}: release-intent policy cannot reference secrets")
        CORE.validate_steps(job, f"{path}.jobs.{name}")

    if "environment" in CORE.as_mapping(jobs["verify"], f"{path}.jobs.verify"):
        fail(f"{path}: pre-approval verify job cannot use an Environment")
    if "environment" in CORE.as_mapping(jobs["plan-intent"], f"{path}.jobs.plan-intent"):
        fail(f"{path}: plan intent cannot use an Environment")
    if "environment" not in CORE.as_mapping(
        jobs["protected-intent"], f"{path}.jobs.protected-intent"
    ):
        fail(f"{path}: protected intent must use the selected protected Environment")

    text = workflow_text(workflow)
    for required in (
        "refs/heads/",
        "git rev-parse HEAD",
        "branches/",
        "check-runs?per_page=100",
        "@sha256:",
        "allow_rebuild_after_staging",
        "allow_retag_after_staging",
        "staging-readonly",
        "production-readonly-canary",
        "protected_environment_approved",
        "runtime_contacted",
        "production_changed",
        "external_effects_enabled",
    ):
        if required not in text:
            fail(f"{path}: release-intent policy is missing {required}")

    prohibited = re.compile(
        r"(?i)(pull_request_target|ssh\s|scp\s|rsync\s|docker\s|kubectl|"
        r"helm\s|terraform|tofu\s|keycloak-config-cli|curl\s+[^\n]*-[Xx]\s*"
        r"(POST|PUT|PATCH|DELETE))"
    )
    if any(prohibited.search(value) for value in CORE.recursive_strings(workflow)):
        fail(f"{path}: release intent must remain metadata-only")


def validate() -> None:
    if not WORKFLOW_DIR.is_dir():
        fail(f"Workflow directory does not exist: {WORKFLOW_DIR}")
    workflow_files = sorted(
        [*WORKFLOW_DIR.glob("*.yml"), *WORKFLOW_DIR.glob("*.yaml")]
    )
    actual_names = {path.name for path in workflow_files}
    if actual_names != EXPECTED_WORKFLOWS:
        fail(
            f"Expected workflow files {sorted(EXPECTED_WORKFLOWS)}, "
            f"found {sorted(actual_names)}"
        )

    validate_legacy_workflows()
    validate_additional_reviewed_workflows()
    validate_repository_name_authority(
        WORKFLOW_DIR / AUTHORITY_WORKFLOW,
        CORE.load_workflow(WORKFLOW_DIR / AUTHORITY_WORKFLOW),
    )
    validate_repository_name_live_authority(
        WORKFLOW_DIR / LIVE_AUTHORITY_WORKFLOW,
        CORE.load_workflow(WORKFLOW_DIR / LIVE_AUTHORITY_WORKFLOW),
    )
    validate_pr_authority_workflows()
    validate_manual_release_intent(
        WORKFLOW_DIR / MANUAL_RELEASE_WORKFLOW,
        CORE.load_workflow(WORKFLOW_DIR / MANUAL_RELEASE_WORKFLOW),
    )
    validate_release_contract()

    print(f"WORKFLOW_FILES={len(workflow_files)}")
    print("REPOSITORY_NAME_WORKFLOW_POLICY=PASS")
    print("PR_AUTHORITY_WORKFLOW_POLICY=PASS")
    print("MANUAL_RELEASE_INTENT_POLICY=PASS")
    print("RELEASE_INTENT_CONTRACT=PASS")
    print("WORKFLOW_YAML_PARSE=PASS")
    print("WORKFLOW_POLICY=PASS")


if __name__ == "__main__":
    try:
        validate()
    except PolicyError as exc:
        print(f"WORKFLOW_POLICY_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
