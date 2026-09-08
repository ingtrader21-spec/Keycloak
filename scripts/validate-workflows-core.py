#!/usr/bin/env python3
"""Fail-closed policy validation for GitHub Actions workflow YAML."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Iterable

import yaml
from yaml.events import AliasEvent
from yaml.resolver import BaseResolver

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
STAGE6_BRANCH = "ops/stage6-intake-observability-execution-20260830"
STAGE6_LOCK = "config/executions/stage6-intake-observability.v1.json"

ALLOWED_ACTIONS = {
    "actions/attest-build-provenance": "43d14bc2b83dec42d39ecae14e916627a18bb661",
    "actions/attest-sbom": "51e74621a501c89df81fc1391c5a8f4cfc9fab2f",
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "aquasecurity/setup-trivy": "81e514348e19b6112ce2a7e3ecbafe19c1e1f567",
}
ACTION_REFERENCE = re.compile(r"^(?P<action>[^@\s]+)@(?P<sha>[0-9a-f]{40})$")
WRITE_PERMISSION = re.compile(r"^(?:write|write-all)$", re.IGNORECASE)
SECRET_EXPRESSION = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)


class PolicyError(RuntimeError):
    pass


class UniqueKeyLoader(yaml.BaseLoader):
    """BaseLoader variant that preserves `on` and rejects duplicate keys."""


def _construct_mapping(loader: UniqueKeyLoader, node: yaml.Node, deep: bool = False) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise PolicyError(f"YAML mapping key must be a string at line {key_node.start_mark.line + 1}")
        if key in mapping:
            raise PolicyError(f"Duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def fail(message: str) -> None:
    raise PolicyError(message)


def load_workflow(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        for event in yaml.parse(text):
            if isinstance(event, AliasEvent) or getattr(event, "anchor", None):
                fail(f"{path}: YAML anchors and aliases are prohibited")
        parsed = yaml.load(text, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        fail(f"{path}: invalid YAML: {exc}")
    if not isinstance(parsed, dict):
        fail(f"{path}: workflow root must be a mapping")
    return parsed


def as_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a mapping")
    return value


def as_sequence(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be a sequence")
    return value


def recursive_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from recursive_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from recursive_strings(child)


def normalize_runs_on(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    fail("runs-on must be a string or a sequence of strings")


def validate_permissions(
    value: Any,
    label: str,
    required: dict[str, str],
    allowed_write_scopes: set[str] | None = None,
) -> None:
    permissions = as_mapping(value, label)
    normalized = {str(key): str(permission).lower() for key, permission in permissions.items()}
    allowed_writes = allowed_write_scopes or set()
    for scope, permission in normalized.items():
        if WRITE_PERMISSION.fullmatch(permission) and scope not in allowed_writes:
            fail(f"{label}: write permission is prohibited for {scope}")
        if permission not in {"read", "none"} and not (permission == "write" and scope in allowed_writes):
            fail(f"{label}: unsupported permission {scope}: {permission}")
    if normalized != required:
        fail(f"{label}: expected permissions {required}, found {normalized}")


def validate_action_step(
    step: dict[str, Any],
    label: str,
    *,
    checkout_fetch_depth: str = "1",
) -> None:
    uses = step.get("uses")
    if uses is None:
        return
    if not isinstance(uses, str):
        fail(f"{label}.uses must be a string")
    if uses.startswith("./"):
        return
    match = ACTION_REFERENCE.fullmatch(uses)
    if not match:
        fail(f"{label}: action reference must use a full 40-character SHA: {uses}")
    action = match.group("action")
    actual_sha = match.group("sha")
    expected_sha = ALLOWED_ACTIONS.get(action)
    if expected_sha is None:
        fail(f"{label}: action is not allowlisted: {action}")
    if actual_sha != expected_sha:
        fail(f"{label}: {action} must be pinned to {expected_sha}, found {actual_sha}")
    if action == "actions/checkout":
        options = as_mapping(step.get("with", {}), f"{label}.with")
        if options.get("persist-credentials") != "false":
            fail(f"{label}: checkout must set persist-credentials: false")
        if options.get("fetch-depth") != checkout_fetch_depth:
            fail(
                f"{label}: checkout must set fetch-depth: "
                f"{checkout_fetch_depth}"
            )
        if not isinstance(options.get("ref"), str) or not options["ref"].strip():
            fail(f"{label}: checkout must bind ref to an explicit SHA expression or literal SHA")


def validate_steps(
    job: dict[str, Any],
    label: str,
    *,
    checkout_fetch_depth_overrides: dict[int, str] | None = None,
) -> None:
    steps = as_sequence(job.get("steps"), f"{label}.steps")
    depth_overrides = checkout_fetch_depth_overrides or {}
    for index, raw_step in enumerate(steps):
        step = as_mapping(raw_step, f"{label}.steps[{index}]")
        validate_action_step(
            step,
            f"{label}.steps[{index}]",
            checkout_fetch_depth=depth_overrides.get(index, "1"),
        )


def validate_source_workflow(path: Path, workflow: dict[str, Any]) -> None:
    triggers = as_mapping(workflow.get("on"), f"{path}.on")
    if set(triggers) != {"pull_request", "push"}:
        fail(f"{path}: source validation must trigger only on pull_request and push")
    push = as_mapping(triggers["push"], f"{path}.on.push")
    if as_sequence(push.get("branches"), f"{path}.on.push.branches") != ["main"]:
        fail(f"{path}: push validation must be limited to main")
    validate_permissions(workflow.get("permissions"), f"{path}.permissions", {"contents": "read"})
    jobs = as_mapping(workflow.get("jobs"), f"{path}.jobs")
    if set(jobs) != {"validate-source", "validate-merge-result"}:
        fail(f"{path}: expected validate-source and validate-merge-result jobs")
    for job_name, raw_job in jobs.items():
        job = as_mapping(raw_job, f"{path}.jobs.{job_name}")
        if "permissions" in job or "environment" in job:
            fail(f"{path}.jobs.{job_name}: permission overrides and Environments are prohibited")
        if "self-hosted" in normalize_runs_on(job.get("runs-on")):
            fail(f"{path}.jobs.{job_name}: source validation must not use a self-hosted runner")
        if any(SECRET_EXPRESSION.search(text) for text in recursive_strings(job)):
            fail(f"{path}.jobs.{job_name}: source validation must not reference secrets")
        validate_steps(job, f"{path}.jobs.{job_name}")
    source_job = as_mapping(jobs["validate-source"], f"{path}.jobs.validate-source")
    merge_job = as_mapping(jobs["validate-merge-result"], f"{path}.jobs.validate-merge-result")
    source_text = "\n".join(recursive_strings(source_job))
    merge_text = "\n".join(recursive_strings(merge_job))
    if "github.event.pull_request.head.sha" not in source_text or "github.sha" not in source_text:
        fail(f"{path}: validate-source must bind to the exact PR head SHA and push SHA")
    if "pull_request" not in str(merge_job.get("if", "")) or "github.sha" not in merge_text:
        fail(f"{path}: merge-result validation must bind to the synthetic PR merge SHA")
    for fragment in ("test-plan-gate.sh", "validate_stage6_intake_observability_source.py", "test_stage6_monitoring_reconcile.py"):
        if fragment not in source_text or fragment not in merge_text:
            fail(f"{path}: both exact-SHA jobs must exercise {fragment}")


def validate_runtime_preflight_trigger(path: Path, workflow: dict[str, Any]) -> None:
    triggers = as_mapping(workflow.get("on"), f"{path}.on")
    if set(triggers) != {"workflow_dispatch", "push"}:
        fail(f"{path}: runtime preflight must use workflow_dispatch plus the exact Stage 6 push trigger")
    push = as_mapping(triggers["push"], f"{path}.on.push")
    if as_sequence(push.get("branches"), f"{path}.on.push.branches") != [STAGE6_BRANCH]:
        fail(f"{path}: Stage 6 push branch is not exact")
    if as_sequence(push.get("paths"), f"{path}.on.push.paths") != [STAGE6_LOCK]:
        fail(f"{path}: Stage 6 push path is not exact")


def validate_privileged_workflow(path: Path, workflow: dict[str, Any]) -> None:
    triggers = as_mapping(workflow.get("on"), f"{path}.on")
    if path.name == "runtime-preflight.yml":
        validate_runtime_preflight_trigger(path, workflow)
    elif set(triggers) != {"workflow_dispatch"}:
        fail(f"{path}: privileged workflow must be workflow_dispatch-only")

    required_permissions = {"contents": "read"}
    if path.name in {"deploy.yml", "drift-review.yml"}:
        required_permissions["actions"] = "read"
    if path.name == "drift-review.yml":
        required_permissions["pull-requests"] = "read"
    if path.name == "runtime-preflight.yml":
        required_permissions["packages"] = "read"
    validate_permissions(workflow.get("permissions"), f"{path}.permissions", required_permissions)

    jobs = as_mapping(workflow.get("jobs"), f"{path}.jobs")
    if path.name == "runtime-preflight.yml" and set(jobs) != {"guard", "inspect", "stage6-intake-observability"}:
        fail(f"{path}: unexpected runtime-preflight job set")
    found_self_hosted = False
    for job_name, raw_job in jobs.items():
        job = as_mapping(raw_job, f"{path}.jobs.{job_name}")
        if "permissions" in job:
            fail(f"{path}.jobs.{job_name}: job-level permission overrides are prohibited")
        runs_on = normalize_runs_on(job.get("runs-on"))
        if "self-hosted" in runs_on:
            found_self_hosted = True
            if "environment" not in job:
                fail(f"{path}.jobs.{job_name}: self-hosted job must use a protected Environment")
        checkout_depth_overrides = (
            {0: "2"}
            if path.name == "runtime-preflight.yml"
            and job_name == "stage6-intake-observability"
            else None
        )
        validate_steps(
            job,
            f"{path}.jobs.{job_name}",
            checkout_fetch_depth_overrides=checkout_depth_overrides,
        )
    if not found_self_hosted and path.name != "drift-review.yml":
        fail(f"{path}: privileged workflow must contain a protected self-hosted job")
    if path.name == "drift-review.yml" and "environment" not in as_mapping(jobs.get("review"), f"{path}.jobs.review"):
        fail(f"{path}: drift review must use a protected Environment")

    workflow_text = "\n".join(recursive_strings(workflow))
    for required_fragment in ("refs/heads/main", "confirm_sha", "--expected-deploy-sha"):
        if required_fragment not in workflow_text:
            fail(f"{path}: privileged manual authority is incomplete; missing {required_fragment}")

    if path.name == "deploy.yml":
        dispatch = as_mapping(triggers["workflow_dispatch"], f"{path}.on.workflow_dispatch")
        inputs = as_mapping(dispatch.get("inputs"), f"{path}.on.workflow_dispatch.inputs")
        required_inputs = {"environment", "mode", "confirm_sha", "plan_run_id", "approved_plan_sha256", "review_run_id", "approved_review_sha256"}
        if not required_inputs.issubset(inputs):
            fail(f"{path}: missing plan-gate inputs: {sorted(required_inputs - set(inputs))}")
        for fragment in ("actions/download-artifact", "approved_plan_sha256", "plan_run_id", "apply-plan.sh", "sync-runtime-repository.sh", "--allow-stale-local-head", "keycloak-plan-", "keycloak-drift-review-", "approved_review_sha256"):
            if fragment not in workflow_text:
                fail(f"{path}: reviewed plan gate is incomplete; missing {fragment}")
    elif path.name == "drift-review.yml":
        for fragment in ("plan_run_id", "approved_plan_sha256", "commits/$GITHUB_SHA/pulls", "review-plan.sh", "keycloak-drift-review-"):
            if fragment not in workflow_text:
                fail(f"{path}: independent drift-review gate is incomplete; missing {fragment}")
    elif path.name == "runtime-preflight.yml":
        manual_guard = as_mapping(jobs["guard"], f"{path}.jobs.guard")
        manual_inspect = as_mapping(jobs["inspect"], f"{path}.jobs.inspect")
        if "workflow_dispatch" not in str(manual_guard.get("if", "")) or "workflow_dispatch" not in str(manual_inspect.get("if", "")):
            fail(f"{path}: existing manual jobs must be isolated from the Stage 6 push event")
        stage6 = as_mapping(jobs["stage6-intake-observability"], f"{path}.jobs.stage6-intake-observability")
        stage6_steps = as_sequence(
            stage6.get("steps"),
            f"{path}.jobs.stage6-intake-observability.steps",
        )
        first_step = as_mapping(
            stage6_steps[0],
            f"{path}.jobs.stage6-intake-observability.steps[0]",
        )
        expected_checkout = (
            "actions/checkout@"
            + ALLOWED_ACTIONS["actions/checkout"]
        )
        if first_step.get("uses") != expected_checkout:
            fail(
                f"{path}: Stage 6 first step must be the pinned "
                "actions/checkout action"
            )
        first_options = as_mapping(
            first_step.get("with", {}),
            f"{path}.jobs.stage6-intake-observability.steps[0].with",
        )
        if first_options.get("fetch-depth") != "2":
            fail(f"{path}: Stage 6 checkout must fetch its exact parent")
        stage6_text = "\n".join(recursive_strings(stage6))
        for fragment in (
            STAGE6_BRANCH,
            STAGE6_LOCK,
            "codestra-keycloak",
            "environment staging",
            "reconcile_monitoring_readonly_staging.py",
            "metrics.token",
            "health.token",
            "collect_staging_intake_evidence.py",
            "middleware-intake-staging:8080",
            "sha256:695fa3ce3f50ba4d0ae0784976b946a0a683ca731155e4bd3bd9e90a4670b820",
            "PROMETHEUS_TARGET_STATE=pending",
            "BLACKBOX_TARGET_STATE=pending",
            "actions/upload-artifact",
            "missing_protected_staging_input",
            "https://auth-staging.codestra.co",
            "KC_BASE_URL",
            "KC_PUBLIC_URL",
            "KC_ADMIN_REALM",
            "kc_base_url_must_be_canonical_staging_https",
            "kc_public_url_must_be_canonical_staging_https",
            "kc_admin_realm_must_be_master",
            "source scripts/ephemeral-docker-auth.sh",
        ):
            if fragment not in stage6_text:
                fail(f"{path}: Stage 6 execution authority is incomplete; missing {fragment}")
        if stage6_text.count("source scripts/ephemeral-docker-auth.sh") != 2:
            fail(f"{path}: every Docker-consuming Stage 6 step must use ephemeral GHCR credentials")
        if "docker login" in stage6_text or "docker logout" in stage6_text:
            fail(f"{path}: inline persistent Docker authentication is prohibited")
        if "github.event_name == 'push'" not in str(stage6.get("if", "")):
            fail(f"{path}: Stage 6 job must be push-only")
        if str(stage6.get("environment", "")) != "staging":
            fail(f"{path}: Stage 6 job must use the protected staging Environment")


def validate() -> None:
    if not WORKFLOW_DIR.is_dir():
        fail(f"Workflow directory does not exist: {WORKFLOW_DIR}")
    workflow_files = sorted([*WORKFLOW_DIR.glob("*.yml"), *WORKFLOW_DIR.glob("*.yaml")])
    expected_names = {"validate.yml", "runtime-preflight.yml", "deploy.yml", "drift-review.yml"}
    actual_names = {path.name for path in workflow_files}
    if actual_names != expected_names:
        fail(f"Expected workflow files {sorted(expected_names)}, found {sorted(actual_names)}")
    for path in workflow_files:
        workflow = load_workflow(path)
        if path.name == "validate.yml":
            validate_source_workflow(path, workflow)
        else:
            validate_privileged_workflow(path, workflow)
    print(f"WORKFLOW_FILES={len(workflow_files)}")
    print("WORKFLOW_YAML_PARSE=PASS")
    print("WORKFLOW_POLICY=PASS")


if __name__ == "__main__":
    try:
        validate()
    except PolicyError as exc:
        print(f"WORKFLOW_POLICY_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
