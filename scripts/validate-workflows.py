#!/usr/bin/env python3
"""Fail-closed policy validation for GitHub Actions workflow YAML.

The validator parses YAML rather than inspecting source text with regular
expressions. It rejects duplicate keys and YAML anchors/aliases so policy checks
cannot be bypassed through merge keys or alternate YAML representations.
"""

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

ALLOWED_ACTIONS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",  # v7.0.1
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",  # v7.0.1
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",  # v8.0.1
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


def validate_permissions(value: Any, label: str, required: dict[str, str]) -> None:
    permissions = as_mapping(value, label)
    normalized = {str(key): str(permission).lower() for key, permission in permissions.items()}
    for scope, permission in normalized.items():
        if WRITE_PERMISSION.fullmatch(permission):
            fail(f"{label}: write permission is prohibited for {scope}")
        if permission not in {"read", "none"}:
            fail(f"{label}: unsupported permission {scope}: {permission}")
    if normalized != required:
        fail(f"{label}: expected permissions {required}, found {normalized}")


def validate_action_step(step: dict[str, Any], label: str) -> None:
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
        if options.get("fetch-depth") != "1":
            fail(f"{label}: checkout must set fetch-depth: 1")
        if not isinstance(options.get("ref"), str) or not options["ref"].strip():
            fail(f"{label}: checkout must bind ref to an explicit GitHub SHA expression")


def validate_steps(job: dict[str, Any], label: str) -> None:
    steps = as_sequence(job.get("steps"), f"{label}.steps")
    for index, raw_step in enumerate(steps):
        step = as_mapping(raw_step, f"{label}.steps[{index}]")
        validate_action_step(step, f"{label}.steps[{index}]")


def validate_source_workflow(path: Path, workflow: dict[str, Any]) -> None:
    triggers = as_mapping(workflow.get("on"), f"{path}.on")
    if set(triggers) != {"pull_request", "push"}:
        fail(f"{path}: source validation must trigger only on pull_request and push")
    push = as_mapping(triggers["push"], f"{path}.on.push")
    branches = as_sequence(push.get("branches"), f"{path}.on.push.branches")
    if branches != ["main"]:
        fail(f"{path}: push validation must be limited to main")

    validate_permissions(workflow.get("permissions"), f"{path}.permissions", {"contents": "read"})
    jobs = as_mapping(workflow.get("jobs"), f"{path}.jobs")
    if set(jobs) != {"validate-source", "validate-merge-result"}:
        fail(f"{path}: expected validate-source and validate-merge-result jobs")

    for job_name, raw_job in jobs.items():
        job = as_mapping(raw_job, f"{path}.jobs.{job_name}")
        if "permissions" in job:
            fail(f"{path}.jobs.{job_name}: job-level permission overrides are prohibited")
        if "environment" in job:
            fail(f"{path}.jobs.{job_name}: pull-request validation must not use an Environment")
        if "self-hosted" in normalize_runs_on(job.get("runs-on")):
            fail(f"{path}.jobs.{job_name}: pull-request validation must not use a self-hosted runner")
        if any(SECRET_EXPRESSION.search(text) for text in recursive_strings(job)):
            fail(f"{path}.jobs.{job_name}: pull-request validation must not reference secrets")
        validate_steps(job, f"{path}.jobs.{job_name}")

    source_job = as_mapping(jobs["validate-source"], f"{path}.jobs.validate-source")
    source_text = "\n".join(recursive_strings(source_job))
    if "github.event.pull_request.head.sha" not in source_text or "github.sha" not in source_text:
        fail(f"{path}: validate-source must bind to the exact PR head SHA and push SHA")

    merge_job = as_mapping(jobs["validate-merge-result"], f"{path}.jobs.validate-merge-result")
    if "pull_request" not in str(merge_job.get("if", "")):
        fail(f"{path}: validate-merge-result must run only for pull_request events")
    merge_text = "\n".join(recursive_strings(merge_job))
    if "github.sha" not in merge_text:
        fail(f"{path}: validate-merge-result must bind to the synthetic merge SHA")
    if "test-plan-gate.sh" not in source_text or "test-plan-gate.sh" not in merge_text:
        fail(f"{path}: both exact-SHA jobs must exercise the reviewed plan-hash gate")


def validate_privileged_workflow(path: Path, workflow: dict[str, Any]) -> None:
    triggers = as_mapping(workflow.get("on"), f"{path}.on")
    if set(triggers) != {"workflow_dispatch"}:
        fail(f"{path}: privileged workflow must be workflow_dispatch-only")

    required_permissions = {"contents": "read"}
    if path.name in {"deploy.yml", "drift-review.yml"}:
        required_permissions["actions"] = "read"
    validate_permissions(workflow.get("permissions"), f"{path}.permissions", required_permissions)

    jobs = as_mapping(workflow.get("jobs"), f"{path}.jobs")
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
        validate_steps(job, f"{path}.jobs.{job_name}")
    if not found_self_hosted and path.name != "drift-review.yml":
        fail(f"{path}: privileged workflow must contain a protected self-hosted job")
    if path.name == "drift-review.yml":
        review_job = as_mapping(jobs.get("review"), f"{path}.jobs.review")
        if "environment" not in review_job:
            fail(f"{path}: drift review must use a protected Environment")

    workflow_text = "\n".join(recursive_strings(workflow))
    if "refs/heads/main" not in workflow_text:
        fail(f"{path}: privileged workflow must enforce refs/heads/main")
    if "confirm_sha" not in workflow_text:
        fail(f"{path}: privileged workflow must require exact SHA confirmation")
    if "--expected-deploy-sha" not in workflow_text:
        fail(f"{path}: runtime verification must receive the selected GitHub SHA")

    if path.name == "deploy.yml":
        dispatch = as_mapping(triggers["workflow_dispatch"], f"{path}.on.workflow_dispatch")
        inputs = as_mapping(dispatch.get("inputs"), f"{path}.on.workflow_dispatch.inputs")
        required_inputs = {
            "environment",
            "mode",
            "confirm_sha",
            "plan_run_id",
            "approved_plan_sha256",
            "review_run_id",
            "approved_review_sha256",
        }
        if not required_inputs.issubset(inputs):
            fail(f"{path}: missing plan-gate inputs: {sorted(required_inputs - set(inputs))}")
        for required_fragment in (
            "actions/download-artifact",
            "approved_plan_sha256",
            "plan_run_id",
            "apply-plan.sh",
            "keycloak-plan-",
            "keycloak-drift-review-",
            "approved_review_sha256",
        ):
            if required_fragment not in workflow_text:
                fail(f"{path}: reviewed plan gate is incomplete; missing {required_fragment}")
    elif path.name == "drift-review.yml":
        for required_fragment in (
            "plan_run_id",
            "approved_plan_sha256",
            "change_author_id",
            "review-plan.sh",
            "keycloak-drift-review-",
        ):
            if required_fragment not in workflow_text:
                fail(f"{path}: independent drift-review gate is incomplete; missing {required_fragment}")


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
