#!/usr/bin/env python3
"""Fail-closed validation for the repository-owned production contract."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / ".codestra/production-orchestrator-contract.v1.json"
INTENT_PATH = ROOT / ".github/workflows/manual-release-intent.yml"
RELEASE_VALIDATOR_PATH = ROOT / ".codestra/validate-release-intent.py"
SCHEMA = "codestra.production-orchestrator-contract.v1"
PHASES = ["plan", "staging", "canary", "production"]
SAFETY_KEYS = {
    "external_effects_default",
    "live_email_delivery",
    "live_sms_delivery",
    "live_pstn_dialing",
    "odoo_write",
    "n8n_external_delivery",
    "live_trading",
    "payment_execution",
}
ACTION_USE = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)")
ALLOWED_ACTIONS = {
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",
}
RUNTIME_TOOLS = {
    "ansible-playbook",
    "docker",
    "helm",
    "kubectl",
    "podman",
    "scp",
    "ssh",
    "terraform",
    "tofu",
}
KUBECTL_MUTATIONS = {"apply", "delete", "patch", "replace", "set"}
HELM_MUTATIONS = {"install", "upgrade", "uninstall"}


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def require_mapping(value: object, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(message)
    return value


def require_string_list(value: object, message: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise ContractError(message)
    if nonempty and not value:
        raise ContractError(message)
    if not all(isinstance(item, str) and item for item in value):
        raise ContractError(message)
    return [item for item in value if isinstance(item, str)]


def load_contract() -> dict[str, Any]:
    require(CONTRACT_PATH.is_file() and not CONTRACT_PATH.is_symlink(), "contract is missing or unsafe")
    value = json.loads(
        CONTRACT_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
    )
    require(isinstance(value, dict), "contract must be a JSON object")
    return value


def workflow_jobs(workflow: str, path: str) -> dict[str, str]:
    """Parse the constrained GitHub Actions jobs mapping by indentation."""
    lines = workflow.splitlines()
    jobs_indexes = [index for index, line in enumerate(lines) if line == "jobs:"]
    require(len(jobs_indexes) == 1, f"workflow has invalid jobs section: {path}")
    start = jobs_indexes[0] + 1
    headings: list[tuple[int, str]] = []
    for index in range(start, len(lines)):
        line = lines[index]
        if line and not line.startswith(" ") and not line.lstrip().startswith("#"):
            break
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
        if match:
            headings.append((index, match.group(1)))
    require(bool(headings), f"workflow has no jobs: {path}")
    jobs: dict[str, str] = {}
    for position, (index, name) in enumerate(headings):
        end = headings[position + 1][0] if position + 1 < len(headings) else len(lines)
        require(name not in jobs, f"workflow contains duplicate job: {path}")
        jobs[name] = "\n".join(lines[index:end]) + "\n"
    return jobs


def workflow_steps(job: str, path: str) -> list[dict[str, Any]]:
    """Parse executable step properties without accepting marker text in comments."""
    lines = job.splitlines()
    steps_indexes = [index for index, line in enumerate(lines) if line == "    steps:"]
    if not steps_indexes:
        return []
    require(len(steps_indexes) == 1, f"job has invalid steps section: {path}")
    start = steps_indexes[0] + 1
    indexes = [
        index
        for index in range(start, len(lines))
        if re.match(r"^      -(?:\s|$)", lines[index])
    ]
    steps: list[dict[str, Any]] = []
    for position, index in enumerate(indexes):
        end = indexes[position + 1] if position + 1 < len(indexes) else len(lines)
        block = lines[index:end]
        step: dict[str, Any] = {"env": {}, "with": {}}
        active_mapping: str | None = None
        first = re.match(r"^      -\s*([A-Za-z0-9_-]+):\s*(.*?)\s*$", block[0])
        if first:
            step[first.group(1)] = first.group(2)
        line_index = 1
        while line_index < len(block):
            line = block[line_index]
            item = re.match(r"^        ([A-Za-z0-9_-]+):(?:\s*(.*?))?\s*$", line)
            if item:
                key, value = item.group(1), item.group(2) or ""
                active_mapping = key if key in {"env", "with"} and not value else None
                if active_mapping:
                    line_index += 1
                    continue
                if key == "run" and value in {"|", "|-", ">", ">-"}:
                    script: list[str] = []
                    line_index += 1
                    while line_index < len(block):
                        script_line = block[line_index]
                        if script_line and len(script_line) - len(script_line.lstrip()) <= 8:
                            break
                        script.append(
                            script_line[10:]
                            if script_line.startswith("          ")
                            else script_line.lstrip()
                        )
                        line_index += 1
                    step[key] = "\n".join(script)
                    continue
                step[key] = value.split(" #", 1)[0].rstrip()
            else:
                child = re.match(r"^          ([A-Za-z0-9_-]+):\s*(.*?)\s*$", line)
                if child and active_mapping:
                    step[active_mapping][child.group(1)] = (
                        child.group(2).split(" #", 1)[0].rstrip()
                    )
            line_index += 1
        steps.append(step)
    return steps


def shell_tokens(script: str) -> list[str]:
    try:
        lexer = shlex.shlex(script, posix=True, punctuation_chars="|&;()")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError as exc:
        raise ContractError("workflow contains an invalid shell command") from exc


def executable_name(token: str) -> str:
    return token.strip("(){}[]").rsplit("/", 1)[-1]


def contains_runtime_command(script: str) -> bool:
    names = [executable_name(token) for token in shell_tokens(script)]
    return any(
        name in RUNTIME_TOOLS
        or name.endswith("deploy_immutable")
        or name.endswith("apply-plan.sh")
        for name in names
    )


def contains_runtime_mutation(script: str) -> bool:
    names = [executable_name(token) for token in shell_tokens(script)]
    for index, name in enumerate(names):
        tail = names[index + 1 : index + 12]
        if name == "scp":
            return True
        if name == "kubectl" and any(item in KUBECTL_MUTATIONS for item in tail):
            return True
        if name == "helm" and any(item in HELM_MUTATIONS for item in tail):
            return True
        if name == "docker" and "compose" in tail and "up" in tail:
            return True
        if name.endswith("deploy_immutable") or name.endswith("apply-plan.sh"):
            return True
    return False


def job_condition(job: str) -> str | None:
    for line in job.splitlines()[1:]:
        match = re.match(r"^    ([A-Za-z0-9_-]+):\s*(.*?)\s*$", line)
        if not match:
            continue
        key, value = match.groups()
        if key == "if":
            return value
        if key == "steps":
            break
    return None


def workflow_has_runtime_command(workflow: str, path: str) -> bool:
    return any(
        contains_runtime_command(str(step.get("run", "")))
        for job in workflow_jobs(workflow, path).values()
        for step in workflow_steps(job, path)
    )


def workflow_has_runtime_mutation(workflow: str, path: str) -> bool:
    return any(
        contains_runtime_mutation(str(step.get("run", "")))
        for job in workflow_jobs(workflow, path).values()
        for step in workflow_steps(job, path)
    )


def validate_intent_source_binding(intent: str) -> None:
    jobs = workflow_jobs(intent, ".github/workflows/manual-release-intent.yml")
    require("verify" in jobs, "release-intent verify job is missing")
    steps = workflow_steps(jobs["verify"], ".github/workflows/manual-release-intent.yml")
    checkout_indexes = [
        index
        for index, step in enumerate(steps)
        if isinstance(step.get("uses"), str)
        and step["uses"].startswith("actions/checkout@")
    ]
    require(len(checkout_indexes) == 1, "release-intent must have one exact checkout step")
    checkout_index = checkout_indexes[0]
    checkout = steps[checkout_index]
    require(
        checkout["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "release-intent checkout action is not pinned",
    )
    require(
        checkout["with"].get("ref") == "${{ github.sha }}",
        "release-intent checkout is not bound to the workflow commit",
    )
    require(
        checkout["with"].get("persist-credentials") == "false",
        "release-intent checkout persists credentials",
    )
    precheck_indexes = [
        index
        for index, step in enumerate(steps)
        if step.get("name")
        == "Verify dispatched source is current protected head before checkout"
    ]
    require(len(precheck_indexes) == 1, "release-intent protected-head precheck is missing")
    require(precheck_indexes[0] < checkout_index, "release-intent checks out before validating the protected head")
    precheck = steps[precheck_indexes[0]]
    require(
        precheck["env"].get("GH_TOKEN") == "${{ github.token }}"
        and precheck["env"].get("EVENT_SHA") == "${{ github.sha }}"
        and precheck["env"].get("REQUESTED_SOURCE_SHA") == "${{ inputs.source_sha }}",
        "release-intent protected-head precheck environment is not exact",
    )
    commands = {
        line.strip()
        for line in str(precheck.get("run", "")).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    required_commands = {
        'test "$GITHUB_REF" = "refs/heads/main"',
        'test "$EVENT_SHA" = "$REQUESTED_SOURCE_SHA"',
        'branch="$(gh api "repos/${GITHUB_REPOSITORY}" --jq .default_branch)"',
        'test "$branch" = "main"',
        'head="$(gh api "repos/${GITHUB_REPOSITORY}/branches/${branch}" --jq .commit.sha)"',
        'test "$head" = "$EVENT_SHA"',
    }
    require(
        required_commands <= commands,
        "release-intent protected-head precheck is incomplete",
    )


def validate(contract: dict[str, Any]) -> None:
    repository = os.environ.get("GITHUB_REPOSITORY", contract.get("repository", ""))
    repository_id_text = os.environ.get("GITHUB_REPOSITORY_ID")
    require(contract.get("schema_version") == SCHEMA, "contract schema mismatch")
    require(contract.get("repository") == repository, "repository identity mismatch")
    if repository_id_text:
        require(repository_id_text.isdigit(), "GITHUB_REPOSITORY_ID is invalid")
        require(contract.get("repository_id") == int(repository_id_text), "stable repository ID mismatch")
    else:
        require(isinstance(contract.get("repository_id"), int), "stable repository ID is missing")
    require(contract.get("default_branch") == "main", "default branch must be main")
    require(contract.get("release_intent_workflow") == ".github/workflows/manual-release-intent.yml", "intent workflow mismatch")
    require(contract.get("require_verified_commit") is True, "verified commits must be required")
    require(contract.get("required_check_app_id") == 15368, "required checks must be bound to GitHub Actions")
    require(isinstance(contract.get("role"), str) and contract["role"], "role is missing")

    checks = require_string_list(
        contract.get("required_checks"),
        "at least one exact-head check is required",
        nonempty=True,
    )
    require(len(checks) == len(set(checks)), "required checks contain duplicates")

    deployment_authority = contract.get("deployment_authority") is True
    runtime_mutation_authority = contract.get("runtime_mutation_authority")
    if not isinstance(runtime_mutation_authority, bool):
        raise ContractError("runtime mutation authority must be boolean")
    require(
        runtime_mutation_authority is (contract.get("role") == "infrastructure"),
        "only the infrastructure repository may hold runtime mutation authority",
    )
    supported = contract.get("supported_phases")
    if deployment_authority:
        require(supported == PHASES, "deployment authority must support the normalized phase sequence")
    else:
        require(supported == ["plan"], "non-deployment authority must be plan-only")

    artifacts = require_mapping(contract.get("artifact_policy"), "artifact policy is missing")
    minimum = artifacts.get("minimum_images")
    maximum = artifacts.get("maximum_images")
    if not isinstance(minimum, int) or not isinstance(maximum, int):
        raise ContractError("image bounds must be integers")
    require(0 <= minimum <= maximum, "image bounds are invalid")
    require(minimum == maximum, "contract must declare an exact image count")
    repositories = require_string_list(
        artifacts.get("image_repositories"),
        "image repositories must match the exact image count",
    )
    require(len(repositories) == maximum, "image repositories must match the exact image count")
    require(len(repositories) == len(set(repositories)), "image repositories contain duplicates")
    require(
        all(
            isinstance(item, str)
            and re.fullmatch(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+", item)
            for item in repositories
        ),
        "image repository is invalid",
    )
    require(artifacts.get("require_digest") is True, "digest-only images are mandatory")
    require(artifacts.get("allow_rebuild_after_staging") is False, "rebuild after staging is forbidden")
    require(artifacts.get("allow_retag_after_staging") is False, "retag after staging is forbidden")
    for field in ("require_sbom", "require_provenance", "require_signature"):
        require(type(artifacts.get(field)) is bool, f"{field} must be boolean")
    supply_chain_required = any(
        artifacts[field]
        for field in ("require_sbom", "require_provenance", "require_signature")
    )
    if supply_chain_required:
        require(artifacts.get("attestation_verifier") in {"github", "cosign"}, "attestation verifier is missing")
        require(artifacts.get("attestation_storage") in {"github", "oci"}, "attestation storage is missing")
        require(
            artifacts.get("attestation_verifier") != "cosign" or artifacts.get("attestation_storage") == "oci",
            "Cosign attestations must use OCI storage",
        )
        signer_workflow = artifacts.get("signer_workflow")
        require(
            isinstance(signer_workflow, str)
            and signer_workflow.startswith(".github/workflows/")
            and signer_workflow.endswith((".yml", ".yaml"))
            and (ROOT / signer_workflow).is_file(),
            "signer workflow is missing or invalid",
        )
    if contract.get("role") == "canonical-middleware":
        require(
            artifacts.get("require_sbom") is True
            and artifacts.get("require_provenance") is True
            and artifacts.get("require_signature") is True
            and artifacts.get("attestation_verifier") == "cosign",
            "canonical middleware supply-chain requirements cannot be downgraded",
        )

    environments = require_mapping(contract.get("environments"), "environment policy is missing")
    expected_environments = {
        "staging": "staging-readonly",
        "canary": "production-readonly-canary",
        "production": "production",
    }
    require(
        environments == expected_environments if deployment_authority else environments == {},
        "protected environment policy mismatch",
    )

    safety = require_mapping(contract.get("safety"), "safety controls are missing")
    require(set(safety) == SAFETY_KEYS, "safety controls are incomplete or unexpected")
    require(all(value is False for value in safety.values()), "every external/live effect must remain disabled")

    native = require_mapping(contract.get("native_workflows"), "native workflow policy must be an object")
    for value in native.values():
        require(isinstance(value, str) and value.startswith(".github/workflows/") and value.endswith((".yml", ".yaml")), "native workflow path is invalid")
        path = ROOT / value
        require(path.is_file() and not path.is_symlink(), f"native workflow is missing or unsafe: {value}")
        workflow = path.read_text(encoding="utf-8")
        if runtime_mutation_authority is False and workflow_has_runtime_mutation(workflow, value):
            require_mutating_jobs_disabled(workflow, value)

    require_string_list(contract.get("blockers"), "blockers must be non-empty strings")

    require(INTENT_PATH.is_file() and not INTENT_PATH.is_symlink(), "manual release-intent workflow is missing or unsafe")
    require(RELEASE_VALIDATOR_PATH.is_file() and not RELEASE_VALIDATOR_PATH.is_symlink(), "release-intent validator is missing or unsafe")
    intent = INTENT_PATH.read_text(encoding="utf-8")
    release_validator = RELEASE_VALIDATOR_PATH.read_text(encoding="utf-8")
    for marker in (
        "runtime_contacted\": False",
        "production_changed\": False",
        "external_effects_enabled\": False",
        "[\"git\", \"rev-parse\", \"HEAD\"]",
        "required checks are not app-bound",
        "prior evidence hash mismatch",
        "--source-digest",
    ):
        require(marker in release_validator, f"release-intent safety marker is missing: {marker}")
    for marker in (
        "persist-credentials: false",
        "prior_evidence_run_id:",
        "protected_environment_approved == false",
        "protected_environment_job_completed = true",
    ):
        require(marker in intent, f"release-intent workflow marker is missing: {marker}")
    validate_intent_source_binding(intent)
    require(
        not workflow_has_runtime_command(intent, ".github/workflows/manual-release-intent.yml"),
        "release-intent workflow contains a runtime/deployment command",
    )
    actions = ACTION_USE.findall(intent)
    require(bool(actions) and set(actions) <= ALLOWED_ACTIONS, "release-intent workflow uses a non-allowlisted action")


def validate_negative_regressions(contract: dict[str, Any]) -> None:
    mutations = []

    missing_check = deepcopy(contract)
    missing_check["required_checks"] = []
    mutations.append(("missing required checks", missing_check))

    wrong_check_app = deepcopy(contract)
    wrong_check_app["required_check_app_id"] = 1
    mutations.append(("wrong required-check app", wrong_check_app))

    mutable_retag = deepcopy(contract)
    mutable_retag["artifact_policy"]["allow_retag_after_staging"] = True
    mutations.append(("mutable retag", mutable_retag))

    incomplete_images = deepcopy(contract)
    incomplete_images["artifact_policy"]["minimum_images"] = (
        incomplete_images["artifact_policy"]["maximum_images"] + 1
    )
    mutations.append(("invalid image bounds", incomplete_images))

    wrong_repositories = deepcopy(contract)
    wrong_repositories["artifact_policy"]["image_repositories"] = [
        "ghcr.io/example/wrong"
    ] * (wrong_repositories["artifact_policy"]["maximum_images"] + 1)
    mutations.append(("incorrect image repositories", wrong_repositories))

    live_effect = deepcopy(contract)
    live_effect["safety"]["payment_execution"] = True
    mutations.append(("enabled live effect", live_effect))

    phase_escalation = deepcopy(contract)
    phase_escalation["deployment_authority"] = False
    phase_escalation["supported_phases"] = PHASES
    mutations.append(("non-authority phase escalation", phase_escalation))

    runtime_escalation = deepcopy(contract)
    runtime_escalation["runtime_mutation_authority"] = not runtime_escalation["runtime_mutation_authority"]
    mutations.append(("runtime mutation authority contradiction", runtime_escalation))

    missing_native = deepcopy(contract)
    missing_native["native_workflows"] = {
        "invalid": ".github/workflows/does-not-exist.yml"
    }
    mutations.append(("missing native workflow", missing_native))

    if any(
        contract["artifact_policy"][field]
        for field in ("require_sbom", "require_provenance", "require_signature")
    ):
        supply_chain_downgrade = deepcopy(contract)
        supply_chain_downgrade["artifact_policy"]["attestation_verifier"] = "none"
        mutations.append(("supply-chain verifier downgrade", supply_chain_downgrade))

    for name, mutation in mutations:
        try:
            validate(mutation)
        except ContractError:
            continue
        raise ContractError(f"negative regression unexpectedly passed: {name}")


def validate_intent_negative_regressions() -> None:
    intent = INTENT_PATH.read_text(encoding="utf-8")
    unsafe_intents = (
        intent.replace(
            "ref: ${{ github.sha }}",
            "ref: ${{ inputs.source_sha }}",
            1,
        ),
        intent.replace(
            "ref: ${{ github.sha }}",
            "ref: ${{ inputs['source_sha'] }}",
            1,
        ),
        intent.replace(
            "          ref: ${{ github.sha }}",
            "          # ref: ${{ github.sha }}\n          ref: ${{ inputs.source_sha }}",
            1,
        ),
        intent.replace(
            '          test "$EVENT_SHA" = "$REQUESTED_SOURCE_SHA"',
            '          # test "$EVENT_SHA" = "$REQUESTED_SOURCE_SHA"',
            1,
        ),
    )
    for unsafe in unsafe_intents:
        try:
            validate_intent_source_binding(unsafe)
        except ContractError:
            continue
        raise ContractError("negative regression unexpectedly passed: unsafe source binding")
    for command in (
        "helm upgrade release chart",
        "kubectl apply -f runtime.yml",
        "terraform apply",
        "./apply-plan.sh",
        "command docker pull example.invalid/image",
        'echo "$TOKEN" | docker login ghcr.io',
    ):
        require(
            contains_runtime_command(command),
            f"negative runtime command regression passed: {command}",
        )
    require(
        not contains_runtime_command("# docker pull example.invalid/image"),
        "comment-only runtime command was treated as executable",
    )
    enabled_mutation = """name: synthetic
jobs:
  deploy:
    # RUNTIME_MUTATION_DISABLED=true
    runs-on: ubuntu-24.04
    steps:
      - run: kubectl apply -f runtime.yml
"""
    try:
        require_mutating_jobs_disabled(enabled_mutation, "synthetic.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: enabled mutating job")


def require_mutating_jobs_disabled(workflow: str, path: str) -> None:
    mutating_jobs = 0
    for job in workflow_jobs(workflow, path).values():
        if any(
            contains_runtime_mutation(str(step.get("run", "")))
            for step in workflow_steps(job, path)
        ):
            mutating_jobs += 1
            require("RUNTIME_MUTATION_DISABLED=true" in job, f"mutating job lacks disable marker: {path}")
            require(
                job_condition(job) == "${{ false }}",
                f"mutating job is not unconditionally disabled: {path}",
            )
    require(mutating_jobs > 0, f"native mutation classification drift: {path}")


def main() -> int:
    contract = load_contract()
    validate(contract)
    validate_negative_regressions(contract)
    validate_intent_negative_regressions()
    subprocess.run(
        ["python3", str(RELEASE_VALIDATOR_PATH), "--self-test"],
        cwd=ROOT,
        check=True,
    )
    expected_sha = os.environ.get("EXPECTED_SHA")
    if expected_sha:
        require(re.fullmatch(r"[0-9a-f]{40}", expected_sha) is not None, "expected source SHA is invalid")
        actual_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        require(actual_sha == expected_sha, "contract validation checkout is not the exact event source")
    print("PRODUCTION_ORCHESTRATOR_CONTRACT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
