#!/usr/bin/env python3
"""Validate a normalized release intent without contacting any runtime."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.error
import urllib.request
import zipfile
from copy import deepcopy
from email.message import Message
from pathlib import Path
from typing import Any


CONTRACT_PATH = Path(".codestra/production-orchestrator-contract.v1.json")
SCHEMA = "codestra.production-orchestrator-contract.v1"
WORKFLOW = ".github/workflows/manual-release-intent.yml"
CONTROLLER_REPOSITORY = "appolon1908-hue/codestra-production-platform"
CONTROLLER_BRANCH = "release/production-activation"
CANDIDATE_SCHEMA = "codestra.manual-production-candidate.v1"
ZERO64 = "0" * 64
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{5,127}$")
IMAGE = re.compile(r"^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$")
IMAGE_REPOSITORY = re.compile(r"^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+$")
CONFIRMATIONS = {
    "plan": "PLAN_RELEASE_INTENT",
    "staging": "APPROVE_STAGING_INTENT",
    "canary": "APPROVE_CANARY_INTENT",
    "production": "APPROVE_PRODUCTION_INTENT",
}
PREVIOUS_PHASE = {"staging": "plan", "canary": "staging", "production": "canary"}
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
CANDIDATE_SAFETY_KEYS = (SAFETY_KEYS - {"external_effects_default"}) | {
    "external_effects_enabled"
}
CATALOG_REPOSITORIES = {
    "appolon1908-hue/Infustruction-repo",
    "appolon1908-hue/Keycloak",
    "appolon1908-hue/Middleware-",
    "appolon1908-hue/codestra",
    "appolon1908-hue/beyvra-backend",
    "appolon1908-hue/backend2",
    "appolon1908-hue/beyvra-frontend",
    "appolon1908-hue/scrapper",
    "appolon1908-hue/Breero.com",
    "appolon1908-hue/Moneybee-Backend",
    "appolon1908-hue/Telnexa-web",
    CONTROLLER_REPOSITORY,
}


class PolicyError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


NO_REDIRECT_OPENER: Any = urllib.request.build_opener(NoRedirectHandler())


def api_request(
    endpoint: str,
    *,
    accept: str = "application/vnd.github+json",
    administration: bool = False,
) -> tuple[bytes, str | None]:
    url = endpoint if endpoint.startswith("https://") else f"https://api.github.com/{endpoint.lstrip('/')}"
    parsed = urllib.parse.urlparse(url)
    require(parsed.scheme == "https" and parsed.hostname == "api.github.com", "refusing non-GitHub API URL")
    token_name = "CODESTRA_ORCHESTRATOR_TOKEN" if administration else "GH_TOKEN"
    token = os.environ.get(token_name, "")
    require(bool(token), f"{token_name} is required for repository policy evidence")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with NO_REDIRECT_OPENER.open(request, timeout=30) as response:
            return response.read(), response.headers.get("Link")
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise PolicyError("unexpected redirect from GitHub API") from error
        raise


def validate_artifact_storage_url(location: str) -> str:
    parsed = urllib.parse.urlparse(location)
    hostname = parsed.hostname or ""
    allowed_host = (
        hostname.endswith(".blob.core.windows.net")
        or hostname.endswith(".actions.githubusercontent.com")
        or hostname in {"objects.githubusercontent.com", "github-releases.githubusercontent.com"}
    )
    require(
        parsed.scheme == "https"
        and allowed_host
        and parsed.username is None
        and parsed.password is None
        and parsed.port in (None, 443)
        and bool(parsed.path)
        and not parsed.fragment,
        "artifact redirect target is not an approved HTTPS storage URL",
    )
    return location


def download_artifact_archive(endpoint: str) -> bytes:
    url = endpoint if endpoint.startswith("https://") else f"https://api.github.com/{endpoint.lstrip('/')}"
    parsed = urllib.parse.urlparse(url)
    require(parsed.scheme == "https" and parsed.hostname == "api.github.com", "refusing non-GitHub artifact API URL")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with NO_REDIRECT_OPENER.open(request, timeout=30):
            raise PolicyError("artifact API did not redirect to signed storage")
    except urllib.error.HTTPError as error:
        if error.code not in {301, 302, 303, 307, 308}:
            raise
        location = error.headers.get("Location", "")
        error.close()
    storage_url = validate_artifact_storage_url(location)
    storage_request = urllib.request.Request(storage_url, headers={"Accept": "application/zip"})
    with NO_REDIRECT_OPENER.open(storage_request, timeout=30) as response:
        archive = response.read(10_000_001)
    require(len(archive) <= 10_000_000, "prior artifact archive exceeds size limit")
    return archive


def next_link(header: str | None) -> str | None:
    if not header:
        return None
    for part in header.split(","):
        fields = [field.strip() for field in part.split(";")]
        if len(fields) >= 2 and 'rel="next"' in fields[1:]:
            require(fields[0].startswith("<") and fields[0].endswith(">"), "invalid pagination link")
            return fields[0][1:-1]
    return None


def api_json(endpoint: str, *, administration: bool = False) -> Any:
    raw, _ = api_request(endpoint, administration=administration)
    return json.loads(raw)


def api_pages(endpoint: str, *, administration: bool = False) -> list[Any]:
    pages: list[Any] = []
    seen: set[str] = set()
    current: str | None = endpoint
    while current is not None:
        require(current not in seen, "GitHub API pagination loop detected")
        seen.add(current)
        raw, link = api_request(current, administration=administration)
        pages.append(json.loads(raw))
        current = next_link(link)
    return pages


def bind_required_check(bindings: dict[str, int], name: object, app_id: object, expected_app_id: int) -> None:
    if not isinstance(name, str) or not name:
        raise PolicyError("invalid required check name")
    if not isinstance(app_id, int):
        raise PolicyError(f"required check {name} has no GitHub App binding")
    require(app_id == expected_app_id, f"required check {name} is not bound to the expected GitHub App")
    require(bindings.get(name) in (None, app_id), f"conflicting app bindings for required check {name}")
    bindings[name] = app_id


def required_check_bindings(branch: dict[str, Any], rules_pages: list[Any], expected_app_id: int) -> tuple[list[str], dict[str, int]]:
    policy = branch.get("protection", {}).get("required_status_checks", {})
    contexts = policy.get("contexts", [])
    checks = policy.get("checks", [])
    require(isinstance(contexts, list) and all(isinstance(name, str) and name for name in contexts), "invalid branch required check contexts")
    require(isinstance(checks, list), "invalid branch required check bindings")
    bindings: dict[str, int] = {}
    for item in checks:
        require(isinstance(item, dict), "invalid branch required check binding")
        bind_required_check(bindings, item.get("context"), item.get("app_id"), expected_app_id)
    ruleset_names: set[str] = set()
    for page in rules_pages:
        require(isinstance(page, list), "effective branch rules page is invalid")
        for rule in page:
            if isinstance(rule, dict) and rule.get("type") == "required_status_checks":
                ruleset_checks = rule.get("parameters", {}).get("required_status_checks", [])
                require(isinstance(ruleset_checks, list), "invalid ruleset required checks")
                for item in ruleset_checks:
                    require(isinstance(item, dict), "invalid ruleset required check binding")
                    name = item.get("context")
                    bind_required_check(bindings, name, item.get("integration_id"), expected_app_id)
                    ruleset_names.add(name)
    names = sorted(set(contexts) | ruleset_names)
    require(bool(names), "protected branch has no required checks")
    unbound = sorted(set(names) - set(bindings))
    require(not unbound, f"required checks are not app-bound by branch protection: {unbound}")
    return names, bindings


def latest_check_conclusions(check_pages: list[Any]) -> dict[tuple[str, int], str | None]:
    runs: list[dict[str, Any]] = []
    for page in check_pages:
        require(isinstance(page, dict) and isinstance(page.get("check_runs"), list), "check-runs page is invalid")
        runs.extend(page["check_runs"])
    latest: dict[tuple[str, int], str | None] = {}
    for item in sorted(runs, key=lambda row: row.get("completed_at") or row.get("started_at") or ""):
        name = item.get("name")
        app_id = item.get("app", {}).get("id")
        if isinstance(name, str) and isinstance(app_id, int):
            latest[(name, app_id)] = item.get("conclusion")
    return latest


def validate_environment_document(value: object, environment: str) -> None:
    if not isinstance(value, dict):
        raise PolicyError("protected environment is missing")
    require(value.get("name") == environment, "protected environment is missing")
    rules = value.get("protection_rules")
    if not isinstance(rules, list):
        raise PolicyError("protected environment rules are invalid")
    reviewer_rules = [
        item
        for item in rules
        if isinstance(item, dict) and item.get("type") == "required_reviewers"
    ]
    require(len(reviewer_rules) == 1, "protected environment must have one required-reviewer rule")
    reviewer_rule = reviewer_rules[0]
    reviewers = reviewer_rule.get("reviewers")
    if not isinstance(reviewers, list) or not reviewers:
        raise PolicyError("protected environment has no required reviewers")
    require(
        all(
            isinstance(item, dict)
            and item.get("type") in {"User", "Team"}
            and isinstance(item.get("reviewer"), dict)
            and isinstance(item["reviewer"].get("id"), int)
            for item in reviewers
        ),
        "protected environment reviewer identity is invalid",
    )
    require(reviewer_rule.get("prevent_self_review") is True, "protected environment permits self-review")
    branch_policy = value.get("deployment_branch_policy")
    require(
        isinstance(branch_policy, dict)
        and branch_policy.get("protected_branches") is True
        and branch_policy.get("custom_branch_policies") is False,
        "protected environment is not restricted to protected branches",
    )


def validate_environment_protection(repository: str, environment: str) -> None:
    encoded = urllib.parse.quote(environment, safe="")
    value = api_json(
        f"repos/{repository}/environments/{encoded}",
        administration=True,
    )
    validate_environment_document(value, environment)


def validate_repository_gates(
    contract: dict[str, Any],
    source_sha: str,
    phase: str,
    environment: str,
) -> tuple[list[str], dict[str, int]]:
    repository = os.environ["GITHUB_REPOSITORY"]
    branch_name = contract.get("default_branch")
    repository_data = api_json(f"repos/{repository}")
    require(repository_data.get("id") == contract.get("repository_id"), "stable repository ID mismatch")
    require(repository_data.get("default_branch") == branch_name, "default branch drift")
    require(repository_data.get("archived") is False and repository_data.get("disabled") is False, "repository unavailable")
    branch = api_json(f"repos/{repository}/branches/{branch_name}")
    require(branch.get("protected") is True, "default branch must be protected")
    require(branch.get("commit", {}).get("sha") == source_sha, "source SHA is not current protected branch head")
    if contract.get("require_verified_commit") is True:
        commit = api_json(f"repos/{repository}/commits/{source_sha}")
        require(commit.get("commit", {}).get("verification", {}).get("verified") is True, "exact source commit is not GitHub-verified")
    contract_checks = contract.get("required_checks")
    if not isinstance(contract_checks, list):
        raise PolicyError("invalid required_checks")
    require(all(isinstance(item, str) and item for item in contract_checks), "invalid required_checks")
    expected_app_id = contract.get("required_check_app_id")
    if not isinstance(expected_app_id, int) or expected_app_id <= 0:
        raise PolicyError("required check app ID is invalid")
    branch_checks, bindings = required_check_bindings(
        branch,
        api_pages(
            f"repos/{repository}/rules/branches/{branch_name}?per_page=100",
            administration=True,
        ),
        expected_app_id,
    )
    required_checks = sorted(set(contract_checks) | set(branch_checks))
    unbound = sorted(set(required_checks) - set(bindings))
    require(not unbound, f"contract checks are not app-bound by branch protection: {unbound}")
    latest = latest_check_conclusions(api_pages(f"repos/{repository}/commits/{source_sha}/check-runs?per_page=100"))
    missing = [name for name in required_checks if latest.get((name, bindings[name])) != "success"]
    require(not missing, f"required exact-head checks are not successful from the bound app: {missing}")
    if phase != "plan":
        require(bool(environment), f"{phase} protected environment is missing")
        validate_environment_protection(repository, environment)
    return required_checks, bindings


def validate_candidate_document(
    raw: bytes,
    expected_hash: str,
    release_id: str,
    repository: str,
    source_sha: str,
    contract_sha256: str,
    images: list[Any],
    previous_images: list[Any],
) -> dict[str, Any]:
    require(len(raw) <= 1_000_000, "candidate file exceeds size limit")
    require(hashlib.sha256(raw).hexdigest() == expected_hash, "candidate file SHA-256 mismatch")
    candidate = json.loads(raw)
    require(isinstance(candidate, dict), "candidate must be an object")
    require(candidate.get("schema_version") == CANDIDATE_SCHEMA, "candidate schema mismatch")
    require(candidate.get("template") is False, "template candidate cannot be admitted")
    require(candidate.get("release_id") == release_id, "candidate release ID mismatch")
    for field, pattern, zero in (
        ("controller_sha", SHA, "0" * 40),
        ("source_lock_sha", SHA, "0" * 40),
        ("runtime_candidate_sha256", DIGEST, ZERO64),
    ):
        value = candidate.get(field)
        require(isinstance(value, str) and pattern.fullmatch(value) is not None and value != zero, f"candidate {field} is invalid")
    safety = candidate.get("safety")
    require(isinstance(safety, dict) and set(safety) == CANDIDATE_SAFETY_KEYS, "candidate safety controls are incomplete or unexpected")
    require(all(value is False for value in safety.values()), "candidate enables an external/live effect")
    components = candidate.get("components")
    require(isinstance(components, list), "candidate components must be an array")
    by_repository: dict[str, dict[str, Any]] = {}
    for item in components:
        require(isinstance(item, dict), "candidate component must be an object")
        name = item.get("repository")
        require(isinstance(name, str) and name in CATALOG_REPOSITORIES, "candidate contains an unexpected repository")
        require(name not in by_repository, f"candidate contains duplicate repository: {name}")
        by_repository[name] = item
    require(set(by_repository) == CATALOG_REPOSITORIES, "candidate does not cover the exact protected catalog")
    require(
        by_repository[CONTROLLER_REPOSITORY].get("source_sha") == candidate["controller_sha"],
        "candidate controller policy-base binding mismatch",
    )
    component = by_repository[repository]
    require(component.get("enabled") is True, "candidate disables a required repository")
    require(component.get("source_sha") == source_sha, "candidate source SHA mismatch")
    require(component.get("contract_sha256") == contract_sha256, "candidate contract SHA-256 mismatch")
    require(component.get("images") == images, "candidate image input mismatch")
    require(component.get("previous_images") == previous_images, "candidate rollback image input mismatch")
    return candidate


def validate_phase_blockers(blockers: object, phase: str) -> list[str]:
    if not isinstance(blockers, list):
        raise PolicyError("contract blockers are invalid")
    require(all(isinstance(item, str) and item for item in blockers), "contract blockers are invalid")
    values = [item for item in blockers if isinstance(item, str)]
    if phase != "plan":
        require(not values, f"{phase} is blocked by unresolved contract blockers")
    return values


def download_and_validate_candidate(
    expected_hash: str,
    release_id: str,
    repository: str,
    source_sha: str,
    contract_sha256: str,
    images: list[Any],
    previous_images: list[Any],
) -> str:
    controller = api_json(f"repos/{CONTROLLER_REPOSITORY}", administration=True)
    require(controller.get("id") == 1314230781, "controller stable repository ID mismatch")
    require(controller.get("default_branch") == CONTROLLER_BRANCH, "controller protected branch drift")
    branch_name = urllib.parse.quote(CONTROLLER_BRANCH, safe="")
    branch = api_json(
        f"repos/{CONTROLLER_REPOSITORY}/branches/{branch_name}",
        administration=True,
    )
    controller_head = branch.get("commit", {}).get("sha")
    require(branch.get("protected") is True, "controller release branch is not protected")
    require(
        isinstance(controller_head, str)
        and SHA.fullmatch(controller_head) is not None,
        "controller protected head is invalid",
    )
    path = urllib.parse.quote(f"config/releases/{release_id}.json", safe="/")
    value = api_json(
        f"repos/{CONTROLLER_REPOSITORY}/contents/{path}?ref={controller_head}",
        administration=True,
    )
    require(
        isinstance(value, dict)
        and value.get("type") == "file"
        and value.get("encoding") == "base64"
        and isinstance(value.get("content"), str),
        "reviewed candidate file is missing or invalid",
    )
    try:
        raw = base64.b64decode("".join(value["content"].split()), validate=True)
    except ValueError as exc:
        raise PolicyError("reviewed candidate file is not valid base64") from exc
    validate_candidate_document(
        raw,
        expected_hash,
        release_id,
        repository,
        source_sha,
        contract_sha256,
        images,
        previous_images,
    )
    controller_sha = json.loads(raw).get("controller_sha")
    comparison = api_json(
        f"repos/{CONTROLLER_REPOSITORY}/compare/{controller_sha}...{controller_head}",
        administration=True,
    )
    require(
        isinstance(comparison, dict) and comparison.get("status") in {"ahead", "identical"},
        "candidate controller policy base is not an ancestor of its reviewed file",
    )
    return controller_head


def recheck_protected_gates() -> int:
    phase = os.environ["PHASE"]
    source_sha = os.environ["SOURCE_SHA"]
    release_id = os.environ["RELEASE_ID"]
    candidate_sha256 = os.environ["CANDIDATE_SHA256"]
    require(phase in PREVIOUS_PHASE, "post-approval recheck requires a protected phase")
    require(SHA.fullmatch(source_sha) is not None and source_sha != "0" * 40, "source_sha must be nonzero lowercase 40-hex")
    require(RELEASE.fullmatch(release_id) is not None, "invalid release_id")
    require(DIGEST.fullmatch(candidate_sha256) is not None and candidate_sha256 != ZERO64, "candidate_sha256 must be nonzero lowercase 64-hex")
    require(CONTRACT_PATH.is_file() and not CONTRACT_PATH.is_symlink(), "release contract is missing or unsafe")
    contract_bytes = CONTRACT_PATH.read_bytes()
    contract = json.loads(contract_bytes)
    require(isinstance(contract, dict) and contract.get("schema_version") == SCHEMA, "unexpected release contract schema")
    repository = os.environ["GITHUB_REPOSITORY"]
    require(contract.get("repository") == repository, "contract repository mismatch")
    branch_name = contract.get("default_branch")
    require(branch_name == os.environ["GITHUB_REF_NAME"] and os.environ["GITHUB_REF"] == f"refs/heads/{branch_name}", "workflow must run from the contract default branch")
    checkout_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(checkout_sha == source_sha, "checkout does not match source_sha")
    validate_phase_blockers(contract.get("blockers"), phase)
    environment = contract.get("environments", {}).get(phase, "")
    expected_environment = {
        "staging": "staging-readonly",
        "canary": "production-readonly-canary",
        "production": "production",
    }[phase]
    require(environment == expected_environment, f"{phase} protected environment mismatch")
    validate_repository_gates(contract, source_sha, phase, environment)
    try:
        images = json.loads(os.environ["IMAGES_JSON"])
        previous_images = json.loads(os.environ["PREVIOUS_IMAGES_JSON"])
    except json.JSONDecodeError as error:
        raise PolicyError(f"image input is not valid JSON: {error}") from error
    require(isinstance(images, list) and isinstance(previous_images, list), "image inputs must be arrays")
    download_and_validate_candidate(
        candidate_sha256,
        release_id,
        repository,
        source_sha,
        hashlib.sha256(contract_bytes).hexdigest(),
        images,
        previous_images,
    )
    print("PROTECTED_GATES_RECHECK=PASS")
    return 0


def validate_images(images: list[Any], previous_images: list[Any], policy: dict[str, Any]) -> list[str]:
    require(all(isinstance(item, str) and IMAGE.fullmatch(item) for item in images), "candidate images must be exact GHCR digests")
    require(all(isinstance(item, str) and IMAGE.fullmatch(item) for item in previous_images), "rollback images must be exact GHCR digests")
    require(len(images) == len(set(images)), "candidate image list contains duplicates")
    require(len(previous_images) == len(set(previous_images)), "rollback image list contains duplicates")
    minimum = policy.get("minimum_images")
    maximum = policy.get("maximum_images")
    if not isinstance(minimum, int) or not isinstance(maximum, int):
        raise PolicyError("contract image count must be integer")
    require(0 <= minimum == maximum, "contract must declare an exact image count")
    require(len(images) == maximum, "candidate image count violates contract")
    require(len(previous_images) == len(images), "rollback image count differs from candidate")
    if images:
        require(set(images) != set(previous_images), "rollback image set must differ from candidate image set")
    repository_value = policy.get("image_repositories")
    if not isinstance(repository_value, list):
        raise PolicyError("image repository policy must be an array")
    repositories = [item for item in repository_value if isinstance(item, str)]
    require(len(repositories) == len(repository_value), "image repository policy is invalid")
    require(len(repositories) == maximum, "image repository policy does not match the exact image count")
    require(len(repositories) == len(set(repositories)), "image repository policy contains duplicates")
    require(all(IMAGE_REPOSITORY.fullmatch(item) for item in repositories), "image repository policy is invalid")
    require(sorted(item.split("@", 1)[0] for item in images) == sorted(repositories), "candidate image repositories do not match the contract")
    require(sorted(item.split("@", 1)[0] for item in previous_images) == sorted(repositories), "rollback image repositories do not match the contract")
    return repositories


def validate_prior(prior: Any, expected: dict[str, Any]) -> None:
    require(isinstance(prior, dict), "prior evidence must be an object")
    for key, value in expected.items():
        require(prior.get(key) == value, f"prior evidence {key} mismatch")


def cosign_statements(raw: str) -> list[dict[str, Any]]:
    records: list[Any]
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    else:
        records = parsed if isinstance(parsed, list) else [parsed]
    statements: list[dict[str, Any]] = []
    for record in records:
        require(isinstance(record, dict) and isinstance(record.get("payload"), str), "cosign attestation output is invalid")
        statement = json.loads(base64.b64decode(record["payload"], validate=True))
        require(isinstance(statement, dict), "cosign attestation statement is invalid")
        statements.append(statement)
    require(bool(statements), "cosign did not return an attestation statement")
    return statements


def download_prior_evidence(repository: str, run_id: int, expected_name: str, expected_hash: str) -> dict[str, Any]:
    run = api_json(f"repos/{repository}/actions/runs/{run_id}")
    require(run.get("id") == run_id, "prior run identity mismatch")
    require(run.get("event") == "workflow_dispatch", "prior evidence run was not manually dispatched")
    require(run.get("status") == "completed" and run.get("conclusion") == "success", "prior evidence run is not successful")
    require(run.get("path") == WORKFLOW, "prior evidence run used a different workflow")
    artifacts: list[dict[str, Any]] = []
    for page in api_pages(f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"):
        require(isinstance(page, dict) and isinstance(page.get("artifacts"), list), "prior artifacts page is invalid")
        artifacts.extend(page["artifacts"])
    matches = [item for item in artifacts if item.get("name") == expected_name and item.get("expired") is False]
    require(len(matches) == 1, "prior release-intent artifact is missing, ambiguous, or expired")
    artifact = matches[0]
    require(artifact.get("workflow_run", {}).get("id") in (None, run_id), "prior artifact run binding mismatch")
    archive = download_artifact_archive(f"repos/{repository}/actions/artifacts/{artifact['id']}/zip")
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        require(bundle.namelist() == ["release-intent.json"], "prior artifact archive has unexpected contents")
        info = bundle.getinfo("release-intent.json")
        require(not info.is_dir() and info.file_size <= 1_000_000, "prior evidence file is invalid")
        prior_bytes = bundle.read(info)
    require(hashlib.sha256(prior_bytes).hexdigest() == expected_hash, "prior evidence hash mismatch")
    return json.loads(prior_bytes)


def verify_supply_chain(
    images: list[str],
    policy: dict[str, Any],
    repository: str,
    branch: str,
    source_sha: str,
    *,
    exact_source: bool,
) -> None:
    require_sbom = policy.get("require_sbom")
    require_provenance = policy.get("require_provenance")
    require_signature = policy.get("require_signature")
    require(all(type(value) is bool for value in (require_sbom, require_provenance, require_signature)), "supply-chain requirements must be boolean")
    if not (require_sbom or require_provenance or require_signature):
        return
    verifier = policy.get("attestation_verifier")
    storage = policy.get("attestation_storage")
    workflow = policy.get("signer_workflow")
    predicate_type = policy.get("provenance_predicate_type", "https://slsa.dev/provenance/v1")
    require(verifier in {"github", "cosign"}, "attestation verifier is missing")
    require(storage in {"github", "oci"}, "attestation storage is missing")
    require(verifier != "cosign" or storage == "oci", "Cosign attestations must use OCI storage")
    require(isinstance(workflow, str) and workflow.startswith(".github/workflows/") and workflow.endswith((".yml", ".yaml")), "signer workflow is invalid")
    require(isinstance(predicate_type, str) and predicate_type.startswith("https://"), "provenance predicate type is invalid")
    subprocess.run(
        ["docker", "login", "ghcr.io", "--username", os.environ["GITHUB_ACTOR"], "--password-stdin"],
        input=os.environ["GH_TOKEN"],
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    signer = f"{repository}/{workflow}"
    identity = f"https://github.com/{signer}@refs/heads/{branch}"
    common = ["--certificate-identity", identity, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"]
    for image in images:
        if verifier == "github":
            require(not require_signature, "GitHub-attestation policy cannot claim a standalone image signature")
            if require_provenance:
                command = [
                    "gh", "attestation", "verify", f"oci://{image}",
                    "--repo", repository,
                    "--signer-workflow", signer,
                    "--source-ref", f"refs/heads/{branch}",
                    "--predicate-type", predicate_type,
                    "--deny-self-hosted-runners",
                    "--format", "json",
                ]
                if exact_source:
                    command.extend(["--source-digest", source_sha])
                if storage == "oci":
                    command.append("--bundle-from-oci")
                raw = subprocess.check_output(command, text=True)
                require(bool(json.loads(raw)), f"provenance attestation is missing for {image}")
            if require_sbom:
                raw = subprocess.check_output(
                    ["docker", "buildx", "imagetools", "inspect", image, "--format", "{{ json .SBOM }}"],
                    text=True,
                )
                require(bool(json.loads(raw)), f"SBOM attestation is missing for {image}")
        else:
            if require_signature:
                command = ["cosign", "verify", *common]
                if exact_source:
                    command.extend(["--annotations", f"codestra.source_sha={source_sha}"])
                subprocess.run([*command, image], check=True, stdout=subprocess.DEVNULL)
            if require_sbom:
                subprocess.run(["cosign", "verify-attestation", "--type", "spdxjson", *common, image], check=True, stdout=subprocess.DEVNULL)
            if require_provenance:
                provenance = subprocess.check_output(
                    ["cosign", "verify-attestation", "--type", "slsaprovenance1", *common, image],
                    text=True,
                )
                statements = cosign_statements(provenance)
                source_commits = {
                    commit
                    for statement in statements
                    for dependency in statement.get("predicate", {}).get("buildDefinition", {}).get("resolvedDependencies", [])
                    if isinstance(dependency, dict)
                    for commit in [dependency.get("digest", {}).get("gitCommit")]
                    if isinstance(commit, str) and SHA.fullmatch(commit)
                }
                if exact_source:
                    require(
                        source_sha in source_commits,
                        f"signed provenance does not bind source SHA for {image}",
                    )
                else:
                    require(
                        bool(source_commits),
                        f"rollback provenance does not bind a source SHA for {image}",
                    )


def main() -> int:
    phase = os.environ["PHASE"]
    source_sha = os.environ["SOURCE_SHA"]
    release_id = os.environ["RELEASE_ID"]
    candidate_sha256 = os.environ["CANDIDATE_SHA256"]
    prior_hash = os.environ["PRIOR_EVIDENCE_SHA256"]
    prior_run_text = os.environ["PRIOR_EVIDENCE_RUN_ID"]
    require(phase in CONFIRMATIONS, "unsupported release phase")
    require(os.environ["CONFIRMATION"] == CONFIRMATIONS[phase], "confirmation mismatch")
    require(SHA.fullmatch(source_sha) is not None and source_sha != "0" * 40, "source_sha must be nonzero lowercase 40-hex")
    require(DIGEST.fullmatch(candidate_sha256) is not None and candidate_sha256 != ZERO64, "candidate_sha256 must be nonzero lowercase 64-hex")
    require(DIGEST.fullmatch(prior_hash) is not None, "prior evidence must be lowercase 64-hex")
    require(prior_run_text.isdigit(), "prior evidence run ID must be decimal")
    require(RELEASE.fullmatch(release_id) is not None, "invalid release_id")
    prior_run_id = int(prior_run_text)
    if phase == "plan":
        require(prior_hash == ZERO64 and prior_run_id == 0, "plan must use zero prior evidence")
    else:
        require(prior_hash != ZERO64 and prior_run_id > 0, f"{phase} requires prior-phase evidence")
        require(prior_run_text != os.environ["GITHUB_RUN_ID"], "prior evidence cannot come from the current run")

    require(CONTRACT_PATH.is_file() and not CONTRACT_PATH.is_symlink(), "release contract is missing or unsafe")
    contract_bytes = CONTRACT_PATH.read_bytes()
    contract = json.loads(contract_bytes)
    repository = os.environ["GITHUB_REPOSITORY"]
    require(isinstance(contract, dict) and contract.get("schema_version") == SCHEMA, "unexpected release contract schema")
    require(contract.get("repository") == repository, "contract repository mismatch")
    require(contract.get("release_intent_workflow") == WORKFLOW, "contract workflow mismatch")
    branch_name = contract.get("default_branch")
    require(branch_name == os.environ["GITHUB_REF_NAME"] and os.environ["GITHUB_REF"] == f"refs/heads/{branch_name}", "workflow must run from the contract default branch")
    checkout_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(checkout_sha == source_sha, "checkout does not match source_sha")
    require(not subprocess.check_output(["git", "status", "--porcelain"], text=True).strip(), "workspace is dirty")

    supported = contract.get("supported_phases")
    require(isinstance(supported, list) and phase in supported, f"phase {phase} is not supported")
    deployment_authority = contract.get("deployment_authority") is True
    if phase != "plan":
        require(deployment_authority, "repository is not a deployment authority")
    blockers = validate_phase_blockers(contract.get("blockers"), phase)
    environment = ""
    if phase != "plan":
        environment = contract.get("environments", {}).get(phase, "")
        expected_environment = {"staging": "staging-readonly", "canary": "production-readonly-canary", "production": "production"}[phase]
        require(environment == expected_environment, f"{phase} protected environment mismatch")
    required_checks, bindings = validate_repository_gates(
        contract,
        source_sha,
        phase,
        environment,
    )

    try:
        images = json.loads(os.environ["IMAGES_JSON"])
        previous_images = json.loads(os.environ["PREVIOUS_IMAGES_JSON"])
    except json.JSONDecodeError as error:
        raise PolicyError(f"image input is not valid JSON: {error}") from error
    require(isinstance(images, list) and isinstance(previous_images, list), "image inputs must be arrays")
    policy = contract.get("artifact_policy")
    require(isinstance(policy, dict), "artifact_policy must be an object")
    require(policy.get("require_digest") is True, "digest-only artifacts are required")
    require(policy.get("allow_rebuild_after_staging") is False, "rebuild after staging must remain forbidden")
    require(policy.get("allow_retag_after_staging") is False, "retag after staging must remain forbidden")
    validate_images(images, previous_images, policy)
    contract_sha256 = hashlib.sha256(contract_bytes).hexdigest()
    controller_candidate_head = download_and_validate_candidate(
        candidate_sha256,
        release_id,
        repository,
        source_sha,
        contract_sha256,
        images,
        previous_images,
    )
    verify_supply_chain(images, policy, repository, branch_name, source_sha, exact_source=True)
    verify_supply_chain(previous_images, policy, repository, branch_name, source_sha, exact_source=False)

    safety = contract.get("safety")
    require(isinstance(safety, dict) and SAFETY_KEYS <= set(safety), "safety contract is incomplete")
    require(all(safety.get(key) is False for key in SAFETY_KEYS), "every external/live effect must remain disabled")
    if phase != "plan":
        previous_phase = PREVIOUS_PHASE[phase]
        prior = download_prior_evidence(repository, prior_run_id, f"codestra-release-intent-{previous_phase}-{source_sha}", prior_hash)
        run = api_json(f"repos/{repository}/actions/runs/{prior_run_id}")
        require(run.get("head_sha") == source_sha, "prior evidence run used a different source SHA")
        validate_prior(
            prior,
            {
                "schema_version": "codestra.normalized-release-intent.v1",
                "repository": repository,
                "repository_id": contract["repository_id"],
                "phase": previous_phase,
                "release_id": release_id,
                "source_sha": source_sha,
                "candidate_sha256": candidate_sha256,
                "candidate_images": images,
                "previous_images": previous_images,
                "runtime_contacted": False,
                "production_changed": False,
                "external_effects_enabled": False,
                "protected_environment_approved": False,
                "protected_environment_job_completed": previous_phase != "plan",
                "status": "PASS",
            },
        )

    evidence = {
        "schema_version": "codestra.normalized-release-intent.v1",
        "repository": repository,
        "repository_id": contract["repository_id"],
        "role": contract["role"],
        "phase": phase,
        "release_id": release_id,
        "source_sha": source_sha,
        "candidate_sha256": candidate_sha256,
        "prior_evidence_sha256": prior_hash,
        "prior_evidence_run_id": prior_run_id,
        "contract_sha256": contract_sha256,
        "controller_candidate_head_sha": controller_candidate_head,
        "contract_blockers": blockers,
        "required_checks": required_checks,
        "required_check_apps": {name: bindings[name] for name in required_checks},
        "candidate_images": images,
        "previous_images": previous_images,
        "deployment_authority": deployment_authority,
        "protected_environment": environment or None,
        "protected_environment_approved": False,
        "protected_environment_job_completed": False,
        "runtime_contacted": False,
        "production_changed": False,
        "external_effects_enabled": False,
        "status": "PASS",
    }
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        stream.write(f"environment={environment}\n")
        stream.write(f"deployment_authority={str(deployment_authority).lower()}\n")
        stream.write(f"evidence_b64={base64.b64encode(encoded).decode()}\n")
        stream.write(f"evidence_sha256={hashlib.sha256(encoded).hexdigest()}\n")
    return 0


def self_test() -> int:
    global NO_REDIRECT_OPENER

    digest_a = "ghcr.io/example/app@sha256:" + "a" * 64
    digest_b = "ghcr.io/example/app@sha256:" + "b" * 64
    policy = {"minimum_images": 1, "maximum_images": 1, "image_repositories": ["ghcr.io/example/app"]}
    validate_images([digest_a], [digest_b], policy)
    for candidate, message in (
        (["ghcr.io/example/app:latest"], "mutable image tag"),
        ([], "incomplete candidate images"),
        (["ghcr.io/example/wrong@sha256:" + "a" * 64], "wrong image repository"),
    ):
        try:
            validate_images(candidate, [digest_b], policy)
        except PolicyError:
            pass
        else:
            raise PolicyError(f"negative regression passed: {message}")
    reordered_policy = {
        "minimum_images": 2,
        "maximum_images": 2,
        "image_repositories": ["ghcr.io/example/app", "ghcr.io/example/worker"],
    }
    app_a = "ghcr.io/example/app@sha256:" + "a" * 64
    worker_b = "ghcr.io/example/worker@sha256:" + "b" * 64
    try:
        validate_images([app_a, worker_b], [worker_b, app_a], reordered_policy)
    except PolicyError:
        pass
    else:
        raise PolicyError("negative reordered rollback regression passed")
    validate_artifact_storage_url("https://productionresultssa0.blob.core.windows.net/actions/results.zip?sig=test")
    for location in (
        "http://productionresultssa0.blob.core.windows.net/results.zip",
        "https://api.github.com/repos/example/archive.zip",
        "https://evil.example/results.zip",
    ):
        try:
            validate_artifact_storage_url(location)
        except PolicyError:
            pass
        else:
            raise PolicyError("negative artifact redirect regression passed")
    original_opener = NO_REDIRECT_OPENER

    class RedirectTestOpener:
        def __init__(self) -> None:
            self.requests: list[urllib.request.Request] = []

        def open(self, request: urllib.request.Request, timeout: int) -> io.BytesIO:
            del timeout
            self.requests.append(request)
            if request.full_url.startswith("https://api.github.com/"):
                require(
                    request.headers.get("Authorization") == "Bearer test-token",
                    "artifact API request omitted authorization",
                )
                headers = Message()
                headers["Location"] = (
                    "https://productionresultssa0.blob.core.windows.net/"
                    "actions/results.zip?sig=test"
                )
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "Found",
                    headers,
                    None,
                )
            require(
                request.headers.get("Authorization") is None,
                "GitHub authorization leaked to artifact storage",
            )
            return io.BytesIO(b"test-archive")

    redirect_opener = RedirectTestOpener()
    NO_REDIRECT_OPENER = redirect_opener
    os.environ.setdefault("GH_TOKEN", "test-token")
    try:
        require(
            download_artifact_archive("repos/example/actions/artifacts/1/zip")
            == b"test-archive",
            "artifact redirect regression returned unexpected content",
        )
        require(len(redirect_opener.requests) == 2, "artifact redirect did not use two explicit requests")
    finally:
        NO_REDIRECT_OPENER = original_opener
    expected = {"phase": "plan", "candidate_sha256": "c" * 64, "production_changed": False}
    validate_prior(deepcopy(expected), expected)
    for key, value in (("phase", "staging"), ("candidate_sha256", "d" * 64), ("production_changed", True)):
        mutation = deepcopy(expected)
        mutation[key] = value
        try:
            validate_prior(mutation, expected)
        except PolicyError:
            pass
        else:
            raise PolicyError(f"negative prior-evidence regression passed: {key}")
    statement = {"predicate": {"buildDefinition": {"resolvedDependencies": [{"digest": {"gitCommit": "e" * 40}}]}}}
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    require(cosign_statements(json.dumps({"payload": payload})) == [statement], "cosign statement regression failed")
    try:
        cosign_statements(json.dumps({"payload": "not-base64"}))
    except (PolicyError, ValueError):
        pass
    else:
        raise PolicyError("negative malformed cosign attestation regression passed")
    branch: dict[str, Any] = {"protection": {"required_status_checks": {"contexts": ["validate"], "checks": [{"context": "validate", "app_id": 15368}]}}}
    names, bindings = required_check_bindings(branch, [[]], 15368)
    require(names == ["validate"] and bindings == {"validate": 15368}, "app-binding positive regression failed")
    wrong = deepcopy(branch)
    wrong["protection"]["required_status_checks"]["checks"][0]["app_id"] = 1
    try:
        required_check_bindings(wrong, [[]], 15368)
    except PolicyError:
        pass
    else:
        raise PolicyError("negative wrong-app regression passed")
    protected_environment: dict[str, Any] = {
        "name": "production",
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {"type": "User", "reviewer": {"id": 42, "login": "reviewer"}}
                ],
            }
        ],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }
    validate_environment_document(protected_environment, "production")
    for mutation_name, mutation in (
        (
            "missing environment reviewers",
            {
                **protected_environment,
                "protection_rules": [],
            },
        ),
        (
            "environment self-review",
            {
                **protected_environment,
                "protection_rules": [
                    {
                        **protected_environment["protection_rules"][0],
                        "prevent_self_review": False,
                    }
                ],
            },
        ),
        (
            "environment unprotected branch",
            {
                **protected_environment,
                "deployment_branch_policy": {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                },
            },
        ),
    ):
        try:
            validate_environment_document(mutation, "production")
        except PolicyError:
            pass
        else:
            raise PolicyError(f"negative {mutation_name} regression passed")
    candidate_document = {
        "schema_version": CANDIDATE_SCHEMA,
        "template": False,
        "release_id": "release-test-001",
        "controller_sha": "1" * 40,
        "source_lock_sha": "2" * 40,
        "runtime_candidate_sha256": "3" * 64,
        "safety": {key: False for key in CANDIDATE_SAFETY_KEYS},
        "components": [
            {
                "repository": repository,
                "source_sha": "1" * 40 if repository == CONTROLLER_REPOSITORY else "4" * 40,
                "contract_sha256": "5" * 64,
                "images": [],
                "previous_images": [],
                "enabled": True,
            }
            for repository in sorted(CATALOG_REPOSITORIES)
        ],
    }
    candidate_raw = json.dumps(candidate_document, sort_keys=True).encode()
    candidate_hash = hashlib.sha256(candidate_raw).hexdigest()
    validate_candidate_document(
        candidate_raw,
        candidate_hash,
        "release-test-001",
        "appolon1908-hue/Infustruction-repo",
        "4" * 40,
        "5" * 64,
        [],
        [],
    )
    try:
        validate_candidate_document(
            candidate_raw,
            "6" * 64,
            "release-test-001",
            "appolon1908-hue/Infustruction-repo",
            "4" * 40,
            "5" * 64,
            [],
            [],
        )
    except PolicyError:
        pass
    else:
        raise PolicyError("negative candidate hash regression passed")
    validate_phase_blockers(["runtime recovery evidence is missing"], "plan")
    try:
        validate_phase_blockers(["runtime recovery evidence is missing"], "staging")
    except PolicyError:
        pass
    else:
        raise PolicyError("negative unresolved blocker regression passed")
    print("RELEASE_INTENT_SELF_TEST=PASS")
    return 0


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--self-test"]:
            raise SystemExit(self_test())
        if sys.argv[1:] == ["--recheck-protected-gates"]:
            raise SystemExit(recheck_protected_gates())
        require(not sys.argv[1:], "unsupported arguments")
        raise SystemExit(main())
    except PolicyError as error:
        raise SystemExit(str(error)) from error
