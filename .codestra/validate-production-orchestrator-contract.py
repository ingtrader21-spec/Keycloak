#!/usr/bin/env python3
"""Fail-closed validation for the repository-owned production contract."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


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
SHELL_INTERPRETERS = {"bash", "dash", "eval", "ksh", "sh", "zsh"}
SCRIPT_INTERPRETERS = {"node", "perl", "php", "python", "python3", "ruby"}
KUBECTL_MUTATIONS = {
    "annotate",
    "apply",
    "autoscale",
    "cordon",
    "cp",
    "create",
    "delete",
    "drain",
    "exec",
    "expose",
    "label",
    "patch",
    "replace",
    "rollout",
    "run",
    "scale",
    "set",
    "taint",
    "uncordon",
}
HELM_MUTATIONS = {"install", "rollback", "uninstall", "upgrade"}
TERRAFORM_MUTATIONS = {"apply", "destroy", "import", "taint", "untaint"}
CONTAINER_MUTATIONS = {"down", "kill", "rm", "start", "stop", "restart", "up"}
HTTP_MUTATION_FLAGS = {
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--form",
    "--form-string",
    "--json",
    "--upload-file",
    "-d",
}
HTTP_MUTATION_METHODS = {"delete", "patch", "post", "put"}
CLOUD_MUTATION_PREFIXES = (
    "apply",
    "associate",
    "attach",
    "authorize",
    "create",
    "delete",
    "deregister",
    "detach",
    "disable",
    "disassociate",
    "enable",
    "execute",
    "invoke",
    "modify",
    "publish",
    "put",
    "reboot",
    "register",
    "reset",
    "restore",
    "revoke",
    "run",
    "send",
    "start",
    "stop",
    "tag",
    "terminate",
    "untag",
    "update",
)
MUTATING_ACTION_MARKERS = {
    "ansible",
    "cloudformation",
    "deploy",
    "helm",
    "kubectl",
    "kubernetes",
    "scp",
    "ssh",
    "terraform",
}
SAFE_NATIVE_ACTION_PREFIXES = {
    "actions/attest-build-provenance@",
    "actions/attest@",
    "actions/cache@",
    "actions/checkout@",
    "actions/download-artifact@",
    "actions/setup-node@",
    "actions/setup-python@",
    "actions/upload-artifact@",
    "anchore/sbom-action@",
    "anchore/scan-action@",
    "aquasecurity/setup-trivy@",
    "aquasecurity/trivy-action@",
    "docker/build-push-action@",
    "docker/login-action@",
    "docker/setup-buildx-action@",
    "github/codeql-action/",
    "gitleaks/gitleaks-action@",
    "pnpm/action-setup@",
    "pypa/gh-action-pip-audit@",
    "sigstore/cosign-installer@",
}
EXPECTED_IDENTITIES: dict[str, tuple[int, str, bool, bool]] = {
    "appolon1908-hue/Infustruction-repo": (1350724865, "infrastructure", True, True),
    "appolon1908-hue/Keycloak": (1347523366, "identity", True, False),
    "appolon1908-hue/Middleware-": (1347559071, "canonical-middleware", False, False),
    "appolon1908-hue/codestra": (1319808791, "application", True, False),
    "appolon1908-hue/beyvra-backend": (1319831182, "application", True, False),
    "appolon1908-hue/backend2": (1319903950, "application", True, False),
    "appolon1908-hue/beyvra-frontend": (1320246591, "application", True, False),
    "appolon1908-hue/scrapper": (1329513537, "migration-evidence", False, False),
    "appolon1908-hue/Breero.com": (1331354808, "application", True, False),
    "appolon1908-hue/Moneybee-Backend": (1343760409, "application", True, False),
    "appolon1908-hue/Telnexa-web": (1346958528, "application", True, False),
    "appolon1908-hue/codestra-production-platform": (1314230781, "controller", False, False),
}
EXPECTED_ARTIFACT_POLICIES: dict[
    str, tuple[tuple[str, ...], bool, bool, bool, str | None, str | None]
] = {
    "appolon1908-hue/Infustruction-repo": ((), False, False, False, None, None),
    "appolon1908-hue/Keycloak": ((), False, False, False, None, None),
    "appolon1908-hue/Middleware-": (
        ("ghcr.io/appolon1908-hue/codestra-middleware",),
        True,
        True,
        True,
        "cosign",
        "oci",
    ),
    "appolon1908-hue/codestra": (
        ("ghcr.io/appolon1908-hue/codestra",),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/beyvra-backend": (
        (
            "ghcr.io/appolon1908-hue/beyvra-backend",
            "ghcr.io/appolon1908-hue/beyvra-backend-edge",
        ),
        True,
        True,
        False,
        "github",
        "oci",
    ),
    "appolon1908-hue/backend2": (
        ("ghcr.io/appolon1908-hue/backend2",),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/beyvra-frontend": (
        ("ghcr.io/appolon1908-hue/beyvra-frontend",),
        True,
        True,
        False,
        "github",
        "oci",
    ),
    "appolon1908-hue/scrapper": ((), False, False, False, None, None),
    "appolon1908-hue/Breero.com": (
        (
            "ghcr.io/appolon1908-hue/breero-api",
            "ghcr.io/appolon1908-hue/breero-frontend",
            "ghcr.io/appolon1908-hue/breero-partner",
            "ghcr.io/appolon1908-hue/breero-ops",
            "ghcr.io/appolon1908-hue/breero-admin",
        ),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/Moneybee-Backend": (
        (
            "ghcr.io/appolon1908-hue/moneybee-api",
            "ghcr.io/appolon1908-hue/moneybee-worker",
            "ghcr.io/appolon1908-hue/moneybee-migrate",
        ),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/Telnexa-web": (
        ("ghcr.io/appolon1908-hue/telnexa-web",),
        True,
        True,
        False,
        "github",
        "github",
    ),
}
APPROVED_COMPLEX_SCRIPT_SHA256: dict[str, dict[str, str]] = {
    "appolon1908-hue/Middleware-": {
        "scripts/release_manifest.py": "67d438833554baa448eabb34188ef3028d6e37088084be0a201e602282175d25",
    },
    "appolon1908-hue/codestra": {
        "scripts/ci/check-runtime-discovery.mjs": "a0ccd39eb918093ba7715c9fc40fc9facaef6feef95210c46e9fead61323708f",
        "scripts/ci/test-runtime-discovery-fixture.sh": "a7b6557ed6dc927f6dc78a45440c3cf8deda6a2410a3bf94c70231be3bda751d",
        "scripts/ci/test-runtime-discovery-host-proxy.sh": "c934ec0ff3aa97a08940c0475139edfa155fb839b43017a5a881ffde480ac9e9",
    },
    "appolon1908-hue/Moneybee-Backend": {
        "ops/verify-compose-contract.py": "5b9c78f82de3784af3d68945be43abadbbe3eab7e73f3edf0f27ef7042e7e674",
    },
}
APPROVED_CONTROL_PLANE_WORKFLOW_SHA256: dict[str, dict[str, str]] = {
    "appolon1908-hue/Middleware-": {
        ".github/workflows/required-ci.yml": "5b135f1eec36d3baa8d605ecddf3d37aa1fbfa7bd9d58e61ba58a5324a087d5e",
    },
}
REQUIRED_NATIVE_WORKFLOWS: dict[str, dict[str, str]] = {
    "appolon1908-hue/Infustruction-repo": {
        "runtime_certification": ".github/workflows/staging-readonly-certification.yml",
    },
    "appolon1908-hue/Keycloak": {
        "plan_apply": ".github/workflows/deploy.yml",
        "drift_review": ".github/workflows/drift-review.yml",
    },
    "appolon1908-hue/Middleware-": {
        "signed_release": ".github/workflows/release.yml",
        "runtime_certification": ".github/workflows/production-runtime-certification.yml",
    },
    "appolon1908-hue/codestra": {
        "build_deploy": ".github/workflows/deploy.yml",
    },
}
ALLOWED_RELEASE_VALIDATOR_COMMANDS = {
    ("cosign", "verify"),
    ("cosign", "verify-attestation"),
    ("docker", "buildx"),
    ("docker", "login"),
    ("gh", "attestation"),
    ("git", "rev-parse"),
    ("git", "status"),
}
FORBIDDEN_RELEASE_VALIDATOR_IMPORTS = {
    "fabric",
    "httpx",
    "paramiko",
    "requests",
    "socket",
}


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


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mappings."""


def construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        require(key not in result, "workflow contains a duplicate YAML key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


@dataclass(frozen=True)
class WorkflowJob:
    data: dict[str, Any]
    raw: str


def workflow_jobs(workflow: str, path: str) -> dict[str, WorkflowJob]:
    """Parse GitHub Actions jobs with YAML semantics and source spans."""

    try:
        document = yaml.load(workflow, Loader=UniqueKeyLoader)
        root = yaml.compose(workflow, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ContractError(f"workflow is not valid YAML: {path}") from exc
    require(isinstance(document, dict), f"workflow is not a mapping: {path}")
    jobs_value = document.get("jobs")
    require(isinstance(jobs_value, dict) and bool(jobs_value), f"workflow has no jobs: {path}")
    require(isinstance(root, yaml.nodes.MappingNode), f"workflow root is invalid: {path}")
    jobs_node: yaml.nodes.MappingNode | None = None
    for key_node, value_node in root.value:
        if isinstance(key_node, yaml.nodes.ScalarNode) and key_node.value == "jobs":
            require(isinstance(value_node, yaml.nodes.MappingNode), f"workflow jobs are invalid: {path}")
            jobs_node = value_node
            break
    if jobs_node is None:
        raise ContractError(f"workflow jobs source is missing: {path}")
    lines = workflow.splitlines()
    result: dict[str, WorkflowJob] = {}
    for key_node, value_node in jobs_node.value:
        require(isinstance(key_node, yaml.nodes.ScalarNode), f"workflow job name is invalid: {path}")
        name = key_node.value
        data = jobs_value.get(name)
        require(isinstance(data, dict), f"workflow job is not a mapping: {path}:{name}")
        raw = "\n".join(lines[key_node.start_mark.line : value_node.end_mark.line]) + "\n"
        result[name] = WorkflowJob(data=data, raw=raw)
    require(set(result) == set(jobs_value), f"workflow job source mismatch: {path}")
    return result


def workflow_steps(job: WorkflowJob, path: str) -> list[dict[str, Any]]:
    value = job.data.get("steps")
    if value is None:
        return []
    require(isinstance(value, list), f"job steps are invalid: {path}")
    steps: list[dict[str, Any]] = []
    for item in value:
        require(isinstance(item, dict), f"workflow step is not a mapping: {path}")
        for key in ("env", "with"):
            require(
                key not in item or isinstance(item[key], dict),
                f"workflow step {key} is invalid: {path}",
            )
        steps.append(item)
    return steps


def shell_tokens(script: str) -> list[str]:
    try:
        lexer = shlex.shlex(
            script.replace("\\\n", " "),
            posix=True,
            punctuation_chars="|&;()\n",
        )
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        # Bash command substitutions and heredocs are richer than POSIX shlex.
        # A conservative token fallback keeps known runtime tools visible rather
        # than treating an unsupported shell construct as safe.
        return re.findall(r"[A-Za-z0-9_./@${}:+-]+", script)


def executable_name(token: str) -> str:
    return token.strip("$(){}[]").rsplit("/", 1)[-1]


def command_indexes(tokens: list[str]) -> list[int]:
    indexes: list[int] = []
    expect_command = True
    wrappers = {"!", "command", "env", "exec", "nohup", "sudo", "time"}
    control = {"do", "elif", "else", "if", "then", "until", "while"}
    separators = {"\n", "&", "&&", "(", ")", ";", "|", "||"}
    for index, token in enumerate(tokens):
        if token in separators:
            expect_command = True
            continue
        if token in control:
            expect_command = True
            continue
        if not expect_command:
            continue
        if token in wrappers:
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
            continue
        indexes.append(index)
        expect_command = False
    return indexes


def command_arguments(tokens: list[str], index: int) -> list[str]:
    separators = {"\n", "&", "&&", "(", ")", ";", "|", "||"}
    arguments: list[str] = []
    for token in tokens[index + 1 :]:
        if token in separators:
            break
        arguments.append(executable_name(token))
    return arguments


def interpreter_payload(tokens: list[str], index: int) -> str | None:
    name = executable_name(tokens[index])
    if name == "eval":
        return tokens[index + 1] if index + 1 < len(tokens) else ""
    if name not in SHELL_INTERPRETERS | SCRIPT_INTERPRETERS:
        return None
    for option_index in range(index + 1, min(index + 4, len(tokens))):
        if tokens[option_index] == "-c":
            return tokens[option_index + 1] if option_index + 1 < len(tokens) else ""
    return None


def interpreter_script_target(tokens: list[str], index: int) -> str | None:
    name = executable_name(tokens[index])
    if name not in SHELL_INTERPRETERS | SCRIPT_INTERPRETERS:
        return None
    shellcheck_only = False
    skip_option_value = False
    for token in tokens[index + 1 :]:
        if token in {"|", "||", "&&", ";", "&"}:
            break
        if skip_option_value:
            skip_option_value = False
            continue
        if (
            token == "-m"
            or token == "-"
            or token.startswith("<<")
            or token == "-c"
            or token == "-e" and name in {"node", "perl", "ruby"}
            or token == "--eval" and name == "node"
            or token == "-r" and name == "php"
        ):
            return None
        if token == "-n" and name in SHELL_INTERPRETERS:
            shellcheck_only = True
            continue
        if token in {"-o", "--option"}:
            skip_option_value = True
            continue
        if token.startswith("-"):
            if name in SHELL_INTERPRETERS and "o" in token[1:]:
                skip_option_value = True
            continue
        if "=" in token and not token.startswith(("./", "../")):
            continue
        return None if shellcheck_only else token
    return None


def python_source_has_runtime_mutation(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return True
    aliases: dict[str, str] = {}
    command_bindings: dict[str, ast.expr] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            command_bindings[node.targets[0].id] = node.value

    def qualified_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parent = qualified_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    runtime_modules = {"ansible", "docker", "fabric", "kubernetes", "paramiko"}
    if any(value.split(".", 1)[0] in runtime_modules for value in aliases.values()):
        return True
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = qualified_name(node.func)
        if qualified in {"os.system", "os.popen"} or qualified.startswith("subprocess."):
            if not node.args:
                return True
            argument = node.args[0]
            if isinstance(argument, ast.Name) and argument.id in command_bindings:
                argument = command_bindings[argument.id]
            command = ""
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                command = argument.value
            elif isinstance(argument, (ast.List, ast.Tuple)):
                if not argument.elts:
                    return True
                first = argument.elts[0]
                if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
                    return True
                values = [
                    item.value
                    for item in argument.elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                ]
                executable = executable_name(first.value)
                if executable in {"ansible-playbook", "scp", "ssh"}:
                    return True
                if executable in {"helm", "kubectl", "terraform", "tofu"} and len(values) != len(argument.elts):
                    return True
                command = " ".join(values)
            else:
                return True
            if contains_runtime_mutation(command):
                return True
    return False


def repository_script_has_runtime_mutation(
    target: str,
    seen_scripts: set[Path],
    script_aliases: dict[str, str] | None = None,
) -> bool:
    normalized_target = target.replace("$RUNNER_TEMP/", "${RUNNER_TEMP}/")
    if script_aliases and normalized_target in script_aliases:
        target = script_aliases[normalized_target]
    if "${{" in target or "$" in target:
        return True
    candidate = ROOT / target.removeprefix("./")
    if candidate.is_symlink():
        return True
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except FileNotFoundError:
        # Generated build outputs and secondary checkout paths are not
        # repository-owned scripts. Checked-in targets resolve and are audited.
        return False
    except (OSError, ValueError):
        return True
    if not resolved.is_file() or resolved.is_symlink():
        return True
    if resolved in seen_scripts:
        return True
    suffix = resolved.suffix.lower()
    if suffix not in {".bash", ".cjs", ".js", ".mjs", ".php", ".pl", ".py", ".rb", ".sh"}:
        return True
    source = resolved.read_text(encoding="utf-8")
    if resolved == Path(__file__).resolve():
        return False
    if resolved == RELEASE_VALIDATOR_PATH.resolve():
        validate_release_validator_operations(source)
        return False
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    relative = resolved.relative_to(ROOT.resolve()).as_posix()
    expected_hash = APPROVED_COMPLEX_SCRIPT_SHA256.get(repository, {}).get(relative)
    if expected_hash is not None:
        return hashlib.sha256(source.encode()).hexdigest() != expected_hash
    if suffix == ".py":
        return python_source_has_runtime_mutation(source)
    return contains_runtime_mutation(source, seen_scripts | {resolved})


def contains_runtime_command(script: str) -> bool:
    tokens = shell_tokens(script)
    for index in command_indexes(tokens):
        name = executable_name(tokens[index])
        if name in RUNTIME_TOOLS or name.endswith("deploy_immutable") or name.endswith("apply-plan.sh"):
            return True
        payload = interpreter_payload(tokens, index)
        if payload is not None:
            if "$" in payload or contains_runtime_command(payload):
                return True
    return False


def contains_runtime_mutation(
    script: str,
    seen_scripts: set[Path] | None = None,
    script_aliases: dict[str, str] | None = None,
) -> bool:
    if seen_scripts is None:
        seen_scripts = set()
    tokens = shell_tokens(script)
    names = [executable_name(token) for token in tokens]
    for index in command_indexes(tokens):
        name = names[index]
        tail = command_arguments(tokens, index)
        lower_name = name.lower()
        payload = interpreter_payload(tokens, index)
        if payload is not None:
            if "$" in payload or contains_runtime_mutation(
                payload,
                seen_scripts,
                script_aliases,
            ):
                return True
        target = interpreter_script_target(tokens, index)
        if target is not None and repository_script_has_runtime_mutation(
            target,
            seen_scripts,
            script_aliases,
        ):
            return True
        if name in {"ansible-playbook", "scp", "ssh"}:
            return True
        if name == "kubectl" and any(item in KUBECTL_MUTATIONS for item in tail):
            return True
        if name == "helm" and any(item in HELM_MUTATIONS for item in tail):
            return True
        if name in {"terraform", "tofu"} and (
            any(item in TERRAFORM_MUTATIONS for item in tail)
            or "state" in tail and any(item in {"mv", "push", "rm"} for item in tail)
        ):
            return True
        if name in {"docker", "podman"} and "compose" in tail and any(
            item in CONTAINER_MUTATIONS for item in tail
        ):
            return True
        if api_client_has_mutating_operation(name, tail):
            return True
        if (
            name.endswith("deploy_immutable")
            or name.endswith("apply-plan.sh")
            or lower_name.startswith("deploy_")
            and lower_name.endswith((".py", ".sh"))
            and any(item in {"apply", "apply-and-issue", "deploy", "rollback"} for item in tail)
            or "reconcile" in lower_name
            and any(item in {"apply", "apply-and-issue", "deploy"} for item in tail)
        ):
            return True
    return False


def option_value(tokens: list[str], names: set[str]) -> str | None:
    for index, token in enumerate(tokens):
        lower = token.lower()
        if lower in names:
            return tokens[index + 1].lower() if index + 1 < len(tokens) else ""
        for name in names:
            if lower.startswith(f"{name}="):
                return lower.split("=", 1)[1]
            if name in {"-x", "-m"} and lower.startswith(name) and len(lower) > 2:
                return lower[2:]
    return None


def api_client_has_mutating_operation(name: str, tail: list[str]) -> bool:
    """Classify explicit write modes for generic API and cloud clients."""

    lower_name = name.lower()
    lower_tail = [token.lower() for token in tail]
    if lower_name in {"curl", "wget"}:
        method = option_value(lower_tail, {"--method", "--request", "-m", "-x"})
        if method in HTTP_MUTATION_METHODS:
            return True
        return any(
            lower in HTTP_MUTATION_FLAGS
            or any(
                lower.startswith(f"{flag}=")
                for flag in HTTP_MUTATION_FLAGS
                if flag.startswith("--")
            )
            or lower.startswith("-d") and len(token) > 2
            or token.startswith(("-F", "-T"))
            or lower.startswith("--post-")
            for token, lower in zip(tail, lower_tail, strict=True)
        )
    if lower_name == "gh" and lower_tail:
        if lower_tail[0] == "api":
            method = option_value(lower_tail[1:], {"--method", "-x"})
            return (
                method not in {None, "get"}
                or any(
                    token in {"--field", "--input", "--raw-field", "-f"}
                    or token.startswith(
                        ("--field=", "--input=", "--raw-field=", "-f=")
                    )
                    for token in lower_tail[1:]
                )
            )
        return lower_tail[:2] == ["workflow", "run"]
    if lower_name in {"aws", "az", "doctl", "gcloud"}:
        return any(
            token.startswith(CLOUD_MUTATION_PREFIXES)
            for token in lower_tail[:4]
            if token and not token.startswith("-")
        )
    return False


def contains_runtime_action(step: dict[str, Any]) -> bool:
    value = step.get("uses")
    if not isinstance(value, str):
        return False
    normalized = value.split(" #", 1)[0].strip().lower()
    if normalized.startswith("actions/github-script@"):
        inputs = step.get("with")
        if not isinstance(inputs, dict) or not isinstance(inputs.get("script"), str):
            return True
        script = inputs["script"].lower()
        return any(
            marker in script
            for marker in (
                "child_process",
                "createworkflowdispatch",
                "repositorydispatch",
                "workflow_dispatch",
                "/dispatches",
                "exec.exec",
                "exec.getexecoutput",
                "fetch(",
            )
        )
    return (
        normalized.startswith("./")
        or "${{" in normalized
        or any(marker in normalized for marker in MUTATING_ACTION_MARKERS)
        or not any(
            normalized.startswith(prefix) for prefix in SAFE_NATIVE_ACTION_PREFIXES
        )
    )


def contains_image_publication(step: dict[str, Any]) -> bool:
    uses = step.get("uses")
    inputs = step.get("with")
    if isinstance(uses, str) and isinstance(inputs, dict):
        normalized = uses.split(" #", 1)[0].strip().lower()
        if normalized.startswith("docker/build-push-action@"):
            return inputs.get("push") in {True, "true"}
        if normalized.startswith("actions/attest-build-provenance@"):
            return inputs.get("push-to-registry") in {True, "true"}
    raw_tokens = shell_tokens(str(step.get("run", "")))
    tokens = [executable_name(item).lower() for item in raw_tokens]
    return any(
        name in {"docker", "podman"} and "push" in tokens[index + 1 : index + 5]
        for index in command_indexes(raw_tokens)
        for name in [tokens[index]]
    )


def job_condition(job: WorkflowJob) -> str | None:
    value = job.data.get("if")
    return value if isinstance(value, str) else None


def job_reusable_workflow_mutation(
    job: WorkflowJob,
    path: str,
    seen_workflows: set[Path] | None = None,
) -> bool:
    value = job.data.get("uses")
    if value is None:
        return False
    if not isinstance(value, str) or "${{" in value:
        return True
    normalized = value.split(" #", 1)[0].strip()
    if not normalized.startswith("./.github/workflows/"):
        return True
    candidate = ROOT / normalized.removeprefix("./")
    if candidate.is_symlink():
        return True
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to((ROOT / ".github/workflows").resolve())
    except (OSError, ValueError):
        return True
    if not resolved.is_file() or resolved.is_symlink():
        return True
    if seen_workflows is None:
        seen_workflows = set()
    if resolved in seen_workflows:
        return True
    relative = resolved.relative_to(ROOT.resolve()).as_posix()
    return workflow_has_runtime_mutation(
        resolved.read_text(encoding="utf-8"),
        relative,
        seen_workflows | {resolved},
    )


def workflow_script_aliases(workflow: str, path: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    pattern = re.compile(
        r'^\s*install\s+-m\s+0?755\s+([A-Za-z0-9_./-]+)\s+["\']?(\$\{?RUNNER_TEMP\}?/[A-Za-z0-9_.-]+)["\']?\s*$'
    )
    for job in workflow_jobs(workflow, path).values():
        for step in workflow_steps(job, path):
            script = str(step.get("run", "")).replace("\\\n", " ")
            for line in script.splitlines():
                match = pattern.fullmatch(line)
                if not match:
                    continue
                source, destination = match.groups()
                destination = destination.replace("$RUNNER_TEMP/", "${RUNNER_TEMP}/")
                require(destination not in aliases, f"duplicate generated script binding: {path}")
                candidate = ROOT / source
                require(
                    candidate.is_file() and not candidate.is_symlink(),
                    f"generated script source is missing or unsafe: {path}",
                )
                aliases[destination] = source
    return aliases


def workflow_has_runtime_command(workflow: str, path: str) -> bool:
    return any(
        contains_runtime_command(str(step.get("run", "")))
        for job in workflow_jobs(workflow, path).values()
        for step in workflow_steps(job, path)
    )


def workflow_has_runtime_mutation(
    workflow: str,
    path: str,
    seen_workflows: set[Path] | None = None,
) -> bool:
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    approved_hash = APPROVED_CONTROL_PLANE_WORKFLOW_SHA256.get(repository, {}).get(
        path
    )
    if approved_hash is not None:
        return hashlib.sha256(workflow.encode()).hexdigest() != approved_hash
    if seen_workflows is None:
        seen_workflows = set()
    script_aliases = workflow_script_aliases(workflow, path)
    return any(
        job_reusable_workflow_mutation(job, path, seen_workflows)
        or any(
            contains_runtime_mutation(
                str(step.get("run", "")),
                script_aliases=script_aliases,
            )
            or contains_runtime_action(step)
            for step in workflow_steps(job, path)
        )
        for job in workflow_jobs(workflow, path).values()
    )


def workflow_has_image_publication(workflow: str, path: str) -> bool:
    return any(
        contains_image_publication(step)
        for job in workflow_jobs(workflow, path).values()
        for step in workflow_steps(job, path)
    )


def workflow_actions(workflow: str, path: str) -> list[str]:
    jobs = workflow_jobs(workflow, path)
    actions = [
        str(step["uses"]).split(" #", 1)[0].strip()
        for job in jobs.values()
        for step in workflow_steps(job, path)
        if isinstance(step.get("uses"), str) and step["uses"]
    ]
    actions.extend(
        str(job.data["uses"]).split(" #", 1)[0].strip()
        for job in jobs.values()
        if isinstance(job.data.get("uses"), str) and job.data["uses"]
    )
    return actions


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
        checkout["with"].get("persist-credentials") is False,
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


def validate_protected_job_recheck(intent: str) -> None:
    jobs = workflow_jobs(intent, ".github/workflows/manual-release-intent.yml")
    require("protected-intent" in jobs, "release-intent protected job is missing")
    job = jobs["protected-intent"]
    steps = workflow_steps(job, ".github/workflows/manual-release-intent.yml")
    checkout_indexes = [
        index
        for index, step in enumerate(steps)
        if step.get("uses")
        == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        and step.get("with", {}).get("ref") == "${{ github.sha }}"
        and step.get("with", {}).get("persist-credentials") is False
    ]
    recheck_indexes = [
        index
        for index, step in enumerate(steps)
        if step.get("run")
        == "python3 .codestra/validate-release-intent.py --recheck-protected-gates"
    ]
    require(len(checkout_indexes) == 1, "protected job exact checkout is missing")
    require(len(recheck_indexes) == 1, "protected job policy recheck is missing")
    require(checkout_indexes[0] < recheck_indexes[0], "protected job rechecks before exact checkout")
    recheck = steps[recheck_indexes[0]]
    expected_env = {
        "GH_TOKEN": "${{ github.token }}",
        "CODESTRA_ORCHESTRATOR_TOKEN": "${{ secrets.CODESTRA_ORCHESTRATOR_TOKEN }}",
        "PHASE": "${{ inputs.phase }}",
        "SOURCE_SHA": "${{ inputs.source_sha }}",
        "RELEASE_ID": "${{ inputs.release_id }}",
        "CANDIDATE_SHA256": "${{ inputs.candidate_sha256 }}",
        "IMAGES_JSON": "${{ inputs.images_json }}",
        "PREVIOUS_IMAGES_JSON": "${{ inputs.previous_images_json }}",
    }
    require(recheck.get("env") == expected_env, "protected job policy recheck inputs are incomplete")


def validate_release_validator_operations(source: str) -> None:
    """Allow evidence clients only; reject runtime-capable execution paths."""

    try:
        tree = ast.parse(source, filename=str(RELEASE_VALIDATOR_PATH))
    except SyntaxError as exc:
        raise ContractError("release-intent validator is not valid Python") from exc

    def unresolved_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = unresolved_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    imports: set[str] = set()
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                imports.add(root)
                aliases[alias.asname or root] = alias.name if alias.asname else root
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".", 1)[0])
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def qualified_name(node: ast.expr) -> str:
        raw = unresolved_name(node)
        root, separator, tail = raw.partition(".")
        replacement = aliases.get(root, root)
        return f"{replacement}.{tail}" if separator else replacement

    command_bindings: dict[str, set[tuple[str, str]]] = {}
    opener_bindings: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, (ast.List, ast.Tuple))
            and len(node.value.elts) >= 2
            and isinstance(node.value.elts[0], ast.Constant)
            and isinstance(node.value.elts[0].value, str)
            and isinstance(node.value.elts[1], ast.Constant)
            and isinstance(node.value.elts[1].value, str)
        ):
            command_bindings.setdefault(node.targets[0].id, set()).add(
                (
                    executable_name(node.value.elts[0].value),
                    node.value.elts[1].value,
                )
            )
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and qualified_name(node.value.func) == "urllib.request.build_opener"
        ):
            opener_bindings.add(node.targets[0].id)
    require(
        not (imports & FORBIDDEN_RELEASE_VALIDATOR_IMPORTS),
        "release-intent validator imports a runtime/network client",
    )

    allowed_subprocess_calls = {"check_output", "run"}

    def bound_commands(argument: ast.expr) -> set[tuple[str, str]]:
        if isinstance(argument, (ast.List, ast.Tuple)) and len(argument.elts) >= 2:
            first = argument.elts[0]
            second = argument.elts[1]
            if (
                isinstance(first, ast.Constant)
                and isinstance(first.value, str)
                and isinstance(second, ast.Constant)
                and isinstance(second.value, str)
            ):
                return {(executable_name(first.value), second.value)}
            if isinstance(first, ast.Starred) and isinstance(first.value, ast.Name):
                return command_bindings.get(first.value.id, set())
        if isinstance(argument, ast.Name):
            return command_bindings.get(argument.id, set())
        return set()

    function_stack: list[str] = []

    class OperationsVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            function_stack.append(node.name)
            self.generic_visit(node)
            function_stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            function_stack.append(node.name)
            self.generic_visit(node)
            function_stack.pop()

        def visit_Call(self, node: ast.Call) -> None:
            qualified = qualified_name(node.func)
            require(
                qualified not in {"eval", "exec", "compile", "os.system", "os.popen"},
                "release-intent validator contains dynamic command execution",
            )
            if qualified.startswith("subprocess."):
                method = qualified.split(".", 1)[1]
                require(
                    method in allowed_subprocess_calls and bool(node.args),
                    "release-intent validator uses a non-allowlisted subprocess API",
                )
                commands = bound_commands(node.args[0])
                require(
                    bool(commands)
                    and commands <= ALLOWED_RELEASE_VALIDATOR_COMMANDS,
                    "release-intent validator executes a non-evidence command",
                )
                require(
                    not any(
                        keyword.arg == "shell"
                        and not (
                            isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is False
                        )
                        for keyword in node.keywords
                    ),
                    "release-intent validator enables a subprocess shell",
                )
            require(
                qualified
                not in {
                    "urllib.request.urlopen",
                    "urllib.request.urlretrieve",
                    "urllib.request.URLopener.open",
                    "urllib.request.FancyURLopener.open",
                },
                "release-intent validator uses an unapproved network-opening API",
            )
            approved_url_call = qualified == "urllib.request.Request" or any(
                qualified == f"{name}.open" for name in opener_bindings
            )
            if approved_url_call:
                require(
                    bool(function_stack)
                    and function_stack[-1] in {"api_request", "download_artifact_archive"},
                    "release-intent validator opens a URL outside the evidence clients",
                )
            self.generic_visit(node)

    OperationsVisitor().visit(tree)


def validate(contract: dict[str, Any]) -> None:
    repository = os.environ.get("GITHUB_REPOSITORY", contract.get("repository", ""))
    repository_id_text = os.environ.get("GITHUB_REPOSITORY_ID")
    require(contract.get("schema_version") == SCHEMA, "contract schema mismatch")
    require(repository in EXPECTED_IDENTITIES, "repository is outside the protected catalog identity map")
    require(contract.get("repository") == repository, "repository identity mismatch")
    expected_id, expected_role, expected_deployment, expected_runtime = EXPECTED_IDENTITIES[repository]
    require(contract.get("repository_id") == expected_id, "stable repository ID mismatch")
    require(contract.get("role") == expected_role, "repository role contradicts the protected catalog")
    require(
        contract.get("deployment_authority") is expected_deployment,
        "deployment authority contradicts the protected catalog",
    )
    require(
        contract.get("runtime_mutation_authority") is expected_runtime,
        "runtime mutation authority contradicts the protected catalog",
    )
    if repository_id_text:
        require(repository_id_text.isdigit(), "GITHUB_REPOSITORY_ID is invalid")
        require(contract.get("repository_id") == int(repository_id_text), "stable repository ID mismatch")
    require(contract.get("default_branch") == "main", "default branch must be main")
    require(contract.get("release_intent_workflow") == ".github/workflows/manual-release-intent.yml", "intent workflow mismatch")
    require(contract.get("require_verified_commit") is True, "verified commits must be required")
    require(contract.get("required_check_app_id") == 15368, "required checks must be bound to GitHub Actions")

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
    (
        expected_repositories,
        expected_sbom,
        expected_provenance,
        expected_signature,
        expected_verifier,
        expected_storage,
    ) = EXPECTED_ARTIFACT_POLICIES[repository]
    require(
        minimum == maximum == len(expected_repositories)
        and repositories == list(expected_repositories),
        "artifact image policy contradicts the protected repository identity",
    )
    require(
        artifacts.get("require_sbom") is expected_sbom
        and artifacts.get("require_provenance") is expected_provenance
        and artifacts.get("require_signature") is expected_signature
        and artifacts.get("attestation_verifier") == expected_verifier
        and artifacts.get("attestation_storage") == expected_storage,
        "artifact supply-chain policy contradicts the protected repository identity",
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
    required_native = REQUIRED_NATIVE_WORKFLOWS.get(repository, {})
    require(
        all(native.get(name) == path for name, path in required_native.items()),
        "native workflow scope contradicts the protected repository mapping",
    )
    signer_workflow = artifacts.get("signer_workflow")
    if supply_chain_required:
        require(
            signer_workflow in native.values(),
            "signer workflow is outside the enforced native workflow scope",
        )
    for value in native.values():
        require(isinstance(value, str) and value.startswith(".github/workflows/") and value.endswith((".yml", ".yaml")), "native workflow path is invalid")
        path = ROOT / value
        require(path.is_file() and not path.is_symlink(), f"native workflow is missing or unsafe: {value}")
        workflow = path.read_text(encoding="utf-8")
        if runtime_mutation_authority is False and workflow_has_runtime_mutation(workflow, value):
            require_mutating_jobs_disabled(workflow, value)
    if runtime_mutation_authority is False:
        workflow_paths = sorted(
            path
            for pattern in ("*.yml", "*.yaml")
            for path in (ROOT / ".github/workflows").glob(pattern)
        )
        require(bool(workflow_paths), "repository has no workflows to enforce")
        for path in workflow_paths:
            relative = path.relative_to(ROOT).as_posix()
            workflow = path.read_text(encoding="utf-8")
            if workflow_has_runtime_mutation(workflow, relative):
                require_mutating_jobs_disabled(workflow, relative)
    if repository == "appolon1908-hue/scrapper":
        for path in workflow_paths:
            relative = path.relative_to(ROOT).as_posix()
            workflow = path.read_text(encoding="utf-8")
            if workflow_has_image_publication(workflow, relative):
                require_image_publishing_jobs_disabled(workflow, relative)

    require_string_list(contract.get("blockers"), "blockers must be non-empty strings")

    require(INTENT_PATH.is_file() and not INTENT_PATH.is_symlink(), "manual release-intent workflow is missing or unsafe")
    require(RELEASE_VALIDATOR_PATH.is_file() and not RELEASE_VALIDATOR_PATH.is_symlink(), "release-intent validator is missing or unsafe")
    intent = INTENT_PATH.read_text(encoding="utf-8")
    release_validator = RELEASE_VALIDATOR_PATH.read_text(encoding="utf-8")
    validate_release_validator_operations(release_validator)
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
    validate_protected_job_recheck(intent)
    require(
        not workflow_has_runtime_command(intent, ".github/workflows/manual-release-intent.yml"),
        "release-intent workflow contains a runtime/deployment command",
    )
    actions = workflow_actions(intent, ".github/workflows/manual-release-intent.yml")
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

    identity_artifact_downgrade = deepcopy(contract)
    identity_artifact_downgrade["artifact_policy"].update(
        {
            "minimum_images": 0,
            "maximum_images": 0,
            "image_repositories": [],
            "require_sbom": False,
            "require_provenance": False,
            "require_signature": False,
            "attestation_verifier": None,
            "attestation_storage": None,
        }
    )
    if contract["artifact_policy"]["maximum_images"] != 0:
        mutations.append(("repository artifact-policy downgrade", identity_artifact_downgrade))

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

    role_escalation = deepcopy(contract)
    role_escalation["role"] = (
        "application" if contract.get("role") == "infrastructure" else "infrastructure"
    )
    role_escalation["runtime_mutation_authority"] = (
        role_escalation["role"] == "infrastructure"
    )
    mutations.append(("self-declared infrastructure authority", role_escalation))

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
        "tofu destroy",
        "ssh runtime.example true",
        "ansible-playbook production.yml",
        "./apply-plan.sh",
        "command docker pull example.invalid/image",
        'echo "$TOKEN" | docker login ghcr.io',
        "bash -c 'kubectl apply -f runtime.yml'",
        "sh -c 'terraform apply'",
        "eval 'helm upgrade release chart'",
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
    enabled_action_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses : vendor/kubernetes-deploy@0123456789012345678901234567890123456789
"""
    try:
        require_mutating_jobs_disabled(enabled_action_mutation, "synthetic-action.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: action mutating job")
    quoted_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - run: "ssh runtime.example deploy"
"""
    try:
        require_mutating_jobs_disabled(quoted_mutation, "synthetic-quoted.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: quoted mutating command")
    github_script_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/github-script@0123456789012345678901234567890123456789
        with:
          script: await exec.exec('kubectl', ['apply', '-f', 'runtime.yml'])
"""
    try:
        require_mutating_jobs_disabled(github_script_mutation, "synthetic-github-script.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: github-script mutation")
    reusable_mutation = """name: synthetic
jobs:
  deploy:
    uses: vendor/runtime/.github/workflows/deploy.yml@0123456789012345678901234567890123456789
"""
    try:
        require_mutating_jobs_disabled(reusable_mutation, "synthetic-reusable.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: reusable workflow mutation")
    local_reusable = ROOT / ".github/workflows/.codestra-local-runtime-negative.yml"
    try:
        local_reusable.write_text(
            """name: synthetic local runtime
on: workflow_call
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - run: kubectl apply -f runtime.yml
""",
            encoding="utf-8",
        )
        caller = """name: synthetic caller
jobs:
  deploy:
    uses: ./.github/workflows/.codestra-local-runtime-negative.yml
"""
        try:
            require_mutating_jobs_disabled(caller, "synthetic-local-reusable.yml")
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: local reusable workflow mutation"
            )
    finally:
        local_reusable.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix=".codestra-contract-", dir=ROOT) as directory:
        local_script = Path(directory) / "runtime.sh"
        local_script.write_text("kubectl apply -f runtime.yml\n", encoding="utf-8")
        relative = local_script.relative_to(ROOT).as_posix()
        require(
            contains_runtime_mutation(f"bash {relative}"),
            "negative local interpreter script regression passed",
        )
    unsafe_validator = """import subprocess
subprocess.run([\"kubectl\", \"apply\", \"-f\", \"runtime.yml\"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_validator)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: runtime validator operation")
    unsafe_aliased_validator = """import subprocess as sp
sp.run(["kubectl", "apply", "-f", "runtime.yml"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_aliased_validator)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: aliased runtime operation")
    unsafe_urlopen = """import urllib.request
urllib.request.urlopen("https://runtime.example/mutate")
"""
    try:
        validate_release_validator_operations(unsafe_urlopen)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: unapproved URL opener")
    unsafe_status_writer = """import subprocess
subprocess.run([\"gh\", \"api\", \"--method\", \"POST\"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_status_writer)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: validator status writer")
    for command in (
        "curl -X POST https://runtime.example/mutate",
        "gh api --method POST repos/example/runtime/dispatches",
        "aws ecs update-service --cluster production --service api",
    ):
        require(
            contains_runtime_mutation(command),
            f"negative API mutation regression passed: {command}",
        )


def require_mutating_jobs_disabled(workflow: str, path: str) -> None:
    mutating_jobs = 0
    script_aliases = workflow_script_aliases(workflow, path)
    for job in workflow_jobs(workflow, path).values():
        if job_reusable_workflow_mutation(job, path) or any(
            contains_runtime_mutation(
                str(step.get("run", "")),
                script_aliases=script_aliases,
            )
            or contains_runtime_action(step)
            for step in workflow_steps(job, path)
        ):
            mutating_jobs += 1
            require(
                "RUNTIME_MUTATION_DISABLED=true" in job.raw,
                f"mutating job lacks disable marker: {path}",
            )
            require(
                job_condition(job) == "${{ false }}",
                f"mutating job is not unconditionally disabled: {path}",
            )
    require(mutating_jobs > 0, f"native mutation classification drift: {path}")


def require_image_publishing_jobs_disabled(workflow: str, path: str) -> None:
    publishing_jobs = 0
    for job in workflow_jobs(workflow, path).values():
        if any(
            contains_image_publication(step)
            for step in workflow_steps(job, path)
        ):
            publishing_jobs += 1
            require(
                "RUNTIME_MUTATION_DISABLED=true" in job.raw,
                f"image-publishing job lacks disable marker: {path}",
            )
            require(
                job_condition(job) == "${{ false }}",
                f"image-publishing job is not unconditionally disabled: {path}",
            )
    require(publishing_jobs > 0, f"image publication classification drift: {path}")


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
