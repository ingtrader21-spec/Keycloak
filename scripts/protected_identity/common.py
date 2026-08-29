from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config"
CLIENT_DIR = CONFIG / "clients"
ROLE_DIR = CONFIG / "realm-roles"
EXPORT_ALLOWLIST_DIR = CONFIG / "export-allowlists"
ROLE_EXPORT_ALLOWLIST_DIR = EXPORT_ALLOWLIST_DIR / "realm-roles"
CLIENT_POLICY = CONFIG / "policy" / "managed-clients.json"
CREATABLE_CLIENT_POLICY = CONFIG / "policy" / "creatable-clients.json"
ROLE_POLICY = CONFIG / "policy" / "managed-realm-roles.json"
CREATABLE_ROLE_POLICY = CONFIG / "policy" / "creatable-realm-roles.json"
SECRET_EXPORT_POLICY = CONFIG / "policy" / "secret-export-clients.json"
ENDPOINTS = CONFIG / "endpoints" / "codestra.json"

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9_.@-]{3,128}$")
SAFE_TICKET = re.compile(r"^[A-Za-z0-9_.:/-]{3,128}$")
SENSITIVE_KEYS = {
    "secret", "clientsecret", "client_secret", "password", "privatekey",
    "private_key", "access_token", "accesstoken", "refresh_token",
    "refreshtoken", "credential", "credentials", "registrationaccesstoken",
}

class EngineError(RuntimeError):
    pass


def fail(message: str) -> "NoReturn":  # type: ignore[name-defined]
    raise EngineError(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse JSON {path}: {exc}")


def ensure_regular(path: Path, *, must_exist: bool = True, absolute: bool = True) -> None:
    if absolute and not path.is_absolute():
        fail(f"path must be absolute: {path}")
    if path.is_symlink():
        fail(f"symlink paths are prohibited: {path}")
    if must_exist and not path.is_file():
        fail(f"regular file is required: {path}")


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def write_json(path: Path, value: Any, *, compact: bool = False, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        fail(f"refusing to replace symlink: {path}")
    if compact:
        data = canonical_bytes(value)
    else:
        data = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    path.write_bytes(data)
    path.chmod(mode)


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            normalized = key.replace("-", "_").lower()
            if normalized in SENSITIVE_KEYS:
                continue
            result[key] = sanitize(child)
        return result
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    return value


def assert_no_sensitive_fields(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.replace("-", "_").lower()
            if normalized in SENSITIVE_KEYS:
                fail(f"sensitive field {key!r} is prohibited in {label}")
            assert_no_sensitive_fields(child, label)
    elif isinstance(value, list):
        for child in value:
            assert_no_sensitive_fields(child, label)


def normalize(value: Any, resource_type: str) -> Any:
    value = sanitize(copy.deepcopy(value))
    if not isinstance(value, dict):
        return value
    if resource_type == "client":
        for field in ("redirectUris", "webOrigins", "defaultClientScopes", "optionalClientScopes"):
            if isinstance(value.get(field), list):
                value[field] = sorted(value[field])
        if isinstance(value.get("protocolMappers"), list):
            value["protocolMappers"] = sorted(value["protocolMappers"], key=lambda item: str(item.get("name", "")))
    elif resource_type == "realmRole":
        attributes = value.get("attributes")
        if isinstance(attributes, dict):
            for key, child in attributes.items():
                if isinstance(child, list):
                    attributes[key] = sorted(child)
    return value


def project(current: Any, wanted: Any) -> Any:
    if isinstance(wanted, dict):
        source = current if isinstance(current, dict) else {}
        return {key: project(source.get(key), child) for key, child in wanted.items()}
    if isinstance(wanted, list):
        source = current if isinstance(current, list) else []
        if wanted and all(isinstance(item, dict) and isinstance(item.get("name"), str) for item in wanted):
            by_name = {
                item.get("name"): item
                for item in source
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            }
            return [project(by_name.get(item["name"], {}), item) for item in wanted]
        return copy.deepcopy(source)
    return copy.deepcopy(current)


def merge_overlay(current: Any, desired: Any) -> Any:
    if isinstance(desired, dict):
        result = copy.deepcopy(current) if isinstance(current, dict) else {}
        for key, child in desired.items():
            result[key] = merge_overlay(result.get(key), child)
        return result
    if isinstance(desired, list):
        if desired and all(isinstance(item, dict) and isinstance(item.get("name"), str) for item in desired):
            existing = copy.deepcopy(current) if isinstance(current, list) else []
            by_name = {
                item.get("name"): item
                for item in existing
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            }
            desired_names = {item["name"] for item in desired}
            merged = [merge_overlay(by_name.get(item["name"], {}), item) for item in desired]
            merged.extend(
                item for item in existing
                if not (isinstance(item, dict) and item.get("name") in desired_names)
            )
            return merged
        return copy.deepcopy(desired)
    return copy.deepcopy(desired)


def load_policy(path: Path, field: str) -> list[str]:
    value = load_json(path)
    if not isinstance(value, dict) or not isinstance(value.get(field), list):
        fail(f"invalid policy {path}")
    items = value[field]
    if not all(isinstance(item, str) and item for item in items):
        fail(f"invalid entries in policy {path}")
    if len(items) != len(set(items)):
        fail(f"duplicate entries in policy {path}")
    return items


def load_desired(directory: Path, id_field: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not directory.is_dir():
        fail(f"desired-state directory is missing: {directory}")
    for path in sorted(directory.glob("*.json")):
        value = load_json(path)
        if not isinstance(value, dict) or not isinstance(value.get(id_field), str):
            fail(f"desired state has no {id_field}: {path}")
        resource_id = value[id_field]
        if resource_id in result:
            fail(f"duplicate desired-state ID {resource_id}")
        assert_no_sensitive_fields(value, str(path))
        result[resource_id] = value
    return result


def resource_actions(plan: dict[str, Any]) -> list[dict[str, Any]]:
    clients = plan.get("clients")
    roles = plan.get("realmRoles")
    if not isinstance(clients, list) or not isinstance(roles, list):
        fail("plan must contain clients and realmRoles arrays")
    resources = [*clients, *roles]
    return sorted(resources, key=lambda item: (str(item.get("resourceType")), str(item.get("resourceId"))))


def reviewed_action(resource: dict[str, Any]) -> dict[str, Any]:
    return {
        "resourceType": resource["resourceType"],
        "resourceId": resource["resourceId"],
        "action": resource["action"],
        "beforeSha256": resource["beforeSha256"],
        "desiredSha256": resource["desiredSha256"],
    }
