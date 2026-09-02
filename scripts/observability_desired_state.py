#!/usr/bin/env python3
"""Validate and deterministically render the repository-only observability plan."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
DESIRED_ROOT = ROOT / "config" / "desired-state" / "observability"
CONTRACT_PATH = ROOT / "config" / "contracts" / "observability-browser-clients.json"
OUTPUT_DIR = ROOT / "release" / "observability"
PLAN_PATH = OUTPUT_DIR / "keycloak-observability-desired-state-plan.json"
CHECKSUM_PATH = OUTPUT_DIR / "keycloak-observability-desired-state-plan.sha256"

CLIENTS = {
    "grafana-observability": {
        "origin": "https://graf.codestra.media",
        "redirects": ["https://graf.codestra.media/login/generic_oauth"],
        "roles": ["observability-viewer", "observability-operator", "observability-admin"],
        "mfa": ["observability-operator", "observability-admin"],
        "idle": "900",
        "maximum": "14400",
        "secret_file": "/run/secrets/grafana_oidc_client_secret",
    },
    "superset-analytics": {
        "origin": "https://supe.codestra.media",
        "redirects": ["https://supe.codestra.media/oauth-authorized/keycloak"],
        "roles": ["observability-viewer", "observability-operator", "observability-admin"],
        "mfa": ["observability-operator", "observability-admin"],
        "idle": "900",
        "maximum": "14400",
        "secret_file": "/run/secrets/superset_oidc_client_secret",
    },
    "openbao-secrets": {
        "origin": "https://bao.codestra.media",
        "redirects": [
            "https://bao.codestra.media/v1/auth/oidc/callback",
            "https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback",
            "http://localhost:8250/oidc/callback",
        ],
        "roles": ["secrets-operator", "secrets-admin"],
        "mfa": ["secrets-operator", "secrets-admin"],
        "idle": "600",
        "maximum": "3600",
        "secret_file": "/run/secrets/openbao_oidc_client_secret",
    },
}
ROLES = {
    "observability-viewer": ("observability", "viewer", "false"),
    "observability-operator": ("observability", "operator", "true"),
    "observability-admin": ("observability", "admin", "true"),
    "secrets-operator": ("secrets", "operator", "true"),
    "secrets-admin": ("secrets", "admin", "true"),
}
SENSITIVE_KEY = re.compile(
    r"^(secret|clientsecret|client_secret|password|privatekey|private_key|"
    r"access_token|accesstoken|refresh_token|refreshtoken|credential|credentials)$",
    re.IGNORECASE,
)


class DesiredStateError(ValueError):
    """The checked-in desired state violates the repository-only contract."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DesiredStateError(f"cannot parse {path.relative_to(ROOT)}: {exc}") from exc
    if not isinstance(value, dict):
        raise DesiredStateError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def assert_no_secret(value: Any, location: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE_KEY.fullmatch(str(key)) and child not in (None, "", [], {}):
                raise DesiredStateError(f"secret-bearing value at {location}.{key}")
            assert_no_secret(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_secret(child, f"{location}[{index}]")


def valid_callback(value: str) -> bool:
    parsed = urlparse(value)
    if "*" in value or parsed.username or parsed.password or parsed.fragment:
        return False
    if parsed.scheme == "https" and parsed.hostname:
        return True
    return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}


def validate_client(client_id: str, client: dict[str, Any]) -> None:
    expected = CLIENTS[client_id]
    assert_no_secret(client, client_id)
    if client.get("clientId") != client_id or client.get("enabled") is not True:
        raise DesiredStateError(f"{client_id}: identity or enabled state mismatch")
    exact_values = {
        "protocol": "openid-connect",
        "clientAuthenticatorType": "client-secret",
        "publicClient": False,
        "bearerOnly": False,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "authorizationServicesEnabled": False,
        "fullScopeAllowed": False,
        "rootUrl": expected["origin"],
        "webOrigins": [expected["origin"]],
        "redirectUris": expected["redirects"],
    }
    for field, required in exact_values.items():
        if client.get(field) != required:
            raise DesiredStateError(f"{client_id}: invalid {field}")
    if not all(valid_callback(value) for value in client["redirectUris"] + client["webOrigins"]):
        raise DesiredStateError(f"{client_id}: unsafe callback or origin")
    attributes = client.get("attributes", {})
    required_attributes = {
        "pkce.code.challenge.method": "S256",
        "post.logout.redirect.uris": expected["origin"] + "/",
        "oauth2.device.authorization.grant.enabled": "false",
        "oidc.ciba.grant.enabled": "false",
        "access.token.lifespan": "300",
        "client.session.idle.timeout": expected["idle"],
        "client.session.max.lifespan": expected["maximum"],
    }
    if attributes != required_attributes:
        raise DesiredStateError(f"{client_id}: token, session, PKCE, or logout policy mismatch")
    expected_mapper = {
        "name": "codestra-realm-roles",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-realm-role-mapper",
        "consentRequired": False,
        "config": {
            "multivalued": "true",
            "userinfo.token.claim": "true",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "realm_access.roles",
            "jsonType.label": "String",
        },
    }
    if client.get("protocolMappers") != [expected_mapper]:
        raise DesiredStateError(f"{client_id}: realm-role mapper mismatch")


def validate_role(role_name: str, role: dict[str, Any]) -> None:
    family, level, mfa = ROLES[role_name]
    assert_no_secret(role, role_name)
    if role.get("name") != role_name or role.get("composite") is not False or role.get("clientRole") is not False:
        raise DesiredStateError(f"{role_name}: must be a non-composite realm role")
    if role.get("attributes") != {
        "codestra.role.family": [family],
        "codestra.role.level": [level],
        "codestra.mfa.required": [mfa],
        "codestra.assignment.independent_approval": ["true"],
        "codestra.cross_family_grant": ["false"],
    }:
        raise DesiredStateError(f"{role_name}: role isolation, MFA, or approval policy mismatch")


def source_documents() -> list[tuple[Path, dict[str, Any]]]:
    documents: list[tuple[Path, dict[str, Any]]] = [(CONTRACT_PATH, load_json(CONTRACT_PATH))]
    for client_id in CLIENTS:
        path = DESIRED_ROOT / "clients" / f"{client_id}.json"
        documents.append((path, load_json(path)))
    for role_name in ROLES:
        path = DESIRED_ROOT / "realm-roles" / f"{role_name}.json"
        documents.append((path, load_json(path)))
    return documents


def validate() -> list[tuple[Path, dict[str, Any]]]:
    documents = source_documents()
    values = {path: value for path, value in documents}
    for client_id in CLIENTS:
        validate_client(client_id, values[DESIRED_ROOT / "clients" / f"{client_id}.json"])
    for role_name in ROLES:
        validate_role(role_name, values[DESIRED_ROOT / "realm-roles" / f"{role_name}.json"])

    contract = values[CONTRACT_PATH]
    if contract.get("schemaVersion") != 1 or contract.get("issuer") != "https://auth.codestra.co/realms/codestra":
        raise DesiredStateError("contract schema or issuer mismatch")
    contract_clients = contract.get("clients", [])
    if [item.get("clientId") for item in contract_clients] != list(CLIENTS):
        raise DesiredStateError("contract client set or order mismatch")
    for item in contract_clients:
        expected = CLIENTS[item["clientId"]]
        if item.get("applicationUrl") != expected["origin"] or item.get("redirectUris") != expected["redirects"]:
            raise DesiredStateError(f"{item['clientId']}: contract URL mismatch")
        if item.get("postLogoutRedirectUris") != [expected["origin"] + "/"]:
            raise DesiredStateError(f"{item['clientId']}: contract logout URL mismatch")
        if item.get("roles") != expected["roles"] or item.get("mfaRequiredRoles") != expected["mfa"]:
            raise DesiredStateError(f"{item['clientId']}: contract role or MFA mismatch")
        if item.get("clientSecretAuthority") != "openbao" or item.get("runtimeSecretFile") != expected["secret_file"]:
            raise DesiredStateError(f"{item['clientId']}: external secret authority mismatch")
    expected_isolation = {
        "observabilityRolesGrantSecretsAccess": False,
        "secretsRolesGrantObservabilityAccess": False,
        "emailAddressGrantsAdministrativeAccess": False,
        "administrativeMfaRequired": True,
        "roleAssignmentRequiresIndependentApproval": True,
    }
    if contract.get("roleIsolation") != expected_isolation:
        raise DesiredStateError("role isolation contract mismatch")
    expected_activation = {
        "desiredStatePrepared": True,
        "renderedPlanPrepared": True,
        "liveStateRead": False,
        "liveApplyAuthorized": False,
        "liveApplyPerformed": False,
        "secretsGenerated": False,
        "roleAssignmentsApplied": False,
        "productionAccessEnabled": False,
    }
    if contract.get("activation") != expected_activation:
        raise DesiredStateError("activation must remain repository-only and unapplied")

    managed = load_json(ROOT / "config" / "policy" / "managed-clients.json").get("clients", [])
    creatable = load_json(ROOT / "config" / "policy" / "creatable-clients.json").get("clients", [])
    if set(CLIENTS) & (set(managed) | set(creatable)):
        raise DesiredStateError("validate-only clients must not enter a live-capable managed policy")
    return documents


def build_plan() -> dict[str, Any]:
    documents = validate()
    source_files = []
    checksum_input = bytearray()
    for path, value in sorted(documents, key=lambda item: str(item[0].relative_to(ROOT))):
        relative = str(path.relative_to(ROOT))
        payload = canonical(value)
        checksum_input.extend(relative.encode() + b"\0" + payload)
        source_files.append({"path": relative, "sha256": hashlib.sha256(payload).hexdigest()})
    configuration_checksum = hashlib.sha256(checksum_input).hexdigest()
    operations = []
    for client_id in CLIENTS:
        desired = load_json(DESIRED_ROOT / "clients" / f"{client_id}.json")
        operations.append({
            "resourceType": "client",
            "resourceId": client_id,
            "action": "RECONCILE_IN_LATER_AUTHORIZED_MISSION",
            "desiredSha256": hashlib.sha256(canonical(desired)).hexdigest(),
        })
    for role_name in ROLES:
        desired = load_json(DESIRED_ROOT / "realm-roles" / f"{role_name}.json")
        operations.append({
            "resourceType": "realm-role",
            "resourceId": role_name,
            "action": "RECONCILE_IN_LATER_AUTHORIZED_MISSION",
            "desiredSha256": hashlib.sha256(canonical(desired)).hexdigest(),
        })
    return {
        "schemaVersion": 1,
        "kind": "CodestraKeycloakObservabilityDesiredStatePlan",
        "realm": "codestra",
        "issuer": "https://auth.codestra.co/realms/codestra",
        "configurationChecksum": configuration_checksum,
        "sourceFiles": source_files,
        "operations": operations,
        "repositoryBoundary": {
            "runtimeStateRead": False,
            "liveApplyAuthorized": False,
            "liveApplyPerformed": False,
            "secretsGenerated": False,
        },
        "activationPreconditions": [
            "protected merge SHA recorded",
            "independently reviewed live-state plan",
            "before-state rollback bundle and checksum",
            "approved secret handoff to runtime files",
            "authorized later server mission",
        ],
        "rollback": {
            "existingResourceBeforeStateRequired": True,
            "newClientSequence": ["disable", "verify no active use", "separately approve deletion"],
            "newRoleSequence": ["remove assignments", "verify zero mappings", "separately approve deletion"],
        },
    }


def rendered_bytes(plan: dict[str, Any]) -> bytes:
    return (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode()


def write_artifacts(plan: dict[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = rendered_bytes(plan)
    PLAN_PATH.write_bytes(payload)
    CHECKSUM_PATH.write_text(
        f"{hashlib.sha256(payload).hexdigest()}  {PLAN_PATH.name}\n",
        encoding="utf-8",
    )


def check_artifacts(plan: dict[str, Any]) -> None:
    expected = rendered_bytes(plan)
    try:
        actual = PLAN_PATH.read_bytes()
        checksum = CHECKSUM_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise DesiredStateError(f"rendered plan artifact missing: {exc}") from exc
    if actual != expected:
        raise DesiredStateError("rendered plan is stale; run with --write")
    expected_checksum = f"{hashlib.sha256(actual).hexdigest()}  {PLAN_PATH.name}\n"
    if checksum != expected_checksum:
        raise DesiredStateError("rendered plan checksum is stale or malformed")


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true", help="write the deterministic source plan")
    group.add_argument("--check", action="store_true", help="validate source and committed artifacts")
    args = parser.parse_args()
    try:
        plan = build_plan()
        if args.write:
            write_artifacts(plan)
        else:
            check_artifacts(plan)
    except DesiredStateError as exc:
        print(f"OBSERVABILITY_DESIRED_STATE_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
    print("KEYCLOAK_OBSERVABILITY_DESIRED_STATE=PASS")
    print(f"KEYCLOAK_OBSERVABILITY_CONFIGURATION_CHECKSUM={plan['configurationChecksum']}")
    print("KEYCLOAK_LIVE_APPLY=PROHIBITED")


if __name__ == "__main__":
    main()
