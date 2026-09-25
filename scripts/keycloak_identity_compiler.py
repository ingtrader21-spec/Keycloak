#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REALM = ROOT / "config" / "realms" / "codestra.json"
CLIENTS = ROOT / "config" / "clients"
SCOPES = ROOT / "config" / "client-scopes"
DESIRED_STATE = ROOT / "config" / "desired-state"
OUT = ROOT / "generated" / "keycloak-identity-authority.v1.json"


class IdentityModelError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise IdentityModelError(f"load_failed:{path.name}:{exc}") from exc
    if not isinstance(value, dict):
        raise IdentityModelError(f"not_object:{path.name}")
    return value


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def validate_client(client: dict[str, Any]) -> None:
    client_id = str(client.get("clientId") or "")
    if not client_id:
        raise IdentityModelError("client_missing_id")

    redirects = list(client.get("redirectUris") or [])
    origins = list(client.get("webOrigins") or [])
    for value in redirects + origins:
        if value in {"*", "+"} or value.endswith("/*"):
            raise IdentityModelError(f"{client_id}:unsafe_redirect_or_origin")

    if client.get("directAccessGrantsEnabled") is True:
        raise IdentityModelError(f"{client_id}:direct_grants_forbidden")

    if client.get("serviceAccountsEnabled") is True:
        if client.get("publicClient") is not False or client.get("standardFlowEnabled") is not False:
            raise IdentityModelError(f"{client_id}:invalid_service_client")
        if redirects or origins:
            raise IdentityModelError(f"{client_id}:service_client_redirects_forbidden")
        if client.get("fullScopeAllowed") is not False:
            raise IdentityModelError(f"{client_id}:service_full_scope_forbidden")
    elif client.get("publicClient") is True and client.get("standardFlowEnabled") is not True:
        raise IdentityModelError(f"{client_id}:public_client_requires_code_flow")

    for mapper in client.get("protocolMappers") or []:
        config = mapper.get("config") or {}
        if any(
            key.lower() in {"secret", "client_secret", "password", "credential"} and config.get(key)
            for key in config
        ):
            raise IdentityModelError(f"{client_id}:secret_in_mapper")


def _unique_by(
    documents: list[tuple[Path, dict[str, Any]]],
    key: str,
    label: str,
) -> list[dict[str, Any]]:
    seen: dict[str, str] = {}
    output: list[dict[str, Any]] = []
    for path, document in documents:
        resource_id = str(document.get(key) or "")
        if not resource_id:
            raise IdentityModelError(f"{label}_missing_id:{path.relative_to(ROOT).as_posix()}")
        fingerprint = canonical(document)
        if resource_id in seen and seen[resource_id] != fingerprint:
            raise IdentityModelError(f"conflicting_{label}:{resource_id}")
        if resource_id in seen:
            continue
        seen[resource_id] = fingerprint
        output.append(document)
    return sorted(output, key=lambda item: str(item.get(key) or ""))


def _nested_documents(directory_name: str) -> list[tuple[Path, dict[str, Any]]]:
    rows: list[tuple[Path, dict[str, Any]]] = []
    if not DESIRED_STATE.exists():
        return rows
    for path in sorted(DESIRED_STATE.rglob("*.json")):
        if path.parent.name == directory_name:
            rows.append((path, load_json(path)))
    return rows


def compile_identity() -> dict[str, Any]:
    realm = load_json(REALM)
    protected_client_docs = [(path, load_json(path)) for path in sorted(CLIENTS.glob("*.json"))]
    staged_client_docs = _nested_documents("clients")
    top_scope_docs = [(path, load_json(path)) for path in sorted(SCOPES.glob("*.json"))]
    nested_scope_docs = _nested_documents("client-scopes")
    role_docs = _nested_documents("realm-roles")

    if realm.get("realm") != "codestra" or realm.get("enabled") is not True:
        raise IdentityModelError("realm_invalid")

    protected_clients = _unique_by(protected_client_docs, "clientId", "client")
    for client in protected_clients:
        validate_client(client)

    protected_ids = {client["clientId"] for client in protected_clients}
    scopes = _unique_by(top_scope_docs + nested_scope_docs, "name", "scope")
    roles = _unique_by(role_docs, "name", "realm_role")

    staged_with_provenance = []
    staged_group_ids: set[tuple[str, str]] = set()
    for path, client in staged_client_docs:
        validate_client(client)
        group = path.parents[1].name
        client_id = str(client["clientId"])
        group_key = (group, client_id)
        if group_key in staged_group_ids:
            raise IdentityModelError(f"duplicate_staged_client:{group}:{client_id}")
        staged_group_ids.add(group_key)
        if client_id in protected_ids:
            raise IdentityModelError(f"protected_staged_client_overlap:{client_id}")
        staged_with_provenance.append(
            {
                "authorityGroup": group,
                "sourcePath": path.relative_to(ROOT).as_posix(),
                "client": client,
            }
        )
    staged_with_provenance.sort(key=lambda item: (item["authorityGroup"], item["client"]["clientId"]))

    model: dict[str, Any] = {
        "schema": "codestra.keycloak.identity-authority.v1",
        "realm": {
            "realm": realm["realm"],
            "enabled": realm["enabled"],
            "sslRequired": realm.get("sslRequired"),
            "verifyEmail": realm.get("verifyEmail"),
            "resetPasswordAllowed": realm.get("resetPasswordAllowed"),
            "bruteForceProtected": realm.get("bruteForceProtected"),
            "accessTokenLifespan": realm.get("accessTokenLifespan"),
        },
        "clients": protected_clients,
        "stagedClients": staged_with_provenance,
        "clientScopes": scopes,
        "realmRoles": roles,
        "environmentBoundaries": {
            "production": {"issuer": "https://auth.codestra.co/realms/codestra"},
            "staging": {"issuer": "https://auth-staging.codestra.co/realms/codestra"},
            "testSyn": {"namingPrefix": "test-syn-", "productionPromotion": False},
        },
    }
    model["sourceSha256"] = sha(model)
    return model


def write_output(check: bool = False) -> dict[str, Any]:
    model = compile_identity()
    text = json.dumps(model, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise IdentityModelError("generated_identity_drift")
    else:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf-8")
    return model


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        model = write_output(args.check)
    except IdentityModelError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(
        json.dumps(
            {
                "ok": True,
                "clients": len(model["clients"]),
                "stagedClients": len(model["stagedClients"]),
                "scopes": len(model["clientScopes"]),
                "roles": len(model["realmRoles"]),
                "sha256": model["sourceSha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
