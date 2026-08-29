#!/usr/bin/env python3
"""Pure policy checks shared by source validation and the mutation engine."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

CLIENT_IDS = ["grafana-observability", "superset-analytics", "openbao-secrets"]
ROLE_IDS = ["observability-viewer", "observability-operator", "observability-admin", "secrets-operator", "secrets-admin"]
CLIENTS = {
    "grafana-observability": {
        "origin": "https://graf.codestra.media",
        "redirects": ["https://graf.codestra.media/login/generic_oauth"],
        "roles": {"observability-viewer", "observability-operator", "observability-admin"},
    },
    "superset-analytics": {
        "origin": "https://supe.codestra.media",
        "redirects": ["https://supe.codestra.media/oauth-authorized/keycloak"],
        "roles": {"observability-viewer", "observability-operator", "observability-admin"},
    },
    "openbao-secrets": {
        "origin": "https://bao.codestra.media",
        "redirects": [
            "https://bao.codestra.media/v1/auth/oidc/callback",
            "https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback",
            "http://localhost:8250/oidc/callback",
        ],
        "roles": {"secrets-operator", "secrets-admin"},
    },
}
SENSITIVE = re.compile(r"^(secret|clientsecret|client_secret|password|privatekey|private_key|access_token|accesstoken|refresh_token|refreshtoken|credential|credentials)$", re.I)


class PolicyError(ValueError):
    pass


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot parse {path}: {exc}") from exc


def assert_no_secret(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE.fullmatch(key) and child not in (None, "", [], {}):
                raise PolicyError(f"secret-bearing field {label}.{key}")
            assert_no_secret(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_secret(child, f"{label}[{index}]")


def validate_client(client_id: str, client: dict[str, Any]) -> None:
    expected = CLIENTS[client_id]
    assert_no_secret(client, client_id)
    required_false = ("publicClient", "bearerOnly", "implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled", "authorizationServicesEnabled")
    if client.get("clientId") != client_id or client.get("enabled") is not True or client.get("protocol") != "openid-connect":
        raise PolicyError(f"{client_id}: identity or protocol mismatch")
    if client.get("clientAuthenticatorType") != "client-secret" or client.get("standardFlowEnabled") is not True:
        raise PolicyError(f"{client_id}: confidential authorization-code client required")
    if any(client.get(field) is not False for field in required_false):
        raise PolicyError(f"{client_id}: unsafe grant, client mode, or authorization service enabled")
    if client.get("fullScopeAllowed") is not False:
        raise PolicyError(f"{client_id}: full scope is prohibited")
    if client.get("rootUrl") != expected["origin"] or client.get("webOrigins") != [expected["origin"]] or client.get("redirectUris") != expected["redirects"]:
        raise PolicyError(f"{client_id}: URL contract mismatch")
    attributes = client.get("attributes", {})
    if attributes.get("pkce.code.challenge.method") != "S256" or attributes.get("access.token.lifespan") != "300":
        raise PolicyError(f"{client_id}: PKCE S256 and 300-second access tokens are required")
    if attributes.get("oauth2.device.authorization.grant.enabled") != "false" or attributes.get("oidc.ciba.grant.enabled") != "false":
        raise PolicyError(f"{client_id}: device/CIBA grants are prohibited")
    mappers = [item for item in client.get("protocolMappers", []) if isinstance(item, dict) and item.get("name") == "codestra-realm-roles"]
    if len(mappers) != 1:
        raise PolicyError(f"{client_id}: exactly one realm-role mapper is required")
    mapper = mappers[0]
    if mapper.get("protocolMapper") != "oidc-usermodel-realm-role-mapper" or mapper.get("config") != {
        "multivalued": "true",
        "userinfo.token.claim": "true",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "claim.name": "realm_access.roles",
        "jsonType.label": "String",
    }:
        raise PolicyError(f"{client_id}: realm-role token mapper mismatch")


def validate_role(role_name: str, role: dict[str, Any]) -> None:
    assert_no_secret(role, role_name)
    expected_family = "observability" if role_name.startswith("observability-") else "secrets"
    expected_level = role_name.rsplit("-", 1)[-1]
    attributes = role.get("attributes", {})
    if role.get("name") != role_name or role.get("composite") is not False or role.get("clientRole") is not False:
        raise PolicyError(f"{role_name}: non-composite realm role required")
    if attributes.get("codestra.role.family") != [expected_family] or attributes.get("codestra.role.level") != [expected_level]:
        raise PolicyError(f"{role_name}: family/level mismatch")
    if attributes.get("codestra.assignment.independent_approval") != ["true"] or attributes.get("codestra.cross_family_grant") != ["false"]:
        raise PolicyError(f"{role_name}: assignment/isolation policy mismatch")
    expected_mfa = "false" if role_name == "observability-viewer" else "true"
    if attributes.get("codestra.mfa.required") != [expected_mfa]:
        raise PolicyError(f"{role_name}: MFA policy mismatch")


def validate_source(config: Path) -> None:
    client_dir = config / "clients"
    role_dir = config / "realm-roles"
    managed = load(config / "policy" / "managed-clients.json")["clients"]
    creatable = load(config / "policy" / "creatable-clients.json")["clients"]
    if any(item not in managed or item not in creatable for item in CLIENT_IDS):
        raise PolicyError("observability clients must be managed and creatable")
    if load(config / "policy" / "managed-realm-roles.json")["roles"] != ROLE_IDS or load(config / "policy" / "creatable-realm-roles.json")["roles"] != ROLE_IDS:
        raise PolicyError("realm-role policies must match the reviewed role set")
    if load(config / "policy" / "secret-export-clients.json")["clients"] != CLIENT_IDS:
        raise PolicyError("secret export policy mismatch")
    for client_id in CLIENT_IDS:
        validate_client(client_id, load(client_dir / f"{client_id}.json"))
    for role_name in ROLE_IDS:
        validate_role(role_name, load(role_dir / f"{role_name}.json"))
    contract = load(config / "contracts" / "observability-browser-clients.json")
    if [item.get("clientId") for item in contract.get("clients", [])] != CLIENT_IDS:
        raise PolicyError("contract client set/order mismatch")
    for item in contract["clients"]:
        expected = CLIENTS[item["clientId"]]
        if item.get("redirectUris") != expected["redirects"] or item.get("webOrigins") != [expected["origin"]] or set(item.get("requiredRoles", [])) != expected["roles"]:
            raise PolicyError(f"{item['clientId']}: contract/managed-source mismatch")
    if contract.get("activation") != {
        "contractReviewed": True,
        "managedClientApplySupportAdded": True,
        "liveClientsCreated": False,
        "liveSecretsGenerated": False,
        "productionAccessEnabled": False,
    }:
        raise PolicyError("source support must not claim live activation")


def negative_self_test(config: Path) -> None:
    client = copy.deepcopy(load(config / "clients" / "grafana-observability.json"))
    client["directAccessGrantsEnabled"] = True
    try:
        validate_client("grafana-observability", client)
    except PolicyError:
        pass
    else:
        raise PolicyError("unsafe direct grant was not rejected")

    client = copy.deepcopy(load(config / "clients" / "openbao-secrets.json"))
    client["redirectUris"].append("https://evil.example/callback")
    try:
        validate_client("openbao-secrets", client)
    except PolicyError:
        pass
    else:
        raise PolicyError("callback drift was not rejected")

    role = copy.deepcopy(load(config / "realm-roles" / "secrets-admin.json"))
    role["attributes"]["codestra.role.family"] = ["observability"]
    try:
        validate_role("secrets-admin", role)
    except PolicyError:
        pass
    else:
        raise PolicyError("cross-family role drift was not rejected")
