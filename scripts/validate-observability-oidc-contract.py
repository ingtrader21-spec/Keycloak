#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT_DIR = ROOT / "config" / "clients"
CONTRACT_PATH = ROOT / "config" / "identity" / "observability-oidc-clients.json"
ROLES_PATH = ROOT / "config" / "roles" / "observability-realm-roles.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


contract = load(CONTRACT_PATH)
roles = load(ROLES_PATH)

expected_roles = [
    "observability-viewer",
    "observability-operator",
    "observability-admin",
    "secrets-operator",
    "secrets-admin",
]
actual_roles = [item["name"] for item in roles.get("roles", [])]
if actual_roles != expected_roles:
    raise SystemExit("OBSERVABILITY_OIDC_ERROR=realm_role_set")
if roles.get("realm") != "codestra" or roles.get("defaultAssignments") != []:
    raise SystemExit("OBSERVABILITY_OIDC_ERROR=unsafe_default_role_assignment")
if roles.get("automaticCrossClientInheritance") is not False:
    raise SystemExit("OBSERVABILITY_OIDC_ERROR=cross_client_inheritance")

if contract.get("issuer") != "https://auth.codestra.co/realms/codestra":
    raise SystemExit("OBSERVABILITY_OIDC_ERROR=issuer")
if contract.get("authorizationFlow") != "authorization_code":
    raise SystemExit("OBSERVABILITY_OIDC_ERROR=flow")
if contract.get("pkceMethod") != "S256":
    raise SystemExit("OBSERVABILITY_OIDC_ERROR=pkce")
for field in ("implicitFlowAllowed", "directAccessGrantAllowed", "deviceGrantAllowed"):
    if contract.get(field) is not False:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={field}")
credential_policy = contract.get("credentials") or {}
if credential_policy != {
    "externalSecretStoreOnly": True,
    "distinctPerClient": True,
    "sharedAcrossServices": False,
}:
    raise SystemExit("OBSERVABILITY_OIDC_ERROR=credential_policy")

expected = {
    "grafana": {
        "host": "graf.codestra.media",
        "redirect": "https://graf.codestra.media/login/generic_oauth",
        "roles": expected_roles[:3],
        "mfa": ["observability-admin"],
        "idle": "900",
        "maximum": "14400",
    },
    "superset": {
        "host": "supe.codestra.media",
        "redirect": "https://supe.codestra.media/oauth-authorized/keycloak",
        "roles": expected_roles[:3],
        "mfa": ["observability-admin"],
        "idle": "900",
        "maximum": "14400",
    },
    "openbao": {
        "host": "bao.codestra.media",
        "redirect": "https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback",
        "roles": expected_roles[3:],
        "mfa": expected_roles[3:],
        "idle": "600",
        "maximum": "3600",
    },
}

contract_clients = {item["clientId"]: item for item in contract.get("clients", [])}
if set(contract_clients) != set(expected):
    raise SystemExit("OBSERVABILITY_OIDC_ERROR=client_contract_set")

for client_id, policy in expected.items():
    client = load(CLIENT_DIR / f"{client_id}.json")
    declared = contract_clients[client_id]
    if client.get("clientId") != client_id or client.get("enabled") is not True:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:identity")
    if client.get("protocol") != "openid-connect":
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:protocol")
    if client.get("clientAuthenticatorType") != "client-secret":
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:authenticator")
    if client.get("publicClient") is not False or client.get("fullScopeAllowed") is not False:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:client_scope")
    if client.get("standardFlowEnabled") is not True:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:standard_flow")
    for forbidden in ("implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled"):
        if client.get(forbidden) is not False:
            raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:{forbidden}")
    if client.get("redirectUris") != [policy["redirect"]]:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:redirect")
    if client.get("webOrigins") != [f"https://{policy['host']}"]:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:origin")
    attributes = client.get("attributes") or {}
    if attributes.get("pkce.code.challenge.method") != "S256":
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:pkce")
    if attributes.get("access.token.lifespan") != "300":
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:token_lifetime")
    if attributes.get("client.session.idle.timeout") != policy["idle"]:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:session_idle")
    if attributes.get("client.session.max.lifespan") != policy["maximum"]:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:session_maximum")
    if "secret" in client:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:credential_in_git")
    if declared.get("canonicalHost") != policy["host"]:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:canonical_host")
    if declared.get("redirectUris") != [policy["redirect"]]:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:contract_redirect")
    if declared.get("allowedRealmRoles") != policy["roles"]:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:role_mapping")
    if declared.get("mfaRequiredRealmRoles") != policy["mfa"]:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR={client_id}:mfa_mapping")

openbao = contract_clients["openbao"]
if openbao.get("deniedRealmRoles") != expected_roles[:3]:
    raise SystemExit("OBSERVABILITY_OIDC_ERROR=openbao_role_separation")
if set(openbao["allowedRealmRoles"]) & set(openbao["deniedRealmRoles"]):
    raise SystemExit("OBSERVABILITY_OIDC_ERROR=openbao_role_overlap")

activation = contract.get("activation") or {}
if activation.get("sourceMergeAppliesRuntime") is not False:
    raise SystemExit("OBSERVABILITY_OIDC_ERROR=source_merge_must_not_apply")
for gate in (
    "independentDriftReviewRequired",
    "applicationRoleMappingEvidenceRequired",
    "mfaAcceptanceEvidenceRequired",
):
    if activation.get(gate) is not True:
        raise SystemExit(f"OBSERVABILITY_OIDC_ERROR=activation_gate:{gate}")

print("OBSERVABILITY_OIDC_CONTRACT=PASS")
print("OBSERVABILITY_OIDC_CLIENTS=grafana,superset,openbao")
print("OPENBAO_ROLE_SEPARATION=PASS")
print("ADMINISTRATIVE_MFA_POLICY=PASS")
print("LIVE_IDENTITY_APPLY_AUTHORIZED=NO")
