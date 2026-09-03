#!/usr/bin/env python3
"""Render deterministic Keycloak client overlays from the reviewed service matrix."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/contracts/service-access-matrix.json"
CLIENT_DIR = ROOT / "config/clients"
CLIENT_SCOPE_DIR = ROOT / "config/client-scopes"
ALLOWLIST_DIR = ROOT / "config/export-allowlists"
MONITORING_CLIENT_ID = "monitoring-readonly"
MONITORING_OPTIONAL_SCOPES = ("health.read", "metrics.read")
MONITORING_TARGET = "middleware-api"
TENANT_BOUND_MIDDLEWARE_CALLERS = {"kong-gateway", "n8n-automation"}


def canonical(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=False) + "\n"


def mapper(name: str, mapper_type: str, config: dict[str, str]) -> dict[str, object]:
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": mapper_type,
        "consentRequired": False,
        "config": config,
    }


def monitoring_client_scope(scope_name: str) -> dict[str, object]:
    if scope_name not in MONITORING_OPTIONAL_SCOPES:
        raise ValueError(f"unsupported monitoring scope: {scope_name}")
    return {
        "name": scope_name,
        "description": (
            "Codestra optional monitoring scope managed by protected Keycloak GitOps. "
            "It is requested explicitly per short-lived service-account token."
        ),
        "protocol": "openid-connect",
        "attributes": {
            "display.on.consent.screen": "false",
            "include.in.token.scope": "true",
        },
        "protocolMappers": [],
    }


def render() -> dict[Path, str]:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    grants_by_caller: dict[str, list[dict[str, object]]] = {}
    for grant in contract["grants"]:
        grants_by_caller.setdefault(grant["callerClientId"], []).append(grant)

    rendered: dict[Path, str] = {}
    for service in contract["services"]:
        client_id = service["clientId"]
        grants = sorted(
            grants_by_caller.get(client_id, []), key=lambda item: item["targetClientId"]
        )
        audiences = sorted({grant["audience"] for grant in grants}) or [client_id]
        scopes = sorted({scope for grant in grants for scope in grant["scopes"]})

        mappers = [
            mapper(
                f"audience-{audience}",
                "oidc-audience-mapper",
                {
                    "included.custom.audience": audience,
                    "id.token.claim": "false",
                    "access.token.claim": "true",
                },
            )
            for audience in audiences
        ]
        optional_client_scopes: list[str] = []
        if client_id == MONITORING_CLIENT_ID:
            if len(grants) != 1 or grants[0].get("targetClientId") != MONITORING_TARGET:
                raise ValueError(
                    "monitoring-readonly must have exactly one grant to middleware-api"
                )
            if audiences != [MONITORING_TARGET]:
                raise ValueError(
                    "monitoring-readonly must have exactly the middleware-api audience"
                )
            if tuple(scopes) != MONITORING_OPTIONAL_SCOPES:
                raise ValueError(
                    "monitoring-readonly grants must contain only health.read and metrics.read"
                )
            optional_client_scopes = list(MONITORING_OPTIONAL_SCOPES)
            for scope_name in MONITORING_OPTIONAL_SCOPES:
                rendered[CLIENT_SCOPE_DIR / f"{scope_name}.json"] = canonical(
                    monitoring_client_scope(scope_name)
                )
        else:
            mappers.append(
                mapper(
                    "reviewed-service-scopes",
                    "oidc-hardcoded-claim-mapper",
                    {
                        "claim.name": "scope",
                        "claim.value": " ".join(scopes),
                        "jsonType.label": "String",
                        "id.token.claim": "false",
                        "access.token.claim": "true",
                        "userinfo.token.claim": "false",
                        "access.tokenResponse.claim": "false",
                    },
                )
            )
            if client_id in TENANT_BOUND_MIDDLEWARE_CALLERS:
                mappers.append(
                    mapper(
                        "tenant-id-from-service-account",
                        "oidc-usermodel-attribute-mapper",
                        {
                            "user.attribute": "tenant_id",
                            "claim.name": "tenant_id",
                            "jsonType.label": "String",
                            "id.token.claim": "false",
                            "access.token.claim": "true",
                            "userinfo.token.claim": "false",
                            "multivalued": "false",
                        },
                    )
                )

        overlay = {
            "clientId": client_id,
            "name": f"Codestra service identity: {client_id}",
            "description": "Confidential machine identity managed by protected Keycloak GitOps.",
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "bearerOnly": False,
            "consentRequired": False,
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": True,
            "authorizationServicesEnabled": False,
            "frontchannelLogout": False,
            "fullScopeAllowed": False,
            "redirectUris": [],
            "webOrigins": [],
            "defaultClientScopes": [],
            "optionalClientScopes": optional_client_scopes,
            "attributes": {
                "access.token.lifespan": str(
                    contract["tokenPolicy"]["maximumAccessTokenLifetimeSeconds"]
                ),
                "oauth2.device.authorization.grant.enabled": "false",
                "oidc.ciba.grant.enabled": "false",
            },
            "protocolMappers": mappers,
        }
        allowlist = {
            "clientId": client_id,
            "topLevelFields": list(overlay),
            "attributeFields": list(overlay["attributes"]),
        }
        rendered[CLIENT_DIR / f"{client_id}.json"] = canonical(overlay)
        rendered[ALLOWLIST_DIR / f"{client_id}.json"] = canonical(allowlist)
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("select exactly one of --write or --check")

    mismatches: list[str] = []
    for path, expected in render().items():
        if args.write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected, encoding="utf-8")
        elif not path.exists() or path.read_text(encoding="utf-8") != expected:
            mismatches.append(str(path.relative_to(ROOT)))
    if mismatches:
        for mismatch in mismatches:
            print(f"MACHINE_OVERLAY_DRIFT={mismatch}", file=sys.stderr)
        return 1
    print("MACHINE_CLIENT_OVERLAYS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
