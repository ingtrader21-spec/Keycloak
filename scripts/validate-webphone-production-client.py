#!/usr/bin/env python3
"""Validate the webphone compatibility identity without contacting Keycloak."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT = "codestra-provisioning-service"
SCOPES = ["identity:rotate", "provisioning:execute", "provisioning:read"]


def validate(contract, client):
    def require(ok, message):
        if not ok:
            raise ValueError(message)

    require(contract["clientId"] == CLIENT, "production client ID")
    require(contract["issuer"] == "https://auth.codestra.co/realms/codestra", "issuer")
    require(contract["audience"] == CLIENT, "audience")
    require(contract["claimName"] == "codestra_scopes", "scope claim")
    require(contract["scopes"] == SCOPES, "exact provisioning scopes")
    require(contract["maximumAccessTokenLifetimeSeconds"] == 300, "token lifetime")
    require(contract["realmRoles"] == [], "realm roles forbidden")
    require(contract["realmManagementRoles"] == ["view-users"], "read-only user lookup")
    require(contract["adapterCredentialSharingAllowed"] is False, "credential isolation")
    require(contract["consumer"] == "middleware-webphone-session-issuer", "consumer")
    require(contract["applyEnvironment"] == "KC_CLIENT_SECRET_CODESTRA_PROVISIONING_SERVICE",
            "protected credential binding")
    require(client["clientId"] == CLIENT, "overlay client ID")
    for key in ("enabled", "serviceAccountsEnabled"):
        require(client[key] is True, key)
    for key in ("publicClient", "bearerOnly", "standardFlowEnabled", "implicitFlowEnabled",
                "directAccessGrantsEnabled", "fullScopeAllowed", "authorizationServicesEnabled"):
        require(client[key] is False, key)
    for key in ("redirectUris", "webOrigins", "defaultClientScopes", "optionalClientScopes"):
        require(client[key] == [], key)
    require(client["attributes"]["access.token.lifespan"] == "300", "overlay lifetime")
    mappers = client["protocolMappers"]
    require(len(mappers) == 3, "exact mapper count")
    audience, scopes, roles = mappers
    require(audience["protocolMapper"] == "oidc-audience-mapper", "audience mapper")
    require(audience["config"] == {
        "included.custom.audience": CLIENT,
        "id.token.claim": "false", "access.token.claim": "true",
    }, "audience mapper contract")
    require(roles["protocolMapper"] == "oidc-usermodel-client-role-mapper", "role mapper")
    require(roles["config"] == {'usermodel.clientRoleMapping.clientId': 'realm-management', 'claim.name': 'resource_access.realm-management.roles', 'jsonType.label': 'String', 'multivalued': 'true', 'access.token.claim': 'true', 'id.token.claim': 'false', 'userinfo.token.claim': 'false', 'introspection.token.claim': 'false'}, "role mapper contract")
    require(scopes["protocolMapper"] == "oidc-hardcoded-claim-mapper", "scope mapper")
    require(scopes["config"] == {
        "claim.name": "codestra_scopes", "claim.value": " ".join(SCOPES),
        "jsonType.label": "String", "id.token.claim": "false",
        "access.token.claim": "true", "userinfo.token.claim": "false",
        "access.tokenResponse.claim": "false",
    }, "scope mapper contract")


if __name__ == "__main__":
    validate(
        json.loads((ROOT / "config/contracts/webphone-production-client.json").read_text()),
        json.loads((ROOT / f"config/clients/{CLIENT}.json").read_text()),
    )
    print("WEBPHONE_PRODUCTION_CLIENT_CONTRACT=PASS")
