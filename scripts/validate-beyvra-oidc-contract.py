#!/usr/bin/env python3
"""Validate the disabled, pre-activation Beyvra OIDC contract."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "identity" / "beyvra-oidc-client.json"


def require(condition, message):
    if not condition:
        raise SystemExit(f"BEYVRA_OIDC_CONTRACT_ERROR={message}")


def main():
    document = json.loads(CONTRACT.read_text(encoding="utf-8"))
    require(document["schemaVersion"] == 1, "schema version changed")
    require(document["realm"] == "codestra", "realm changed")
    require(document["issuer"] == "https://auth.codestra.co/realms/codestra", "issuer changed")
    require(document["provisioningState"] == "declared-runtime-verification-required", "contract activated in source")

    client = document["client"]
    require(client["clientId"] == "beyvra-web-production", "client id changed")
    require(client["enabled"] is False, "client must remain disabled before runtime verification")
    require(client["protocol"] == "openid-connect", "OIDC protocol is required")
    require(client["publicClient"] is True, "browser client must be public")
    require(client["standardFlowEnabled"] is True, "authorization code flow is required")
    require(client["implicitFlowEnabled"] is False, "implicit flow is forbidden")
    require(client["directAccessGrantsEnabled"] is False, "password grant is forbidden")
    require(client["deviceAuthorizationGrantEnabled"] is False, "device grant is forbidden")
    require(client["cibaGrantEnabled"] is False, "CIBA grant is forbidden")
    require(client["serviceAccountsEnabled"] is False, "browser service account is forbidden")
    require(client["pkceCodeChallengeMethod"] == "S256", "PKCE S256 is required")
    require(client["redirectUris"] == ["https://beyvra.com/api/v1/auth/oidc/callback/"], "redirect URI must be exact")
    require(client["postLogoutRedirectUris"] == ["https://beyvra.com/signIn?logged_out=1"], "post-logout URI must be exact")
    require(client["webOrigins"] == ["https://beyvra.com"], "web origin must be exact")
    require(document["apiAudience"] == "beyvra-api-production", "API audience changed")
    require(client["protocolMappers"] == [{
        "name": "beyvra-api-audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "consentRequired": False,
        "config": {
            "included.custom.audience": "beyvra-api-production",
            "access.token.claim": "true",
            "id.token.claim": "false",
        },
    }], "API audience mapper changed")

    roles = document["roles"]
    require(roles["default"] == ["beyvra-user"], "default role changed")
    require(roles["managed"] == ["beyvra-user", "beyvra-admin", "beyvra-super-admin"], "managed roles changed")

    registration = document["registrationPolicy"]
    require(registration == {
        "selfRegistration": True,
        "verifyEmail": True,
        "termsAcceptanceRequired": True,
        "passwordAuthority": "keycloak-only",
        "mfaAuthority": "keycloak-only",
        "adminMfaRequired": True,
    }, "registration authority changed")

    bff = document["backendForFrontend"]
    require(bff["callbackOwner"] == "beyvra-backend", "callback owner changed")
    require(bff["browserBearerStorageAllowed"] is False, "browser bearer storage is forbidden")
    require(bff["browserRefreshStorageAllowed"] is False, "browser refresh storage is forbidden")
    require(bff["identityBinding"] == "issuer-and-subject", "identity binding changed")
    require(bff["provisioningEvent"] == "identity.account.provisioned", "provisioning event changed")

    recovery = document["passwordRecovery"]
    require(recovery["localResetAllowed"] is False, "local reset is forbidden")
    require(recovery["authority"] == "keycloak", "recovery authority changed")
    require(recovery["securityMailContract"] == "config/email/keycloak-security-smtp.json", "mail contract changed")
    require(recovery["resetTokenLifetimeSeconds"] == 900, "reset token lifetime changed")

    required_gates = {
        "runtime-client-does-not-exist-or-matches-reviewed-export",
        "exact-redirect-and-origin-probe-passes",
        "beyvra-same-origin-api-proxy-passes",
        "klyrow-security-smtp-starttls-auth-passes",
        "password-reset-send-and-consume-smoke-test-passes",
        "rollback-plan-and-reviewed-apply-plan-hash-exist",
    }
    require(set(document["activationGates"]) == required_gates, "activation gates changed")
    serialized = CONTRACT.read_text(encoding="utf-8").lower()
    require("*" not in serialized, "wildcards are forbidden")
    legacy_issuer = "auth.codestra" + ".agency"
    require(legacy_issuer not in serialized, "legacy issuer is forbidden")
    print("BEYVRA_OIDC_CONTRACT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
