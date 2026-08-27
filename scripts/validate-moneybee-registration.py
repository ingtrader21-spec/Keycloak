#!/usr/bin/env python3
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
contract = json.loads((root / "config/identity/moneybee-registration.json").read_text())
producer = json.loads((root / "config/contracts/moneybee-backend-producer.json").read_text())
realm = json.loads((root / "config/realms/codestra.json").read_text())

assert contract["realm"] == "codestra"
assert contract["registrationAllowed"] is True
assert contract["registrationClient"] == "moneybee-borrower"
assert contract["deniedPublicRegistrationClients"] == ["moneybee-lender", "moneybee-admin"]
assert contract["registrationGateProvider"] == "moneybee-registration-gate"
assert contract["emailVerificationRequiredAction"] == "moneybee-verify-email-otp"
verification = contract["verification"]
assert verification == {
    "type": "numeric-email-otp",
    "length": 6,
    "ttlSeconds": 600,
    "maxAttempts": 5,
    "resendCooldownSeconds": 60,
    "maxSendsPerHour": 5,
    "oneTimeUse": True,
    "invalidatePreviousOnResend": True,
    "plaintextPersistence": False,
    "hmacSecretEnvironment": "MONEYBEE_EMAIL_OTP_HMAC_KEY",
}
assert realm["registrationAllowed"] is True
assert realm["registrationEmailAsUsername"] is True
assert realm["duplicateEmailsAllowed"] is False
assert realm["resetPasswordAllowed"] is True
assert realm["verifyEmail"] is False
assert realm["loginTheme"] == "codestra-identity"
assert realm["emailTheme"] == "codestra-identity"

assert producer == {
    "schemaVersion": 1,
    "issuer": "https://auth.codestra.co/realms/codestra",
    "clientId": "moneybee-backend",
    "clientType": "confidential",
    "grantType": "client_credentials",
    "serviceAccountsEnabled": True,
    "standardFlowEnabled": False,
    "implicitFlowEnabled": False,
    "directAccessGrantsEnabled": False,
    "targetClientId": "middleware-api",
    "audience": "middleware-api",
    "scopes": ["moneybee.events.publish"],
    "maximumAccessTokenLifetimeSeconds": 300,
    "refreshTokensAllowed": False,
    "fullScopeAllowed": False,
    "humanLoginAllowed": False,
    "keycloakAdminApiAccess": False,
    "prohibitedRealmManagementRoles": ["realm-admin", "manage-realm", "manage-clients"],
    "provisioningState": "declared-not-created",
}

global_machine = json.loads((root / "config/contracts/machine-clients.json").read_text())
global_access = json.loads((root / "config/contracts/service-access-matrix.json").read_text())
assert "moneybee-backend" not in {item["clientId"] for item in global_machine["clients"]}
assert "moneybee-backend" not in {item["clientId"] for item in global_access["services"]}

gate = (root / "extensions/moneybee-email-otp/src/main/java/co/codestra/keycloak/moneybee/MoneyBeeRegistrationGate.java").read_text()
otp = (root / "extensions/moneybee-email-otp/src/main/java/co/codestra/keycloak/moneybee/MoneyBeeEmailOtpRequiredAction.java").read_text()
plan = (root / "scripts/plan-moneybee-registration.sh").read_text()
assert 'BORROWER_CLIENT_ID = "moneybee-borrower"' in gate
assert 'addRequiredAction' in gate
assert 'isUserSetupAllowed()' in gate
assert 'MONEYBEE_EMAIL_OTP_HMAC_KEY' in otp
assert 'setEmailVerified(true)' in otp
assert 'moneybee.security.emailOtp.window' in otp
assert 'moneybee.security.emailOtp.sends' in otp
assert 'moneybee.security.emailOtp.lastSent' in otp
assert 'setSingleAttribute' in otp
assert '.requirement == "REQUIRED"' in plan
assert 'scope:"registration-form"' in plan
assert 'not REQUIRED inside the registration-form scope' in plan
assert 'plaintext' not in contract.get("verification", {})
print("MONEYBEE_REGISTRATION_CONTRACT=PASS")
print("MONEYBEE_BACKEND_PRODUCER_CONTRACT=PASS")
