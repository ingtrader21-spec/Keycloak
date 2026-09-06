#!/usr/bin/env python3
"""Validate explicit Codestra realm, token, MFA, and recovery policy."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REALM = json.loads((ROOT / "config/realms/codestra.json").read_text())
POLICY = json.loads((ROOT / "config/security/realm-security-policy.json").read_text())
MACHINE = json.loads((ROOT / "config/contracts/machine-clients.json").read_text())
SMTP = json.loads((ROOT / "config/email/keycloak-security-smtp.json").read_text())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"REALM_SECURITY_POLICY_ERROR={message}")


require(REALM["realm"] == "codestra" and REALM["enabled"] is True, "realm identity")
require(REALM["sslRequired"] == "external", "external TLS")
for key in ("rememberMe", "duplicateEmailsAllowed", "editUsernameAllowed"):
    require(REALM[key] is False, f"{key} must be false")
require(REALM["registrationAllowed"] is True, "reviewed registration gate must be enabled")
require(REALM["registrationEmailAsUsername"] is True, "registration email identity")
require(REALM["loginTheme"] == "codestra-identity", "login theme")
require(REALM["emailTheme"] == "codestra-identity", "email theme")
for key in ("loginWithEmailAllowed", "resetPasswordAllowed"):
    require(REALM[key] is True, f"{key} must be true")
require(REALM["verifyEmail"] is False, "standard email verification must defer to reviewed MoneyBee OTP")

password_fragments = {
    "length(14)", "maxLength(128)", "upperCase(1)", "lowerCase(1)",
    "digits(1)", "specialChars(1)", "notUsername(undefined)",
    "notEmail(undefined)", "passwordHistory(12)", "hashIterations(600000)",
}
require(set(REALM["passwordPolicy"].split(" and ")) == password_fragments, "password policy")
passwords = POLICY["passwords"]
require(passwords["minimumLength"] == 14 and passwords["maximumLength"] == 128, "password length")
require(passwords["history"] >= 12 and passwords["hashIterations"] >= 600000, "password reuse/hash")
require(passwords["commonPasswordProviderState"] == "blocked-requires-reviewed-provider", "common-password blocker")

require(REALM["bruteForceProtected"] is True and REALM["failureFactor"] == 5, "brute force")
require(REALM["permanentLockout"] is False, "recoverable lockout")
require(60 <= REALM["waitIncrementSeconds"] <= 300, "wait increment")
require(REALM["maxFailureWaitSeconds"] == 900, "maximum failure wait")

require(REALM["ssoSessionIdleTimeout"] == 1800, "SSO idle")
require(REALM["ssoSessionMaxLifespan"] == 28800, "SSO max")
require(REALM["clientSessionIdleTimeout"] == 1800, "client idle")
require(REALM["clientSessionMaxLifespan"] == 28800, "client max")
require(REALM["offlineSessionIdleTimeout"] == 2592000, "offline idle")
require(REALM["offlineSessionMaxLifespanEnabled"] is True, "offline max enabled")
require(REALM["offlineSessionMaxLifespan"] == 7776000, "offline max")

require(REALM["accessTokenLifespan"] <= 300, "access-token maximum")
require(REALM["accessTokenLifespanForImplicitFlow"] == 0, "implicit token lifetime")
require(REALM["revokeRefreshToken"] is True and REALM["refreshTokenMaxReuse"] == 0, "refresh rotation")
require(REALM["actionTokenGeneratedByUserLifespan"] == 900, "user action token")
require(REALM["actionTokenGeneratedByAdminLifespan"] == 43200, "admin action token")
require(MACHINE["maximumAccessTokenLifetimeSeconds"] <= 300, "machine token maximum")
require(POLICY["machineTokens"]["refreshTokensAllowed"] is False, "machine refresh tokens")

require(REALM["otpPolicyType"] == "totp", "TOTP type")
require(REALM["otpPolicyAlgorithm"] == "HmacSHA256", "TOTP algorithm")
require(REALM["otpPolicyDigits"] == 6 and REALM["otpPolicyPeriod"] == 30, "TOTP parameters")
require(REALM["webAuthnPolicyRpId"] == "auth.codestra.co", "WebAuthn RP")
require(REALM["webAuthnPolicyUserVerificationRequirement"] == "required", "WebAuthn verification")
require(POLICY["administrators"]["mfaRequired"] is True, "administrator MFA")
require(POLICY["requiredActions"]["webauthnRegistrationForPrivilegedUsers"] is True, "privileged WebAuthn")
require(POLICY["requiredActions"]["moneybeeEmailOtp"] is True, "MoneyBee email OTP")

smtp = REALM["smtpServer"]
smtp_contract = SMTP["smtp"]
require(set(smtp) == {"host", "port", "from", "fromDisplayName", "replyTo", "envelopeFrom", "auth", "starttls", "ssl"}, "SMTP secret boundary")
require(smtp["host"] == "10.40.0.4" and smtp["port"] == "587", "SMTP endpoint")
require(smtp["auth"] == "true" and smtp["starttls"] == "true" and smtp["ssl"] == "false", "SMTP transport")

recovery = POLICY["accountRecovery"]
require(recovery["smtpContract"] == "config/email/keycloak-security-smtp.json", "SMTP linkage")
require(recovery["resetPasswordTokenLifespanSeconds"] == SMTP["passwordReset"]["resetTokenLifespanSeconds"], "reset lifespan")
require(recovery["liveTestState"] == "blocked-production-credentials-and-approval-required", "live evidence blocker")
require(POLICY["liveVerificationRequired"] is True, "live verification")

print("REALM_SECURITY_POLICY=PASS")
print("PASSWORD_POLICY=PASS")
print("BRUTE_FORCE_POLICY=PASS")
print("SESSION_POLICY=PASS")
print("TOKEN_POLICY=PASS")
print("MFA_POLICY=PASS")
print("ACCOUNT_RECOVERY_POLICY=PASS")
