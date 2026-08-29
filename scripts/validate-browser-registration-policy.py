#!/usr/bin/env python3
"""Validate fail-closed browser self-registration for MoneyBee and Beyvra."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "identity" / "browser-registration-policy.json"
REALM = ROOT / "config" / "realms" / "codestra.json"
MONEYBEE = ROOT / "config" / "identity" / "moneybee-oidc-clients.json"
BEYVRA = ROOT / "config" / "identity" / "beyvra-oidc-client.json"
SMTP = ROOT / "config" / "email" / "keycloak-security-smtp.json"
DOCKERFILE = ROOT / "Dockerfile"
JAVA = (
    ROOT
    / "extensions"
    / "codestra-registration-gate"
    / "src"
    / "main"
    / "java"
    / "co"
    / "codestra"
    / "keycloak"
    / "registration"
    / "CodestraRegistrationGate.java"
)
SERVICE = (
    ROOT
    / "extensions"
    / "codestra-registration-gate"
    / "src"
    / "main"
    / "resources"
    / "META-INF"
    / "services"
    / "org.keycloak.authentication.FormActionFactory"
)

CANONICAL_ISSUER = "https://auth.codestra.co/realms/codestra"
ALLOWED = ["moneybee-borrower", "beyvra-web-production"]
DENIED = ["moneybee-lender", "moneybee-admin"]


class ValidationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable to load {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def validate() -> None:
    policy = load(POLICY)
    realm = load(REALM)
    moneybee = load(MONEYBEE)
    beyvra = load(BEYVRA)
    smtp = load(SMTP)

    if policy.get("schemaVersion") != 1:
        fail("browser registration schemaVersion must be 1")
    if policy.get("realm") != "codestra" or policy.get("issuer") != CANONICAL_ISSUER:
        fail("browser registration must use the canonical codestra realm")
    if policy.get("state") != "desired-flow-not-activated":
        fail("registration policy must remain fail-closed until gated-flow readback")
    if policy.get("providerId") != "codestra-registration-gate":
        fail("registration gate provider ID changed")
    if policy.get("registrationFlow") != "codestra-registration":
        fail("registration flow alias changed")
    if policy.get("allowedPublicRegistrationClients") != ALLOWED:
        fail("only MoneyBee borrower and Beyvra may self-register")
    if policy.get("explicitlyDeniedRegistrationClients") != DENIED:
        fail("MoneyBee lender/admin denial policy changed")
    if policy.get("credentialAuthority") != "keycloak-only":
        fail("Keycloak must remain credential authority")
    if policy.get("emailVerificationAuthority") != "keycloak-standard-verify-email":
        fail("standard Keycloak verify-email must remain authoritative")
    if policy.get("passwordRecoveryAuthority") != "keycloak-only":
        fail("Keycloak must remain password-recovery authority")
    if policy.get("smtpAuthority") != "config/email/keycloak-security-smtp.json":
        fail("registration policy must use the reviewed Klyrow SMTP authority")
    for field in (
        "applicationPasswordCollectionAllowed",
        "middlewareResetMaterialAllowed",
        "kongResetMaterialAllowed",
    ):
        if policy.get(field) is not False:
            fail(f"{field} must remain false")

    activation = policy.get("activation")
    if not isinstance(activation, dict):
        fail("activation policy must be an object")
    if activation.get("realmRegistrationAllowedBeforeGatedFlowExists") is not False:
        fail("realm registration must remain disabled before gated flow exists")
    if activation.get("copyBuiltInRegistrationFlow") is not True:
        fail("registration activation must copy the built-in flow")
    if activation.get("gateRequirement") != "REQUIRED":
        fail("registration gate must be REQUIRED")
    if activation.get("gateScope") != "registration-form":
        fail("registration gate must be inside the registration form")
    if activation.get("enableRealmRegistrationOnlyAfterGateReadback") is not True:
        fail("realm registration may only enable after gate readback")
    if activation.get("verifyDeniedClientBeforeActivation") is not True:
        fail("negative registration test is mandatory")
    if activation.get("verifyAllowedClientsBeforeActivation") is not True:
        fail("positive registration tests are mandatory")

    # The Git overlay intentionally stays closed until the custom flow exists in runtime.
    if realm.get("registrationAllowed") is not False:
        fail("realm registration must remain disabled in source until gated-flow activation")
    if realm.get("verifyEmail") is not True:
        fail("realm email verification must remain enabled")
    if realm.get("resetPasswordAllowed") is not True:
        fail("realm password recovery must remain enabled")

    moneybee_client_ids = [item.get("clientId") for item in moneybee.get("clients", [])]
    if moneybee_client_ids != ["moneybee-borrower", "moneybee-lender", "moneybee-admin"]:
        fail("MoneyBee browser client membership changed")
    if moneybee.get("issuer") != CANONICAL_ISSUER:
        fail("MoneyBee issuer is not canonical")

    beyvra_client = beyvra.get("client")
    if not isinstance(beyvra_client, dict):
        fail("Beyvra browser client contract is missing")
    if beyvra_client.get("clientId") != "beyvra-web-production":
        fail("Beyvra registration client changed")
    if beyvra.get("issuer") != CANONICAL_ISSUER:
        fail("Beyvra issuer is not canonical")
    registration_policy = beyvra.get("registrationPolicy")
    if not isinstance(registration_policy, dict) or registration_policy.get("selfRegistration") is not True:
        fail("Beyvra contract must declare reviewed self-registration")
    if registration_policy.get("passwordAuthority") != "keycloak-only":
        fail("Beyvra password authority must be Keycloak")

    if smtp.get("passwordReset", {}).get("passwordAuthority") != "keycloak-only":
        fail("SMTP contract must preserve Keycloak password authority")

    try:
        java = JAVA.read_text(encoding="utf-8")
        service = SERVICE.read_text(encoding="utf-8").strip()
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"registration extension source is incomplete: {exc}")

    if service != "co.codestra.keycloak.registration.CodestraRegistrationGate":
        fail("FormActionFactory service binding changed")
    for client_id in ALLOWED:
        if f'"{client_id}"' not in java:
            fail(f"registration gate does not allow reviewed client {client_id}")
    for client_id in DENIED:
        if f'"{client_id}"' in java:
            fail(f"registration gate must not allow {client_id}")
    if "context.validationError" not in java or "context.success()" not in java:
        fail("registration gate does not implement fail-closed validation")
    if "codestra-registration-gate-1.0.0.jar" not in dockerfile:
        fail("Keycloak image does not include the registration gate JAR")
    if "/opt/keycloak/providers/codestra-registration-gate.jar" not in dockerfile:
        fail("registration gate is not installed in the Keycloak providers directory")

    combined = "\n".join(
        [
            POLICY.read_text(encoding="utf-8"),
            JAVA.read_text(encoding="utf-8"),
        ]
    ).lower()
    for prohibited in (
        "client_secret=",
        "smtp_password=",
        "begin private key",
        "reset_token",
        "temporary_password",
    ):
        if prohibited in combined:
            fail(f"registration source contains prohibited secret/reset material marker: {prohibited}")


def main() -> int:
    try:
        validate()
    except ValidationError as exc:
        print(f"BROWSER_REGISTRATION_POLICY_ERROR={exc}", file=sys.stderr)
        return 1
    print("BROWSER_REGISTRATION_POLICY=PASS")
    print("MONEYBEE_BORROWER_SELF_REGISTRATION=DECLARED_GATED")
    print("BEYVRA_SELF_REGISTRATION=DECLARED_GATED")
    print("MONEYBEE_LENDER_ADMIN_SELF_REGISTRATION=BLOCKED")
    print("KEYCLOAK_STANDARD_EMAIL_VERIFICATION=PASS")
    print("RESET_MATERIAL_OUTSIDE_KEYCLOAK=BLOCKED")
    print("REALM_REGISTRATION_ACTIVATION=FAIL_CLOSED_PENDING_GATED_FLOW_READBACK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
