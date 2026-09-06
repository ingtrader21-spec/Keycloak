#!/usr/bin/env python3
"""Validate fail-closed production and service-identity certification contracts."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


matrix = load("config/certification/service-identity-matrix.json")
environment = load("config/github/production-environment.json")

assert matrix["schemaVersion"] == 1
assert matrix["stagingIssuer"] != matrix["productionIssuer"]
assert matrix["environmentsTrustEachOther"] is False
assert matrix["productionMutationAllowed"] is False

required_positive_cases = {
    "valid_service_identity", "valid_tenant_binding", "valid_campaign_binding",
}
required_negative_cases = {
    "missing_token", "malformed_token",
    "wrong_issuer", "wrong_audience", "wrong_azp", "insufficient_scope",
    "wrong_tenant", "wrong_campaign", "expired", "not_before",
    "invalid_signature", "unknown_signing_key", "forwarded_only_token",
    "cross_client_scope_confusion", "disabled_client", "replayed_jti",
}
required_claims = {"iss", "sub", "aud", "azp", "iat", "exp", "nbf", "jti", "scope", "tenant_id"}
required_evidence = {
    "repository_sha", "realm_export_sha256", "issuer", "jwks_fingerprint",
    "kong_configuration_sha256", "middleware_configuration_sha256",
    "case_results", "rollback_result",
}
assert set(matrix["positiveCases"]) == required_positive_cases
assert set(matrix["negativeCases"]) == required_negative_cases
assert set(matrix["requiredClaims"]) == required_claims
assert set(matrix["requiredEvidence"]) == required_evidence

assert environment["schemaVersion"] == 1
assert environment["environment"] == "production"
assert environment["protectedBranchesOnly"] is True
assert environment["preventSelfReview"] is True
assert environment["administratorBypassAllowed"] is False
assert environment["requiredIndependentReviewer"] == "kazan555"
assert environment["applyRequiresReviewedPlan"] is True
assert environment["applyRequiresIndependentDriftReview"] is True
assert environment["sourceOnlyMayEnableProduction"] is False
required_variables = {
    "KC_BASE_URL", "KC_PUBLIC_URL", "KC_TARGET_REALM", "KC_ADMIN_REALM",
    "KC_SMTP_CREDENTIAL_VERSION", "RUNTIME_REPO_DIR", "RUNTIME_COMPOSE_FILE",
    "RUNTIME_ENV_FILE", "RUNTIME_CADDY_FILE", "RUNTIME_GIT_SSH_KEY",
    "RUNTIME_GIT_KNOWN_HOSTS", "RUNTIME_GIT_REMOTE", "RUNTIME_GIT_BRANCH",
    "RUNTIME_PATHS_APPROVED_SHA256",
}
assert set(environment["requiredVariables"]) == required_variables
destinations = load("config/contracts/machine-secret-destinations.json")
machine_secrets = {client["applyEnvironment"] for client in destinations["clients"]}
required_secrets = {
    "KC_ADMIN_CLIENT_ID", "KC_ADMIN_CLIENT_SECRET", "KC_SMTP_USERNAME",
    "KC_SMTP_PASSWORD",
} | machine_secrets
assert set(environment["requiredSecrets"]) == required_secrets

deploy_workflow = (ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8")
assert "Enforce production mutation stop flag" in deploy_workflow
assert ".productionMutationAllowed == true" in deploy_workflow
assert "production_mutation_not_authorized_by_certification_contract" in deploy_workflow
for secret_name in machine_secrets:
    assert f"secrets.{secret_name}" in deploy_workflow

kong_certification = (ROOT / "scripts/certify-kong.sh").read_text(encoding="utf-8")
assert "DISABLED_CLIENT_EVIDENCE_FILE" in kong_certification
assert 'keycloak-admin-readback' in kong_certification
assert '.clientId == $client' in kong_certification
assert '.enabled == false' in kong_certification
assert '($now - 900)' in kong_certification

print("SERVICE_IDENTITY_CERTIFICATION_CONTRACT=PASS")
print("PRODUCTION_ENVIRONMENT_CONTRACT=PASS")
print("PRODUCTION_MUTATION_ALLOWED=NO")
