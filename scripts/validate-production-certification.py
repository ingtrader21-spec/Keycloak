#!/usr/bin/env python3
"""Validate fail-closed production and service-identity certification contracts."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("CERTIFICATION_CONTRACT=FAIL: " + message)


matrix = load("config/certification/service-identity-matrix.json")
environment = load("config/github/production-environment.json")

require(matrix["schemaVersion"] == 1, "unsupported identity matrix schema")
require(matrix["stagingIssuer"] == load("config/endpoints/codestra-staging.json")["issuer"], "staging issuer must match canonical endpoints")
require(matrix["productionIssuer"] == load("config/endpoints/codestra.json")["issuer"], "production issuer must match canonical endpoints")
require(matrix["stagingIssuer"] != matrix["productionIssuer"], "staging and production issuers must differ")
require(matrix["environmentsTrustEachOther"] is False, "cross-environment trust must remain disabled")
require(matrix["productionMutationAllowed"] is False, "production mutations require completed live certification")

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
require(set(matrix["positiveCases"]) == required_positive_cases, "positive identity cases are incomplete")
require(set(matrix["negativeCases"]) == required_negative_cases, "negative identity cases are incomplete")
require(set(matrix["requiredClaims"]) == required_claims, "required identity claims differ from the contract")
require(set(matrix["requiredEvidence"]) == required_evidence, "required release evidence is incomplete")

require(environment["schemaVersion"] == 1, "unsupported environment schema")
require(environment["environment"] == "production", "protected environment must be production")
require(environment["protectedBranchesOnly"] is True, "production must restrict deployment branches")
require(environment["preventSelfReview"] is True, "production must prevent self-review")
require(environment["administratorBypassAllowed"] is False, "production must forbid administrator bypass")
require(environment["requiredIndependentReviewer"] == "kazan555", "required independent reviewer changed")
require(environment["applyRequiresReviewedPlan"] is True, "apply must require a reviewed plan")
require(environment["applyRequiresIndependentDriftReview"] is True, "apply must require independent drift review")
require(environment["sourceOnlyMayEnableProduction"] is False, "source checks alone must not enable production")
required_variables = {
    "KC_BASE_URL", "KC_PUBLIC_URL", "KC_TARGET_REALM", "KC_ADMIN_REALM",
    "KC_SMTP_CREDENTIAL_VERSION", "RUNTIME_REPO_DIR", "RUNTIME_COMPOSE_FILE",
    "RUNTIME_ENV_FILE", "RUNTIME_CADDY_FILE", "RUNTIME_GIT_SSH_KEY",
    "RUNTIME_GIT_KNOWN_HOSTS", "RUNTIME_GIT_REMOTE", "RUNTIME_GIT_BRANCH",
    "RUNTIME_PATHS_APPROVED_SHA256",
}
require(set(environment["requiredVariables"]) == required_variables, "required production variables are incomplete")
destinations = load("config/contracts/machine-secret-destinations.json")
machine_secrets = {client["applyEnvironment"] for client in destinations["clients"]}
required_secrets = {
    "KC_ADMIN_CLIENT_ID", "KC_ADMIN_CLIENT_SECRET", "KC_SMTP_USERNAME",
    "KC_SMTP_PASSWORD",
} | machine_secrets
require(set(environment["requiredSecrets"]) == required_secrets, "required production credentials are incomplete")

deploy_workflow = (ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8")
require("Enforce production mutation stop flag" in deploy_workflow, "deployment must include the production stop gate")
require(".productionMutationAllowed == true" in deploy_workflow, "deployment must enforce the production stop flag")
require("production_mutation_not_authorized_by_certification_contract" in deploy_workflow, "deployment must reject unauthorized production mutations")
for secret_name in machine_secrets:
    require(f"secrets.{secret_name}" in deploy_workflow, f"missing apply credential binding: {secret_name}")

kong_certification = (ROOT / "scripts/certify-kong.sh").read_text(encoding="utf-8")
require('python3 "$root_dir/scripts/certify_disabled_client.py"' in kong_certification,
        "Kong must execute authenticated disabled-client certification")
require('disabledClientEvidence:$disabledEvidence[0]' in kong_certification,
        "Kong evidence must include authenticated fixture read-back")
require('DISABLED_CLIENT_EVIDENCE_FILE' not in kong_certification,
        "caller-supplied disabled-client evidence must not be trusted")
apply_script = (ROOT / "scripts/apply-plan.sh").read_text(encoding="utf-8")
require('.productionMutationAllowed == true' in apply_script,
        "direct apply must enforce the production mutation stop flag")
require('production_mutation_not_authorized_by_certification_contract' in apply_script,
        "direct apply must fail when production certification is blocked")

print("SERVICE_IDENTITY_CERTIFICATION_CONTRACT=PASS")
print("PRODUCTION_ENVIRONMENT_CONTRACT=PASS")
print("PRODUCTION_MUTATION_ALLOWED=NO")
