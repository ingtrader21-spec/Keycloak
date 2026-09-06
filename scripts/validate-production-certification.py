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

required_cases = {
    "wrong_issuer", "wrong_audience", "wrong_azp", "insufficient_scope",
    "wrong_tenant", "wrong_campaign", "expired", "not_before",
    "invalid_signature", "unknown_signing_key", "forwarded_only_token",
    "cross_client_scope_confusion", "replayed_jti",
}
assert required_cases <= set(matrix["negativeCases"])
assert {"iss", "aud", "azp", "scope", "tenant_id", "jti"} <= set(matrix["requiredClaims"])
assert {"repository_sha", "realm_export_sha256", "case_results", "rollback_result"} <= set(matrix["requiredEvidence"])

assert environment["schemaVersion"] == 1
assert environment["environment"] == "production"
assert environment["protectedBranchesOnly"] is True
assert environment["preventSelfReview"] is True
assert environment["administratorBypassAllowed"] is False
assert environment["requiredIndependentReviewer"]
assert environment["applyRequiresReviewedPlan"] is True
assert environment["applyRequiresIndependentDriftReview"] is True
assert environment["sourceOnlyMayEnableProduction"] is False
assert {"KC_BASE_URL", "KC_PUBLIC_URL", "KC_TARGET_REALM", "KC_ADMIN_REALM", "RUNTIME_PATHS_APPROVED_SHA256"} <= set(environment["requiredVariables"])
assert {"KC_ADMIN_CLIENT_ID", "KC_ADMIN_CLIENT_SECRET"} <= set(environment["requiredSecrets"])

print("SERVICE_IDENTITY_CERTIFICATION_CONTRACT=PASS")
print("PRODUCTION_ENVIRONMENT_CONTRACT=PASS")
print("PRODUCTION_MUTATION_ALLOWED=NO")
