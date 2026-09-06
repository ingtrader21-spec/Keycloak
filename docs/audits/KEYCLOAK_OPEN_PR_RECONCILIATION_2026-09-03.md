# Keycloak open pull-request reconciliation — 2026-09-03

Repository: `appolon1908-hue/Keycloak`
Immutable current-main authority: `3d8cd0483a178100b679b2c3f0f4d4ca36fe161c`
Audited at: `2026-09-03T10:38:51.823606+00:00`

This is a source-only audit. It did not contact a Keycloak runtime, read a secret, issue a token, change SSH/DNS, deploy, or merge a pull request.

## Summary

- Open pull requests audited: **18**
- `CLEAN_REBASE_GATES_PENDING`: **3**
- `CONFLICT_REMEDIATION_REQUIRED`: **4**
- `DRAFT_REBASE_CANDIDATE`: **6**
- `DRAFT_REWORK_REQUIRED`: **5**

## Exact-head matrix

| PR | Draft | Head branch | Behind main | Paths | Merge | Checks | Approval | Threads | Decision |
|---:|:---:|---|---:|---:|:---:|:---:|:---:|---:|---|
| #68 | yes | `codex/codestra-orbit-v2-keycloak` | 2 | 1 | clean | green | no | 0 | **DRAFT_REBASE_CANDIDATE** |
| #62 | yes | `feature/platform-api-scopes-v2-20260901` | 3 | 6 | conflict | green | no | 0 | **DRAFT_REWORK_REQUIRED** |
| #59 | no | `harden/stage6-ephemeral-docker-auth-20260831` | 3 | 7 | conflict | green | yes | 0 | **CONFLICT_REMEDIATION_REQUIRED** |
| #44 | yes | `docs/repository-profile-v1` | 19 | 1 | clean | green | no | 0 | **DRAFT_REBASE_CANDIDATE** |
| #37 | yes | `cert2/sdk-intake-exact-ci` | 19 | 51 | conflict | pending/absent | no | 0 | **DRAFT_REWORK_REQUIRED** |
| #32 | yes | `feature/sdk-intake-client-v2` | 19 | 51 | conflict | pending/absent | no | 0 | **DRAFT_REWORK_REQUIRED** |
| #28 | yes | `docs/communications-platform-authority` | 19 | 1 | clean | green | no | 0 | **DRAFT_REBASE_CANDIDATE** |
| #27 | yes | `integration/registration-recovery-20260829` | 20 | 23 | conflict | green | no | 0 | **DRAFT_REWORK_REQUIRED** |
| #19 | no | `feat/keycloak-machine-identities` | 19 | 9 | conflict | failed | yes | 2 | **CONFLICT_REMEDIATION_REQUIRED** |
| #18 | no | `feat/keycloak-realm-security-policy` | 19 | 13 | conflict | failed | yes | 2 | **CONFLICT_REMEDIATION_REQUIRED** |
| #17 | no | `security/keycloak-runtime-hardening` | 21 | 19 | conflict | green | yes | 2 | **CONFLICT_REMEDIATION_REQUIRED** |
| #16 | no | `fix/keycloak-apply-transaction-safety` | 21 | 7 | clean | green | yes | 1 | **CLEAN_REBASE_GATES_PENDING** |
| #14 | no | `docs/independent-keycloak-authority` | 22 | 3 | clean | green | yes | 2 | **CLEAN_REBASE_GATES_PENDING** |
| #12 | yes | `feat/scrapper-turnkey-identity-v1` | 26 | 3 | clean | failed | no | 0 | **DRAFT_REBASE_CANDIDATE** |
| #10 | yes | `integration/n8n-service-identities-v2-20260827` | 23 | 6 | clean | green | no | 0 | **DRAFT_REBASE_CANDIDATE** |
| #9 | yes | `feature/n8n-automation-service-clients-v2` | 23 | 2 | clean | green | no | 0 | **DRAFT_REBASE_CANDIDATE** |
| #8 | no | `feat/moneybee-registration-email-otp` | 23 | 26 | clean | failed | yes | 0 | **CLEAN_REBASE_GATES_PENDING** |
| #6 | yes | `feat/password-reset-e2e-acceptance` | 26 | 12 | conflict | failed | yes | 0 | **DRAFT_REWORK_REQUIRED** |

## Decision semantics

- `CLOSE_NO_PAYLOAD`: no remaining diff against the immutable main authority.
- `CLOSE_SUPERSEDED_BY_MAIN`: every unique patch is already represented on main.
- `DRAFT_REBASE_CANDIDATE`: unique draft payload merges cleanly but remains intentionally blocked.
- `DRAFT_REWORK_REQUIRED`: draft payload conflicts with current main and needs a clean replacement branch.
- `CONFLICT_REMEDIATION_REQUIRED`: non-draft payload conflicts and must not be merged or force-rebased blindly.
- `CLEAN_REBASE_GATES_PENDING`: payload merges cleanly, but exact-head review/check gates are incomplete.
- `EXACT_HEAD_GATES_PASS_REBASE_REQUIRED`: visible gates pass, but the stale branch still must be recreated on current main and revalidated.

## Pull-request details

### PR #68 — chore(orbit): register supported identity theme and logout rules

- Exact head: `260083f9a02e9672565a31cdc20b0868ad3b7356`
- Base recorded by GitHub: `main@fd9771bcf756c3ef1611422838beacb2d2575caa`
- Current-main divergence: `1` unique commits ahead, `2` commits behind
- Merge simulation: `PASS`
- Exact-head checks: successes `2`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `NO`
- Active unresolved review threads: `0`
- Decision: **DRAFT_REBASE_CANDIDATE**

Changed paths:

- `orbit/adoption-manifest.json`

### PR #62 — feat(auth): complete platform API clients and scopes v2

- Exact head: `b3f43a66d5085decd240d45e91eb923bae95a6ba`
- Base recorded by GitHub: `main@28ce563f9e5143bf5dd1e78224e79482d27c18bd`
- Current-main divergence: `2` unique commits ahead, `3` commits behind
- Merge simulation: `CONFLICT`
- Exact-head checks: successes `2`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `NO`
- Active unresolved review threads: `0`
- Decision: **DRAFT_REWORK_REQUIRED**

Changed paths:

- `config/clients/kong-gateway.json`
- `config/clients/n8n-automation.json`
- `docs/PLATFORM-API-SCOPES-V2.md`
- `scripts/render-machine-client-overlays.py`
- `tests/test_kong_oidc_contract.py`
- `tests/test_tenant_bound_service_clients.py`

Conflict paths:

- `scripts/render-machine-client-overlays.py`

### PR #59 — fix(stage6): harden runner Docker authentication

- Exact head: `9879c6bd28d89962b5bde6dad2b330146364d194`
- Base recorded by GitHub: `main@28ce563f9e5143bf5dd1e78224e79482d27c18bd`
- Current-main divergence: `19` unique commits ahead, `3` commits behind
- Merge simulation: `CONFLICT`
- Exact-head checks: successes `2`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `YES`
- Active unresolved review threads: `0`
- Decision: **CONFLICT_REMEDIATION_REQUIRED**

Changed paths:

- `.github/workflows/runtime-preflight.yml`
- `docs/SERVER_GIT_SSH.md`
- `scripts/ephemeral-docker-auth.sh`
- `scripts/runner-systemd-preflight.sh`
- `scripts/test-ephemeral-docker-auth.sh`
- `scripts/validate-workflows.py`
- `scripts/validate.sh`

Conflict paths:

- `scripts/validate-workflows.py`

### PR #44 — docs: add repository profile and authority outline

- Exact head: `a1f5d4191cfb7e9efeb58df947c8991e1440d3cc`
- Base recorded by GitHub: `main@92ca388323db23c1f308ce4e33d9f36b0c77c74e`
- Current-main divergence: `1` unique commits ahead, `19` commits behind
- Merge simulation: `PASS`
- Exact-head checks: successes `2`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `NO`
- Active unresolved review threads: `0`
- Decision: **DRAFT_REBASE_CANDIDATE**

Changed paths:

- `REPOSITORY_PROFILE.md`

### PR #37 — cert2: fresh exact-head sdk-intake validation

- Exact head: `f37878fba4e7419f77e53a30731a61302ab0e05e`
- Base recorded by GitHub: `feature/observability-managed-clients-v1@93bf3e98b2a6fcd954524cbb2afb36fa02b2aefc`
- Current-main divergence: `29` unique commits ahead, `19` commits behind
- Merge simulation: `CONFLICT`
- Exact-head checks: successes `0`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `NO`
- Active unresolved review threads: `0`
- Decision: **DRAFT_REWORK_REQUIRED**

Changed paths:

- `.github/workflows/validate.yml`
- `config/clients/grafana-observability.json`
- `config/clients/openbao-secrets.json`
- `config/clients/sdk-intake.json`
- `config/clients/superset-analytics.json`
- `config/contracts/observability-browser-clients.json`
- `config/export-allowlists/grafana-observability.json`
- `config/export-allowlists/openbao-secrets.json`
- `config/export-allowlists/realm-roles/observability-admin.json`
- `config/export-allowlists/realm-roles/observability-operator.json`
- `config/export-allowlists/realm-roles/observability-viewer.json`
- `config/export-allowlists/realm-roles/secrets-admin.json`
- `config/export-allowlists/realm-roles/secrets-operator.json`
- `config/export-allowlists/sdk-intake.json`
- `config/export-allowlists/superset-analytics.json`
- `config/policy/creatable-clients.json`
- `config/policy/creatable-realm-roles.json`
- `config/policy/managed-clients.json`
- `config/policy/managed-realm-roles.json`
- `config/policy/secret-export-clients.json`
- `config/realm-roles/observability-admin.json`
- `config/realm-roles/observability-operator.json`
- `config/realm-roles/observability-viewer.json`
- `config/realm-roles/secrets-admin.json`
- `config/realm-roles/secrets-operator.json`
- `docs/OBSERVABILITY-MANAGED-IDENTITIES.md`
- `docs/OBSERVABILITY-OIDC.md`
- `scripts/apply-plan.sh`
- `scripts/export-client.sh`
- `scripts/export-generated-client-secrets.sh`
- `scripts/observability_identity_policy.py`
- `scripts/plan.sh`
- `scripts/prepare-rollback-evidence.sh`
- `scripts/protected_identity/__init__.py`
- `scripts/protected_identity/api.py`
- `scripts/protected_identity/apply.py`
- `scripts/protected_identity/cli.py`
- `scripts/protected_identity/common.py`
- `scripts/protected_identity/export.py`
- `scripts/protected_identity/plan_review.py`
- `scripts/protected_identity/state.py`
- `scripts/protected_identity_engine.py`
- `scripts/protected_identity_test_server.py`
- `scripts/review-plan.sh`
- `scripts/test-plan-gate.sh`
- `scripts/test-protected-identity-engine.py`
- `scripts/validate-moneybee-oidc-contract.py`
- `scripts/validate-observability-managed-identities.py`
- `scripts/validate-observability-oidc-contract.py`
- `scripts/validate-source.py`
- `scripts/validate.sh`

Conflict paths:

- `config/contracts/observability-browser-clients.json`
- `config/policy/creatable-clients.json`
- `config/policy/managed-clients.json`
- `scripts/apply-plan.sh`
- `scripts/plan.sh`
- `scripts/test-plan-gate.sh`
- `scripts/validate-moneybee-oidc-contract.py`
- `scripts/validate.sh`

### PR #32 — feat: add sdk-intake through managed-client GitOps

- Exact head: `dafda3d4be26ffdcd0964781964c5a81a1768bcf`
- Base recorded by GitHub: `feature/observability-managed-clients-v1@93bf3e98b2a6fcd954524cbb2afb36fa02b2aefc`
- Current-main divergence: `20` unique commits ahead, `19` commits behind
- Merge simulation: `CONFLICT`
- Exact-head checks: successes `0`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `NO`
- Active unresolved review threads: `0`
- Decision: **DRAFT_REWORK_REQUIRED**

Changed paths:

- `.github/workflows/validate.yml`
- `config/clients/grafana-observability.json`
- `config/clients/openbao-secrets.json`
- `config/clients/sdk-intake.json`
- `config/clients/superset-analytics.json`
- `config/contracts/observability-browser-clients.json`
- `config/export-allowlists/grafana-observability.json`
- `config/export-allowlists/openbao-secrets.json`
- `config/export-allowlists/realm-roles/observability-admin.json`
- `config/export-allowlists/realm-roles/observability-operator.json`
- `config/export-allowlists/realm-roles/observability-viewer.json`
- `config/export-allowlists/realm-roles/secrets-admin.json`
- `config/export-allowlists/realm-roles/secrets-operator.json`
- `config/export-allowlists/sdk-intake.json`
- `config/export-allowlists/superset-analytics.json`
- `config/policy/creatable-clients.json`
- `config/policy/creatable-realm-roles.json`
- `config/policy/managed-clients.json`
- `config/policy/managed-realm-roles.json`
- `config/policy/secret-export-clients.json`
- `config/realm-roles/observability-admin.json`
- `config/realm-roles/observability-operator.json`
- `config/realm-roles/observability-viewer.json`
- `config/realm-roles/secrets-admin.json`
- `config/realm-roles/secrets-operator.json`
- `docs/OBSERVABILITY-MANAGED-IDENTITIES.md`
- `docs/OBSERVABILITY-OIDC.md`
- `scripts/apply-plan.sh`
- `scripts/export-client.sh`
- `scripts/export-generated-client-secrets.sh`
- `scripts/observability_identity_policy.py`
- `scripts/plan.sh`
- `scripts/prepare-rollback-evidence.sh`
- `scripts/protected_identity/__init__.py`
- `scripts/protected_identity/api.py`
- `scripts/protected_identity/apply.py`
- `scripts/protected_identity/cli.py`
- `scripts/protected_identity/common.py`
- `scripts/protected_identity/export.py`
- `scripts/protected_identity/plan_review.py`
- `scripts/protected_identity/state.py`
- `scripts/protected_identity_engine.py`
- `scripts/protected_identity_test_server.py`
- `scripts/review-plan.sh`
- `scripts/test-plan-gate.sh`
- `scripts/test-protected-identity-engine.py`
- `scripts/validate-moneybee-oidc-contract.py`
- `scripts/validate-observability-managed-identities.py`
- `scripts/validate-observability-oidc-contract.py`
- `scripts/validate-source.py`
- `scripts/validate.sh`

Conflict paths:

- `config/contracts/observability-browser-clients.json`
- `config/policy/creatable-clients.json`
- `config/policy/managed-clients.json`
- `scripts/apply-plan.sh`
- `scripts/plan.sh`
- `scripts/test-plan-gate.sh`
- `scripts/validate-moneybee-oidc-contract.py`
- `scripts/validate.sh`

### PR #28 — Document communications identity authority

- Exact head: `6d0663be63b9ed47e5ead1a482e6f2525de3d75d`
- Base recorded by GitHub: `main@92ca388323db23c1f308ce4e33d9f36b0c77c74e`
- Current-main divergence: `1` unique commits ahead, `19` commits behind
- Merge simulation: `PASS`
- Exact-head checks: successes `2`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `NO`
- Active unresolved review threads: `0`
- Decision: **DRAFT_REBASE_CANDIDATE**

Changed paths:

- `docs/COMMUNICATIONS_PLATFORM_AUTHORITY.md`

### PR #27 — feat(identity): unify MoneyBee, Beyvra, and Breero registration and recovery

- Exact head: `def030a6cde380fb5c60045188a0a3312d4b698e`
- Base recorded by GitHub: `main@04f603b4a4c430aeaa37b3c9cebedccabfc95d1a`
- Current-main divergence: `26` unique commits ahead, `20` commits behind
- Merge simulation: `CONFLICT`
- Exact-head checks: successes `2`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `NO`
- Active unresolved review threads: `0`
- Decision: **DRAFT_REWORK_REQUIRED**

Changed paths:

- `.github/workflows/deploy.yml`
- `.github/workflows/validate.yml`
- `Dockerfile`
- `config/email/keycloak-security-smtp.json`
- `config/identity/browser-registration-policy.json`
- `config/realms/codestra.json`
- `config/security/realm-security-policy.json`
- `docs/BROWSER_SELF_REGISTRATION.md`
- `docs/KEYCLOAK_PASSWORD_RESET_SMTP.md`
- `docs/security/BROWSER_CLIENT_POLICY.md`
- `docs/security/REALM_SECURITY_POLICY.md`
- `docs/security/TOKEN_POLICY.md`
- `extensions/codestra-registration-gate/pom.xml`
- `extensions/codestra-registration-gate/src/main/java/co/codestra/keycloak/registration/CodestraRegistrationGate.java`
- `extensions/codestra-registration-gate/src/main/resources/META-INF/services/org.keycloak.authentication.FormActionFactory`
- `scripts/apply-plan.sh`
- `scripts/plan.sh`
- `scripts/review-plan.sh`
- `scripts/test-plan-gate.sh`
- `scripts/validate-browser-registration-policy.py`
- `scripts/validate-password-reset-contract.py`
- `scripts/validate-realm-security-policy.py`
- `scripts/validate.sh`

Conflict paths:

- `scripts/test-plan-gate.sh`
- `scripts/validate.sh`

### PR #19 — security: externalize machine client credentials

- Exact head: `82a3be32c4479e46821279036ba237756995a4c1`
- Base recorded by GitHub: `main@92ca388323db23c1f308ce4e33d9f36b0c77c74e`
- Current-main divergence: `2` unique commits ahead, `19` commits behind
- Merge simulation: `CONFLICT`
- Exact-head checks: successes `0`, pending `0`, failures `2`
- Exact-head approval by `kazan555`: `YES`
- Active unresolved review threads: `2`
- Decision: **CONFLICT_REMEDIATION_REQUIRED**

Changed paths:

- `.github/workflows/deploy.yml`
- `config/contracts/machine-secret-destinations.json`
- `docs/operations/CLIENT_PROVISIONING.md`
- `docs/security/ACCESS_CONTRACTS.md`
- `docs/security/MACHINE_IDENTITY_POLICY.md`
- `scripts/apply-plan.sh`
- `scripts/test-plan-gate.sh`
- `scripts/validate-machine-secret-contract.py`
- `scripts/validate.sh`

Conflict paths:

- `scripts/test-plan-gate.sh`
- `scripts/validate.sh`

Failed checks:

- `validate-merge-result`
- `validate-source`

### PR #18 — feat: manage Keycloak realm security and recovery policy

- Exact head: `168168f387e7d0466871ba5ac048a0bf47b959ff`
- Base recorded by GitHub: `main@92ca388323db23c1f308ce4e33d9f36b0c77c74e`
- Current-main divergence: `5` unique commits ahead, `19` commits behind
- Merge simulation: `CONFLICT`
- Exact-head checks: successes `0`, pending `0`, failures `2`
- Exact-head approval by `kazan555`: `YES`
- Active unresolved review threads: `2`
- Decision: **CONFLICT_REMEDIATION_REQUIRED**

Changed paths:

- `.github/workflows/deploy.yml`
- `config/realms/codestra.json`
- `config/security/realm-security-policy.json`
- `docs/KEYCLOAK_PASSWORD_RESET_SMTP.md`
- `docs/security/BROWSER_CLIENT_POLICY.md`
- `docs/security/REALM_SECURITY_POLICY.md`
- `docs/security/TOKEN_POLICY.md`
- `scripts/apply-plan.sh`
- `scripts/plan.sh`
- `scripts/review-plan.sh`
- `scripts/test-plan-gate.sh`
- `scripts/validate-realm-security-policy.py`
- `scripts/validate.sh`

Conflict paths:

- `scripts/test-plan-gate.sh`
- `scripts/validate.sh`

Failed checks:

- `validate-merge-result`
- `validate-source`

### PR #17 — security: harden immutable Keycloak runtime supply chain

- Exact head: `60d81a61fb55706dd04757f044a11791162a2e3d`
- Base recorded by GitHub: `main@49d33b68a1ebf7c9de97049597583fe30a49a3ce`
- Current-main divergence: `4` unique commits ahead, `21` commits behind
- Merge simulation: `CONFLICT`
- Exact-head checks: successes `2`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `YES`
- Active unresolved review threads: `2`
- Decision: **CONFLICT_REMEDIATION_REQUIRED**

Changed paths:

- `.env.example`
- `.github/workflows/release-image.yml`
- `.github/workflows/validate.yml`
- `Dockerfile`
- `Makefile`
- `README.md`
- `compose.yaml`
- `deploy/secrets/admin-api.env.example`
- `deploy/secrets/bootstrap-admin.env.example`
- `deploy/secrets/monitoring.env.example`
- `deploy/secrets/postgres.env.example`
- `deploy/secrets/runtime-ssh.env.example`
- `deploy/secrets/smtp.env.example`
- `docs/audits/KEYCLOAK_RUNTIME_GAP_ANALYSIS.md`
- `docs/operations/SECRET_ROTATION.md`
- `docs/security/CONTAINER_SUPPLY_CHAIN.md`
- `scripts/validate-runtime-security.py`
- `scripts/validate-workflows.py`
- `scripts/validate.sh`

Conflict paths:

- `README.md`
- `docs/audits/KEYCLOAK_RUNTIME_GAP_ANALYSIS.md`
- `scripts/validate-workflows.py`

### PR #16 — fix: make Keycloak apply transaction-safe and recoverable

- Exact head: `a3e67178d062babf3390094202aee9688995209a`
- Base recorded by GitHub: `main@49d33b68a1ebf7c9de97049597583fe30a49a3ce`
- Current-main divergence: `3` unique commits ahead, `21` commits behind
- Merge simulation: `PASS`
- Exact-head checks: successes `2`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `YES`
- Active unresolved review threads: `1`
- Decision: **CLEAN_REBASE_GATES_PENDING**

Changed paths:

- `.github/workflows/deploy.yml`
- `Makefile`
- `README.md`
- `docs/GITOPS.md`
- `docs/audits/KEYCLOAK_BASELINE_AUDIT.md`
- `scripts/apply-plan.sh`
- `scripts/test-plan-gate.sh`

### PR #14 — docs: establish Keycloak as independent identity authority

- Exact head: `1547c05d68f728af561579eb7d4625e70dcb10da`
- Base recorded by GitHub: `main@85b8c3f54d79331cd93a3efe5bd2f4bfb9064667`
- Current-main divergence: `3` unique commits ahead, `22` commits behind
- Merge simulation: `PASS`
- Exact-head checks: successes `2`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `YES`
- Active unresolved review threads: `2`
- Decision: **CLEAN_REBASE_GATES_PENDING**

Changed paths:

- `README.md`
- `docs/CODESTRA_MISSION_PLAN.md`
- `docs/KEYCLOAK_REPOSITORY_AUTHORITY.md`

### PR #12 — contract: turnkey scrapper BFF and service identities

- Exact head: `64b4c966cda79d42b452f29ec59312f5ca6bdc00`
- Base recorded by GitHub: `feat/service-api-webhook-identity-contracts@460e7271d6e2c28fcfd78856960e0bf84962e0f9`
- Current-main divergence: `3` unique commits ahead, `26` commits behind
- Merge simulation: `PASS`
- Exact-head checks: successes `1`, pending `0`, failures `2`
- Exact-head approval by `kazan555`: `NO`
- Active unresolved review threads: `0`
- Decision: **DRAFT_REBASE_CANDIDATE**

Changed paths:

- `.github/workflows/scrapper-identity-contract.yml`
- `contracts/scrapper-turnkey-identity-v1.json`
- `docs/SCRAPPER_TURNKEY_IDENTITY.md`

Failed checks:

- `validate-merge-result`
- `validate-source`

### PR #10 — feat(identity): define isolated integration-fabric service identities v2

- Exact head: `fb2bda91e52385c0f673f358ab3147f93b42b766`
- Base recorded by GitHub: `main@d3ed59800c53b82b03323960fe006fc15a08091e`
- Current-main divergence: `5` unique commits ahead, `23` commits behind
- Merge simulation: `PASS`
- Exact-head checks: successes `2`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `NO`
- Active unresolved review threads: `0`
- Decision: **DRAFT_REBASE_CANDIDATE**

Changed paths:

- `config/contracts/integration-fabric-service-clients-v2.json`
- `config/contracts/n8n-automation-clients-v2.json`
- `docs/integrations/CODESTRA_INTEGRATION_FABRIC_IDENTITIES_V2.md`
- `docs/integrations/INTEGRATION_FABRIC_IDENTITY_BRANCH_MAP.md`
- `docs/integrations/n8n-automation-identities.md`
- `scripts/validate_integration_fabric_clients.py`

### PR #9 — feat(identity): declare n8n automation service clients v2

- Exact head: `51e28b9d0ce6db7c11be43c152d100341a9bef9b`
- Base recorded by GitHub: `main@d3ed59800c53b82b03323960fe006fc15a08091e`
- Current-main divergence: `2` unique commits ahead, `23` commits behind
- Merge simulation: `PASS`
- Exact-head checks: successes `2`, pending `0`, failures `0`
- Exact-head approval by `kazan555`: `NO`
- Active unresolved review threads: `0`
- Decision: **DRAFT_REBASE_CANDIDATE**

Changed paths:

- `config/contracts/n8n-automation-clients-v2.json`
- `docs/N8N_AUTOMATION_SERVICE_CLIENTS_V2.md`

### PR #8 — feat(identity): add MoneyBee borrower registration and email OTP

- Exact head: `5bfb717570f93a25312a815b8806387d6564af61`
- Base recorded by GitHub: `main@d3ed59800c53b82b03323960fe006fc15a08091e`
- Current-main divergence: `25` unique commits ahead, `23` commits behind
- Merge simulation: `PASS`
- Exact-head checks: successes `1`, pending `0`, failures `1`
- Exact-head approval by `kazan555`: `YES`
- Active unresolved review threads: `0`
- Decision: **CLEAN_REBASE_GATES_PENDING**

Changed paths:

- `.env.example`
- `.github/workflows/validate.yml`
- `Dockerfile`
- `compose.yaml`
- `config/contracts/moneybee-backend-producer.json`
- `config/email/keycloak-security-smtp.json`
- `config/identity/moneybee-enterprise-access-policy.json`
- `config/identity/moneybee-registration.json`
- `config/realms/codestra.json`
- `docs/KEYCLOAK_PASSWORD_RESET_SMTP.md`
- `docs/MONEYBEE_SECURITY_SENDER_POLICY.md`
- `extensions/moneybee-email-otp/pom.xml`
- `extensions/moneybee-email-otp/src/main/java/co/codestra/keycloak/moneybee/MoneyBeeEmailOtpRequiredAction.java`
- `extensions/moneybee-email-otp/src/main/java/co/codestra/keycloak/moneybee/MoneyBeeRegistrationGate.java`
- `extensions/moneybee-email-otp/src/main/resources/META-INF/services/org.keycloak.authentication.FormActionFactory`
- `extensions/moneybee-email-otp/src/main/resources/META-INF/services/org.keycloak.authentication.RequiredActionFactory`
- `scripts/plan-moneybee-registration.sh`
- `scripts/validate-moneybee-registration.py`
- `scripts/validate-password-reset-contract.py`
- `themes/codestra-identity/email/html/moneybee-email-otp.ftl`
- `themes/codestra-identity/email/messages/messages_en.properties`
- `themes/codestra-identity/email/messages/messages_es.properties`
- `themes/codestra-identity/email/text/moneybee-email-otp.ftl`
- `themes/codestra-identity/email/theme.properties`
- `themes/codestra-identity/login/moneybee-email-otp.ftl`
- `themes/codestra-identity/login/theme.properties`

Failed checks:

- `validate-source`

### PR #6 — Add protected end-to-end password-reset acceptance for gates 1–11

- Exact head: `96c0db86cef0c2f54c8a108181d49fdf4dd77c0b`
- Base recorded by GitHub: `feat/klyrow-smtp-password-reset@f25f06345649d5ff2fe47bb26e3325404a1a734c`
- Current-main divergence: `6` unique commits ahead, `26` commits behind
- Merge simulation: `CONFLICT`
- Exact-head checks: successes `0`, pending `0`, failures `4`
- Exact-head approval by `kazan555`: `YES`
- Active unresolved review threads: `0`
- Decision: **DRAFT_REWORK_REQUIRED**

Changed paths:

- `.github/workflows/password-reset-staging-e2e.yml`
- `.github/workflows/validate-password-reset-e2e.yml`
- `.github/workflows/validate.yml`
- `config/email/keycloak-security-smtp.json`
- `config/identity/application-domain-registry.json`
- `deploy/keycloak-email.env.example`
- `docs/KEYCLOAK_PASSWORD_RESET_SMTP.md`
- `docs/PASSWORD_RESET_E2E_ACCEPTANCE.md`
- `scripts/password-reset-e2e.py`
- `scripts/validate-domain-application-registry.py`
- `scripts/validate-password-reset-contract.py`
- `scripts/validate-password-reset-e2e.py`

Conflict paths:

- `.github/workflows/validate.yml`
- `config/email/keycloak-security-smtp.json`
- `config/identity/application-domain-registry.json`
- `scripts/validate-domain-application-registry.py`
- `scripts/validate-password-reset-contract.py`

Failed checks:

- `validate-merge-result`
- `validate-merge-result-e2e`
- `validate-source`
- `validate-source-e2e`

## Safety

```text
KEYCLOAK_RUNTIME_CONTACTED=false
KEYCLOAK_RUNTIME_APPLY=false
SECRETS_READ=0
TOKENS_ISSUED=0
PRS_MERGED=0
SSH_CHANGED=false
PRODUCTION_CHANGED=false
```
