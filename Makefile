SHELL := /usr/bin/env bash

.PHONY: validate test-runtime-preflight build up down logs check plan review-plan apply-plan export-klyrow smoke runtime-preflight backup verify-backup check-recovery-freshness certify-kong edge-certification-check certify-edge-identity reconcile-edge-certification openbao-workload-identity-check reconcile-openbao-workload-identity

validate: mcr-identity-check
	./scripts/validate.sh

test-runtime-preflight:
	./scripts/test-runtime-preflight.sh

build:
	docker build -t $${KEYCLOAK_BUILD_TAG:-codestra-keycloak:local} .

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=200 keycloak

check:
	: "$${EXPECTED_DEPLOY_SHA:?Set EXPECTED_DEPLOY_SHA}"
	./scripts/reconcile.sh --check --expected-deploy-sha "$${EXPECTED_DEPLOY_SHA}"

plan:
	: "$${EXPECTED_DEPLOY_SHA:?Set EXPECTED_DEPLOY_SHA}"
	: "$${DEPLOY_ENVIRONMENT:?Set DEPLOY_ENVIRONMENT to staging or production}"
	./scripts/plan.sh --output-dir "$${PLAN_DIR:-$${PWD}/artifacts/plan}" --expected-deploy-sha "$${EXPECTED_DEPLOY_SHA}"

review-plan:
	: "$${PLAN_FILE:?Set PLAN_FILE to plan.json}"
	: "$${PLAN_SHA256:?Set PLAN_SHA256 to the plan hash}"
	: "$${EXPECTED_DEPLOY_SHA:?Set EXPECTED_DEPLOY_SHA}"
	: "$${DEPLOY_ENVIRONMENT:?Set DEPLOY_ENVIRONMENT to staging or production}"
	./scripts/review-plan.sh --plan "$${PLAN_FILE}" --expected-plan-sha "$${PLAN_SHA256}" --expected-deploy-sha "$${EXPECTED_DEPLOY_SHA}" --output "$${REVIEW_FILE:-$${PWD}/artifacts/review/review.json}"

apply-plan:
	: "$${PLAN_FILE:?Set PLAN_FILE to reviewed plan.json}"
	: "$${PLAN_SHA256:?Set PLAN_SHA256 to the reviewed plan hash}"
	: "$${REVIEW_FILE:?Set REVIEW_FILE to review.json}"
	: "$${REVIEW_SHA256:?Set REVIEW_SHA256 to the review hash}"
	: "$${EXPECTED_DEPLOY_SHA:?Set EXPECTED_DEPLOY_SHA}"
	: "$${DEPLOY_ENVIRONMENT:?Set DEPLOY_ENVIRONMENT to staging or production}"
	: "$${RECOVERY_DIR:?Set RECOVERY_DIR to a durable absolute artifact directory}"
	./scripts/apply-plan.sh --plan "$${PLAN_FILE}" --expected-plan-sha "$${PLAN_SHA256}" --review "$${REVIEW_FILE}" --expected-review-sha "$${REVIEW_SHA256}" --expected-deploy-sha "$${EXPECTED_DEPLOY_SHA}" --recovery-dir "$${RECOVERY_DIR}"

export-klyrow:
	./scripts/export-client.sh --output "$${PWD}/artifacts/before" klyrow-portal

smoke:
	./scripts/smoke-test.sh

runtime-preflight:
	: "$${EXPECTED_DEPLOY_SHA:?Set EXPECTED_DEPLOY_SHA}"
	./scripts/runtime-preflight.sh --expected-deploy-sha "$${EXPECTED_DEPLOY_SHA}"

backup:
	./scripts/backup-postgres.sh

verify-backup:
	: "$${BACKUP_FILE:?Set BACKUP_FILE to an encrypted backup}"
	./scripts/verify-backup.sh "$${BACKUP_FILE}"

check-recovery-freshness:
	: "$${RESTORE_EVIDENCE_DIR:?Set RESTORE_EVIDENCE_DIR}"
	./scripts/check-recovery-freshness.sh "$${RESTORE_EVIDENCE_DIR}" "$${RESTORE_MAX_AGE_SECONDS:-2592000}"

certify-kong:
	./scripts/certify-kong.sh

openbao-workload-identity-check:
	python3 scripts/openbao_workload_identity_desired_state.py --check --require-cross-check

reconcile-openbao-workload-identity:
	python3 scripts/reconcile_openbao_workload_identity_staging.py --mode $(MODE) --output-dir $(OUTPUT_DIR)

edge-certification-check:
	python3 scripts/edge_certification_desired_state.py --check --require-cross-check
	python3 -m unittest discover -s tests -p 'test_edge_integration_certification.py' -v

certify-edge-identity:
	: "$${CERTIFY_ENVIRONMENT:?Set CERTIFY_ENVIRONMENT=staging}"
	: "$${CERTIFY_CAMPAIGN_ID:?Set CERTIFY_CAMPAIGN_ID=TEST_SYN}"
	: "$${EDGE_IDENTITY_REPORT:?Set EDGE_IDENTITY_REPORT to an absolute path outside the checkout}"
	python3 scripts/certify_edge_identity_staging.py --output "$${EDGE_IDENTITY_REPORT}"

reconcile-edge-certification:
	: "$${CERTIFY_ENVIRONMENT:?Set CERTIFY_ENVIRONMENT=staging}"
	: "$${CERTIFY_CAMPAIGN_ID:?Set CERTIFY_CAMPAIGN_ID=TEST_SYN}"
	: "$${EDGE_CERTIFICATION_MODE:?Set EDGE_CERTIFICATION_MODE to plan, apply, or disable}"
	: "$${EDGE_CERTIFICATION_DIR:?Set EDGE_CERTIFICATION_DIR to an absolute 0700 directory outside the checkout}"
	python3 scripts/reconcile_edge_certification_staging.py --mode "$${EDGE_CERTIFICATION_MODE}" --output-dir "$${EDGE_CERTIFICATION_DIR}"

.PHONY: mcr-identity-check
mcr-identity-check:
	python3 scripts/validate_mcr_identity.py
	python3 -m unittest discover -s tests -p 'test_mcr_identity.py' -v
