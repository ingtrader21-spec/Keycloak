SHELL := /usr/bin/env bash

.PHONY: validate test-runtime-preflight build up down logs check plan apply-plan export-klyrow smoke runtime-preflight

validate:
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

apply-plan:
	: "$${PLAN_FILE:?Set PLAN_FILE to reviewed plan.json}"
	: "$${PLAN_SHA256:?Set PLAN_SHA256 to the reviewed plan hash}"
	: "$${EXPECTED_DEPLOY_SHA:?Set EXPECTED_DEPLOY_SHA}"
	: "$${DEPLOY_ENVIRONMENT:?Set DEPLOY_ENVIRONMENT to staging or production}"
	./scripts/apply-plan.sh --plan "$${PLAN_FILE}" --expected-plan-sha "$${PLAN_SHA256}" --expected-deploy-sha "$${EXPECTED_DEPLOY_SHA}"

export-klyrow:
	./scripts/export-client.sh --output "$${PWD}/artifacts/before" klyrow-portal

smoke:
	./scripts/smoke-test.sh

runtime-preflight:
	: "$${EXPECTED_DEPLOY_SHA:?Set EXPECTED_DEPLOY_SHA}"
	./scripts/runtime-preflight.sh --expected-deploy-sha "$${EXPECTED_DEPLOY_SHA}"
