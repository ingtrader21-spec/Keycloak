SHELL := /usr/bin/env bash

.PHONY: validate build up down logs check apply export-klyrow smoke

validate:
	./scripts/validate.sh

build:
	docker build --build-arg KEYCLOAK_VERSION=$${KEYCLOAK_VERSION:-26.7.2} -t $${KEYCLOAK_IMAGE:-codestra-keycloak:local} .

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=200 keycloak

check:
	./scripts/reconcile.sh --check

apply:
	./scripts/reconcile.sh --apply

export-klyrow:
	./scripts/export-client.sh --output ./artifacts/before klyrow-portal

smoke:
	./scripts/smoke-test.sh
