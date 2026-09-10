#!/usr/bin/env python3
"""Fail-closed validation for immutable, isolated Keycloak runtime authority."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$")
GHCR_RUNTIME = re.compile(
    r"^\$\{KEYCLOAK_IMAGE:\?[^}]+\}$"
)


def fail(message: str) -> None:
    raise SystemExit(f"RUNTIME_SECURITY_ERROR={message}")


compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
services = compose.get("services", {})
if set(services) != {"postgres", "keycloak-image-policy", "keycloak"}:
    fail("dedicated compose may contain only postgres, image policy, and keycloak")

postgres = services["postgres"]
image_policy = services["keycloak-image-policy"]
keycloak = services["keycloak"]
if keycloak.get("extra_hosts") != ["mail.klyrow.com:10.40.0.4"]:
    fail("SMTP certificate hostname must resolve only to the private Klyrow relay")
if not DIGEST.fullmatch(str(postgres.get("image", ""))):
    fail("postgres image must use a version and immutable sha256 digest")
if not GHCR_RUNTIME.fullmatch(str(keycloak.get("image", ""))):
    fail("Keycloak runtime image must be a required externally supplied release digest")
if "build" in keycloak:
    fail("production compose must deploy a published image, not build in place")

for name, service in {"postgres": postgres, "keycloak": keycloak}.items():
    if service.get("privileged") is True:
        fail(f"{name} must not be privileged")
    if service.get("read_only") is not True:
        fail(f"{name} root filesystem must be read-only")
    if service.get("cap_drop") != ["ALL"]:
        fail(f"{name} must drop all capabilities")
    if service.get("security_opt") != ["no-new-privileges:true"]:
        fail(f"{name} must set no-new-privileges")
    if service.get("restart") != "unless-stopped":
        fail(f"{name} restart policy is invalid")
    if not isinstance(service.get("pids_limit"), int) or service["pids_limit"] <= 0:
        fail(f"{name} must set a positive PID limit")
    if not service.get("mem_limit") or not service.get("cpus"):
        fail(f"{name} must set memory and CPU limits")
    logging = service.get("logging", {})
    if logging.get("driver") != "json-file" or logging.get("options") != {
        "max-size": "10m",
        "max-file": "5",
    }:
        fail(f"{name} log rotation policy is invalid")

if image_policy.get("image") != postgres.get("image"):
    fail("image policy helper must reuse the immutable postgres image")
if image_policy.get("restart") != "no":
    fail("image policy helper must be a one-shot service")
if image_policy.get("read_only") is not True:
    fail("image policy helper root filesystem must be read-only")
if image_policy.get("cap_drop") != ["ALL"]:
    fail("image policy helper must drop all capabilities")
if image_policy.get("security_opt") != ["no-new-privileges:true"]:
    fail("image policy helper must set no-new-privileges")
if image_policy.get("networks") != ["keycloak-internal"]:
    fail("image policy helper must use only the dedicated internal network")
if set(image_policy.get("environment", {})) != {"CANDIDATE_IMAGE"}:
    fail("image policy helper environment is invalid")
if image_policy.get("entrypoint") != ["/bin/sh", "-ec"]:
    fail("image policy helper entrypoint is invalid")
policy_command = image_policy.get("command")
if not isinstance(policy_command, list) or len(policy_command) != 1:
    fail("image policy helper command is invalid")
if "ghcr.io/appolon1908-hue/codestra-keycloak:" not in policy_command[0] or "@sha256:" not in policy_command[0]:
    fail("image policy helper must enforce approved GHCR digest identity")
if "ghcr.io/appolon1908-hue/*:" in policy_command[0]:
    fail("image policy helper must not accept another package in the owner namespace")

if "ports" in postgres:
    fail("postgres must not publish a host port")
if keycloak.get("ports") != [
    "127.0.0.1:${KEYCLOAK_HTTP_PORT:-8080}:8080",
    "127.0.0.1:${KEYCLOAK_MANAGEMENT_PORT:-9000}:9000",
]:
    fail("Keycloak application and management ports must bind only to localhost")
if postgres.get("networks") != ["keycloak-internal"]:
    fail("postgres must use only the dedicated internal network")
if keycloak.get("networks") != ["keycloak-internal"]:
    fail("Keycloak must use only the dedicated internal network")

allowed_postgres_env = {"POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD"}
allowed_keycloak_env = {
    "KC_DB",
    "KC_DB_URL_HOST",
    "KC_DB_URL_PORT",
    "KC_DB_URL_DATABASE",
    "KC_DB_USERNAME",
    "KC_DB_PASSWORD",
    "KC_HOSTNAME",
    "KC_HOSTNAME_STRICT",
    "KC_HTTP_ENABLED",
    "KC_PROXY_HEADERS",
    "KC_HEALTH_ENABLED",
    "KC_METRICS_ENABLED",
    "KC_CACHE",
    "KC_CACHE_STACK",
    "KC_BOOTSTRAP_ADMIN_USERNAME",
    "KC_BOOTSTRAP_ADMIN_PASSWORD",
    "MONEYBEE_EMAIL_OTP_HMAC_KEY",
}
if set(postgres.get("environment", {})) != allowed_postgres_env:
    fail("postgres environment contains missing or unrelated variables")
if set(keycloak.get("environment", {})) != allowed_keycloak_env:
    fail("Keycloak environment contains missing or unrelated variables")

dockerfile = (ROOT / "Dockerfile").read_text()
base_matches = re.findall(
    r"^ARG KEYCLOAK_BASE_IMAGE=(quay\.io/keycloak/keycloak:[^\s]+@sha256:[0-9a-f]{64})$",
    dockerfile,
    flags=re.MULTILINE,
)
if len(base_matches) != 1 or not DIGEST.fullmatch(base_matches[0]):
    fail("Dockerfile Keycloak base must be pinned by version and digest")
if dockerfile.count("FROM ${KEYCLOAK_BASE_IMAGE}") != 2:
    fail("both Dockerfile stages must use the same immutable base image")
if "USER 1000" not in dockerfile:
    fail("final Keycloak image must run as UID 1000")

secret_examples = {
    "postgres.env.example": {"POSTGRES_PASSWORD"},
    "bootstrap-admin.env.example": {"KC_BOOTSTRAP_ADMIN_PASSWORD"},
    "admin-api.env.example": {"KC_ADMIN_CLIENT_ID", "KC_ADMIN_CLIENT_SECRET"},
    "smtp.env.example": {"KC_SMTP_USERNAME", "KC_SMTP_PASSWORD"},
    "monitoring.env.example": {
        "KEYCLOAK_MONITORING_CLIENT_ID",
        "KEYCLOAK_MONITORING_CLIENT_SECRET",
    },
    "runtime-ssh.env.example": {"RUNTIME_GIT_SSH_KEY", "RUNTIME_GIT_KNOWN_HOSTS"},
    "moneybee-otp.env.example": {"MONEYBEE_EMAIL_OTP_HMAC_KEY"},
}
secret_dir = ROOT / "deploy" / "secrets"
for filename, expected_names in secret_examples.items():
    lines = [
        line
        for line in (secret_dir / filename).read_text().splitlines()
        if line and not line.startswith("#")
    ]
    names = {line.split("=", 1)[0] for line in lines}
    if names != expected_names:
        fail(f"secret boundary is invalid in {filename}")

print("IMMUTABLE_IMAGE_POLICY=PASS")
print("RUNTIME_HARDENING_POLICY=PASS")
print("SECRET_SEGREGATION_POLICY=PASS")
