#!/usr/bin/env python3
"""Hosted-CI-only compatibility test. Never uses production backups or clients."""
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
import urllib.request


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("Disposable Docker operation failed: " + args[0])
    return result.stdout.strip()


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Hosted GitHub runner required; production execution forbidden")
    image = os.environ["RELEASE_IMAGE"]
    if not re.fullmatch(r"ghcr.io/appolon1908-hue/codestra-keycloak@sha256:[0-9a-f]{64}", image):
        raise SystemExit("Exact immutable candidate required")
    pg = "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94"
    prefix = "kc-cert-" + secrets.token_hex(6)
    db, kc = prefix + "-db", prefix + "-kc"
    docker("pull", pg)
    docker("pull", image)
    with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
        root = Path(tmp)
        password = secrets.token_hex(32)
        db_env = root / "db.env"
        kc_env = root / "kc.env"
        db_env.write_text("POSTGRES_DB=keycloak\nPOSTGRES_USER=keycloak\nPOSTGRES_PASSWORD=" + password + "\n")
        kc_env.write_text("KC_DB=postgres\nKC_DB_URL=jdbc:postgresql://" + db + ":5432/keycloak\nKC_DB_USERNAME=keycloak\nKC_DB_PASSWORD=" + password + "\nKC_HTTP_ENABLED=true\nKC_HOSTNAME=https://auth.codestra.co\n")
        for path in (db_env, kc_env):
            path.chmod(0o600)
        realm = root / "codestra.json"
        realm.write_text(json.dumps({"realm": "codestra", "enabled": True, "registrationAllowed": False, "smtpServer": {}}))
        realm.chmod(0o644)
        docker("network", "create", "--internal", prefix)
        try:
            docker("run", "-d", "--name", db, "--network", prefix, "--env-file", str(db_env), pg)
            for _ in range(60):
                r = subprocess.run(["docker", "exec", db, "pg_isready", "-U", "keycloak"], capture_output=True)
                if r.returncode == 0:
                    break
                time.sleep(2)
            else:
                raise RuntimeError("Disposable PostgreSQL readiness failed")
            docker("run", "-d", "--name", kc, "--network", prefix, "--env-file", str(kc_env),
                   "-p", "127.0.0.1::8080", "-p", "127.0.0.1::9000", "-v", str(realm) + ":/opt/keycloak/data/import/codestra.json:ro",
                   image, "start", "--optimized", "--import-realm")
            app_port = docker("port", kc, "8080/tcp").rsplit(":", 1)[1]
            health_port = docker("port", kc, "9000/tcp").rsplit(":", 1)[1]
            for _ in range(120):
                try:
                    with urllib.request.urlopen("http://127.0.0.1:" + health_port + "/health/ready", timeout=3) as response:
                        assert json.load(response)["status"] == "UP"
                    break
                except Exception:
                    time.sleep(2)
            else:
                raise RuntimeError("Disposable Keycloak readiness failed")
            with urllib.request.urlopen("http://127.0.0.1:" + health_port + "/health", timeout=5) as response:
                assert json.load(response)["status"] == "UP"
            with urllib.request.urlopen("http://127.0.0.1:" + app_port + "/realms/codestra/.well-known/openid-configuration", timeout=5) as response:
                assert json.load(response)["issuer"] == "https://auth.codestra.co/realms/codestra"
            print("PG17_6_COMPATIBILITY=PASS_SYNTHETIC_REALM_ONLY")
        finally:
            subprocess.run(["docker", "rm", "-fv", kc, db], capture_output=True)
            subprocess.run(["docker", "network", "rm", prefix], capture_output=True)


if __name__ == "__main__":
    main()
