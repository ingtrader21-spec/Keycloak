#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import threading
from pathlib import Path

from protected_identity_test_server import build_server, load, write

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], env: dict[str, str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=check)


def invoke(script: str, arguments: list[str], env: dict[str, str], *, check: bool = True):
    return run([str(ROOT / "scripts" / script), *arguments], env, check=check)


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        state_file = temp / "state.json"
        klyrow = load(ROOT / "config/clients/klyrow-portal.json")
        viewer = load(ROOT / "config/realm-roles/observability-viewer.json")
        write(state_file, {
            "clients": {
                "klyrow-portal": {
                    "id": "uuid-klyrow-portal",
                    "representation": {**klyrow, "redirectUris": ["https://wrong.example/callback"], "secret": "must-never-enter-evidence"},
                    "secret": "mock-secret-klyrow-portal-0000000000",
                }
            },
            "roles": {
                "observability-viewer": {
                    "id": "role-observability-viewer",
                    "representation": {**viewer, "description": "drifted description"},
                }
            },
        })
        server = build_server(state_file)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env = dict(os.environ)
        env.update({
            "KC_BASE_URL": f"http://127.0.0.1:{server.server_port}",
            "KC_PUBLIC_URL": "https://auth.codestra.co",
            "KC_TARGET_REALM": "codestra",
            "KC_ADMIN_REALM": "master",
            "KC_ADMIN_CLIENT_ID": "test-gitops-client",
            "KC_ADMIN_CLIENT_SECRET": env.get("TEST_KC_CLIENT_SECRET", "ci-only-protected-identity-secret"),
            "ALLOW_INSECURE_KC_BASE_URL": "true",
            "ALLOW_NONCANONICAL_KC_BASE_URL_FOR_TESTS": "true",
            "DEPLOY_ENVIRONMENT": "staging",
        })
        expected_sha = "1" * 40
        try:
            plan_dir = temp / "plan"
            invoke("plan.sh", ["--output-dir", str(plan_dir), "--expected-deploy-sha", expected_sha], env)
            plan = load(plan_dir / "plan.json")
            assert (plan["schemaVersion"], plan["resourceCount"], plan["clientCount"], plan["realmRoleCount"]) == (2, 31, 26, 5)
            assert (plan["driftCount"], plan["blockedCount"], plan["createCount"], plan["updateCount"]) == (31, 0, 29, 2)
            assert next(item for item in plan["clients"] if item["clientId"] == "klyrow-portal")["action"] == "update"
            assert next(item for item in plan["realmRoles"] if item["roleName"] == "observability-viewer")["action"] == "update"
            for client_id in ("grafana-observability", "superset-analytics", "openbao-secrets", "sdk-intake"):
                item = next(value for value in plan["clients"] if value["clientId"] == client_id)
                assert item["action"] == "create" and item["rollback"]["kind"] == "disable_then_reviewed_delete"
            for role_name in ("observability-operator", "observability-admin", "secrets-operator", "secrets-admin"):
                item = next(value for value in plan["realmRoles"] if value["roleName"] == role_name)
                assert item["action"] == "create" and item["rollback"]["kind"] == "remove_assignments_then_reviewed_delete"
            plan_text = (plan_dir / "plan.json").read_text(encoding="utf-8")
            assert "must-never-enter-evidence" not in plan_text and "mock-secret" not in plan_text

            plan_hash = (plan_dir / "plan.sha256").read_text().split()[0]
            env.update({
                "KEYCLOAK_REVIEWER_ID": "independent-reviewer",
                "KEYCLOAK_CHANGE_AUTHOR_ID": "change-author",
                "KEYCLOAK_CHANGE_TICKET": "TEST-PROTECTED-IDENTITY",
            })
            review = temp / "review.json"
            invoke("review-plan.sh", ["--plan", str(plan_dir / "plan.json"), "--expected-plan-sha", plan_hash, "--expected-deploy-sha", expected_sha, "--output", str(review)], env)
            review_hash = Path(str(review) + ".sha256").read_text().split()[0]
            assert len(load(review)["reviewedActions"]) == 31

            rollback = temp / "rollback"
            managed = load(ROOT / "config/policy/managed-clients.json")["clients"]
            invoke("export-client.sh", ["--output", str(rollback), *managed], env)
            metadata = load(rollback / "rollback-metadata.json")
            assert (metadata["existingClientCount"], metadata["absentCreatableClientCount"]) == (1, 25)
            assert (metadata["existingRealmRoleCount"], metadata["absentCreatableRealmRoleCount"]) == (1, 4)
            assert "mock-secret" not in (rollback / "rollback-metadata.json").read_text()

            bad = invoke("apply-plan.sh", ["--plan", str(plan_dir / "plan.json"), "--expected-plan-sha", "f" * 64, "--review", str(review), "--expected-review-sha", review_hash, "--expected-deploy-sha", expected_sha], env, check=False)
            assert bad.returncode != 0

            raced = load(state_file)
            grafana = load(ROOT / "config/clients/grafana-observability.json")
            raced["clients"]["grafana-observability"] = {"id": "uuid-race-grafana", "representation": grafana, "secret": "mock-race-secret-0000000000"}
            write(state_file, raced)
            race = invoke("apply-plan.sh", ["--plan", str(plan_dir / "plan.json"), "--expected-plan-sha", plan_hash, "--review", str(review), "--expected-review-sha", review_hash, "--expected-deploy-sha", expected_sha], env, check=False)
            assert race.returncode != 0
            after = load(state_file)
            assert after["clients"]["klyrow-portal"]["representation"]["redirectUris"] == ["https://wrong.example/callback"]
            assert "observability-operator" not in after["roles"]
            del after["clients"]["grafana-observability"]
            write(state_file, after)

            invoke("apply-plan.sh", ["--plan", str(plan_dir / "plan.json"), "--expected-plan-sha", plan_hash, "--review", str(review), "--expected-review-sha", review_hash, "--expected-deploy-sha", expected_sha], env)
            converged_dir = temp / "converged"
            invoke("plan.sh", ["--output-dir", str(converged_dir), "--expected-deploy-sha", expected_sha], env)
            converged = load(converged_dir / "plan.json")
            assert converged["driftCount"] == 0 and converged["blockedCount"] == 0
            final = load(state_file)
            assert len(final["clients"]) == 26 and len(final["roles"]) == 5
            assert final["roles"]["observability-admin"]["representation"]["attributes"]["codestra.role.family"] == ["observability"]
            assert final["roles"]["secrets-admin"]["representation"]["attributes"]["codestra.role.family"] == ["secrets"]

            secret_dir = temp / "secret-handoff"
            result = invoke("export-generated-client-secrets.sh", ["--output-dir", str(secret_dir)], env)
            assert "mock-secret-" not in result.stdout and "mock-secret-" not in result.stderr
            manifest = load(secret_dir / "manifest.json")
            assert [item["clientId"] for item in manifest["clients"]] == ["grafana-observability", "openbao-secrets", "superset-analytics"]
            for item in manifest["clients"]:
                secret_path = secret_dir / item["file"]
                assert secret_path.read_text().startswith("mock-secret-")
                assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600

            final = load(state_file)
            del final["clients"]["klyrow-portal"]
            write(state_file, final)
            blocked_dir = temp / "blocked"
            invoke("plan.sh", ["--output-dir", str(blocked_dir), "--expected-deploy-sha", expected_sha], env)
            blocked = load(blocked_dir / "plan.json")
            assert blocked["blockedCount"] == 1
            assert next(item for item in blocked["clients"] if item["clientId"] == "klyrow-portal")["action"] == "blocked_missing"

            print("PLAN_GATE_TESTS=PASS")
            print("CLIENT_AND_REALM_ROLE_PLAN=PASS")
            print("INDEPENDENT_DRIFT_REVIEW_GATE=PASS")
            print("CREATE_PREWRITE_RACE_GUARD=PASS")
            print("ROLLBACK_EVIDENCE_TESTS=PASS")
            print("CLIENT_SECRET_REDACTION=PASS")
            print("CLIENT_SECRET_HANDOFF_TEST=PASS")
            print("ROLE_ISOLATION_TEST=PASS")
            print("NO_LIVE_APPLY=PASS")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
