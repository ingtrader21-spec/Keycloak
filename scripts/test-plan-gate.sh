#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/keycloak-admin.sh
source "$ROOT_DIR/scripts/lib/keycloak-admin.sh"
test_root="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$test_root"
}
trap cleanup EXIT

state_file="$test_root/clients.json"
port_file="$test_root/port"

jq -S -n \
  --slurpfile klyrow "$ROOT_DIR/config/clients/klyrow-portal.json" '
    {
      "klyrow-portal": {
        id: "uuid-klyrow",
        representation: ($klyrow[0] | .redirectUris = ["https://wrong.example/callback"])
      }
    }
  ' >"$state_file"

cat >"$test_root/mock_keycloak.py" <<'PY'
#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

state_path = Path(os.environ["MOCK_STATE_FILE"])
port_path = Path(os.environ["MOCK_PORT_FILE"])


def load_state() -> dict[str, dict]:
    return json.loads(state_path.read_text())


def save_state(value: dict[str, dict]) -> None:
    state_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def live_representation(client_id: str, item: dict) -> dict:
    value = json.loads(json.dumps(item["representation"]))
    value["id"] = item["id"]
    mappers = value.get("protocolMappers")
    if isinstance(mappers, list):
        for index, mapper in enumerate(mappers):
            if isinstance(mapper, dict):
                mapper.setdefault("id", f"mapper-{client_id}-{index}")
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "MockKeycloak/2"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        content_length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(content_length))

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/realms/master/protocol/openid-connect/token":
            self.send_json(200, {"access_token": "test-token", "expires_in": 60})
            return
        if parsed.path == "/admin/realms/codestra/clients":
            payload = self.read_json()
            client_id = str(payload.get("clientId") or "")
            state = load_state()
            if not client_id or client_id in state:
                self.send_json(409, {"error": "client_exists_or_invalid"})
                return
            # Match the admin API representation returned by Keycloak when
            # authorization services are disabled.
            if payload.get("authorizationServicesEnabled") is False:
                payload.pop("authorizationServicesEnabled")
            state[client_id] = {
                "id": f"uuid-{client_id}",
                "representation": payload,
            }
            save_state(state)
            self.send_response(201)
            self.end_headers()
            return
        self.send_json(404, {"error": "not_found"})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        state = load_state()
        if parsed.path == "/admin/realms/codestra/clients":
            query = parse_qs(parsed.query)
            client_ids = query.get("clientId") or []
            client_id = client_ids[0] if client_ids else ""
            item = state.get(client_id)
            if item is None:
                self.send_json(200, [])
            else:
                self.send_json(200, [{"id": item["id"], "clientId": client_id}])
            return

        prefix = "/admin/realms/codestra/clients/"
        if parsed.path.startswith(prefix):
            client_uuid = parsed.path.removeprefix(prefix)
            for client_id, item in state.items():
                if item["id"] == client_uuid:
                    self.send_json(200, live_representation(client_id, item))
                    return
            self.send_json(404, {"error": "not_found"})
            return
        self.send_json(404, {"error": "not_found"})

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        prefix = "/admin/realms/codestra/clients/"
        if not parsed.path.startswith(prefix):
            self.send_json(404, {"error": "not_found"})
            return
        client_uuid = parsed.path.removeprefix(prefix)
        state = load_state()
        for client_id, item in state.items():
            if item["id"] == client_uuid:
                payload = self.read_json()
                payload.pop("id", None)
                # Keycloak omits this field when authorization services are
                # disabled, so its admin API returns null after a successful
                # create/update with an explicit false value.
                if payload.get("authorizationServicesEnabled") is False:
                    payload.pop("authorizationServicesEnabled")
                item["representation"] = payload
                state[client_id] = item
                save_state(state)
                self.send_response(204)
                self.end_headers()
                return
        self.send_json(404, {"error": "not_found"})


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
port_path.write_text(str(server.server_port))
server.serve_forever()
PY

MOCK_STATE_FILE="$state_file" \
MOCK_PORT_FILE="$port_file" \
python3 "$test_root/mock_keycloak.py" &
server_pid=$!

for _ in {1..50}; do
  [[ -s "$port_file" ]] && break
  sleep 0.1
done
[[ -s "$port_file" ]] || {
  echo 'TEST_ERROR=mock_keycloak_failed_to_start' >&2
  exit 1
}

port="$(cat "$port_file")"
export KC_BASE_URL="http://127.0.0.1:${port}"
export KC_PUBLIC_URL="https://auth-staging.codestra.co"
export KC_TARGET_REALM="codestra"
export KC_ADMIN_REALM="master"
export KC_ADMIN_CLIENT_ID="test-gitops-client"
: "${TEST_KC_CLIENT_SECRET:?Set TEST_KC_CLIENT_SECRET for the mock test}"
export KC_ADMIN_CLIENT_SECRET=$TEST_KC_CLIENT_SECRET
export ALLOW_INSECURE_KC_BASE_URL="true"
export ALLOW_NONCANONICAL_KC_BASE_URL_FOR_TESTS="true"
export DEPLOY_ENVIRONMENT="staging"
expected_sha="1111111111111111111111111111111111111111"

[[ "$(keycloak_endpoint_file)" == "$ROOT_DIR/config/endpoints/codestra-staging.json" ]]
DEPLOY_ENVIRONMENT=production
[[ "$(keycloak_endpoint_file)" == "$ROOT_DIR/config/endpoints/codestra.json" ]]
DEPLOY_ENVIRONMENT=staging

plan_dir="$test_root/plan"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$plan_dir" \
  --expected-deploy-sha "$expected_sha" >/dev/null

[[ "$(jq -er '.api.adminApiBaseUrl' "$plan_dir/plan.json")" == "https://auth-staging.codestra.co" ]]
[[ "$(jq -er '.api.issuer' "$plan_dir/plan.json")" == "https://auth-staging.codestra.co/realms/codestra" ]]

[[ "$(jq -er '.driftCount' "$plan_dir/plan.json")" -eq 31 ]]
[[ "$(jq -er '.blockedCount' "$plan_dir/plan.json")" -eq 0 ]]
[[ "$(jq -er '.createCount' "$plan_dir/plan.json")" -eq 30 ]]
[[ "$(jq -er '.updateCount' "$plan_dir/plan.json")" -eq 1 ]]
[[ "$(jq -er '.clients[] | select(.clientId == "klyrow-portal") | .action' "$plan_dir/plan.json")" == "update" ]]
for client_id in moneybee-admin moneybee-borrower moneybee-lender moneybee-backend breero-backend larim-a-backend transportation-backend beyvra-backend social-codestra; do
  [[ "$(jq -er --arg client_id "$client_id" '.clients[] | select(.clientId == $client_id) | .action' "$plan_dir/plan.json")" == "create" ]]
  jq -e --arg client_id "$client_id" '
    .clients[]
    | select(.clientId == $client_id)
    | .before == {}
      and .rollback.kind == "disable_then_reviewed_delete"
      and .rollback.disableFirst == true
      and .rollback.deleteRequiresSeparateReviewedRollback == true
  ' "$plan_dir/plan.json" >/dev/null
done

plan_sha256="$(awk 'NR == 1 {print $1}' "$plan_dir/plan.sha256")"
[[ "$plan_sha256" =~ ^[0-9a-f]{64}$ ]]
export KEYCLOAK_REVIEWER_ID="independent-reviewer"
export KEYCLOAK_CHANGE_AUTHOR_ID="change-author"
export KEYCLOAK_CHANGE_TICKET="TEST-PLAN-GATE"
review_file="$test_root/review.json"
"$ROOT_DIR/scripts/review-plan.sh" \
  --plan "$plan_dir/plan.json" \
  --expected-plan-sha "$plan_sha256" \
  --expected-deploy-sha "$expected_sha" \
  --output "$review_file" >/dev/null
review_sha256="$(awk 'NR == 1 {print $1}' "${review_file}.sha256")"

rollback_dir="$test_root/rollback"
mapfile -t managed_clients < <(jq -r '.clients[]' "$ROOT_DIR/config/policy/managed-clients.json")
"$ROOT_DIR/scripts/export-client.sh" \
  --output "$rollback_dir" \
  "${managed_clients[@]}" >/dev/null
[[ -f "$rollback_dir/config/clients/klyrow-portal.json" ]]
[[ "$(jq -er '.existingClientCount' "$rollback_dir/rollback-metadata.json")" -eq 1 ]]
[[ "$(jq -er '.absentCreatableClientCount' "$rollback_dir/rollback-metadata.json")" -eq 30 ]]

# Exercise the apply create path with a non-empty test credential for every
# managed machine identity. Production values remain supplied only by the
# protected apply workflow; these placeholders never leave the test process.
while IFS= read -r secret_name; do
  printf -v "$secret_name" 'ci-only-%s' "$secret_name"
  export "$secret_name"
done < <(jq -er '.clients[].applyEnvironment' \
  "$ROOT_DIR/config/contracts/machine-secret-destinations.json")

if "$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$plan_dir/plan.json" \
  --expected-plan-sha 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' \
  --review "$review_file" \
  --expected-review-sha "$review_sha256" \
  --expected-deploy-sha "$expected_sha" >/dev/null 2>&1; then
  echo 'TEST_ERROR=mismatched_plan_hash_was_accepted' >&2
  exit 1
fi

jq -S \
  --slurpfile admin "$ROOT_DIR/config/clients/moneybee-admin.json" '
    .["moneybee-admin"] = {
      id: "uuid-race-moneybee-admin",
      representation: $admin[0]
    }
  ' "$state_file" >"$state_file.tmp"
mv "$state_file.tmp" "$state_file"

if "$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$plan_dir/plan.json" \
  --expected-plan-sha "$plan_sha256" \
  --review "$review_file" \
  --expected-review-sha "$review_sha256" \
  --expected-deploy-sha "$expected_sha" >/dev/null 2>&1; then
  echo 'TEST_ERROR=create_race_was_not_rejected' >&2
  exit 1
fi

jq -e '
  .["klyrow-portal"].representation.redirectUris == ["https://wrong.example/callback"]
  and has("moneybee-admin")
  and (has("moneybee-borrower") | not)
  and (has("moneybee-lender") | not)
  and (has("moneybee-backend") | not)
  and (has("social-codestra") | not)
' "$state_file" >/dev/null

jq -S 'del(."moneybee-admin")' "$state_file" >"$state_file.tmp"
mv "$state_file.tmp" "$state_file"

"$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$plan_dir/plan.json" \
  --expected-plan-sha "$plan_sha256" \
  --review "$review_file" \
  --expected-review-sha "$review_sha256" \
  --expected-deploy-sha "$expected_sha" >/dev/null

for client_id in klyrow-portal moneybee-admin moneybee-borrower moneybee-lender moneybee-backend breero-backend larim-a-backend transportation-backend beyvra-backend social-codestra sdk-intake alertmanager; do
  jq -e --arg client_id "$client_id" 'has($client_id)' "$state_file" >/dev/null
done
jq -e --slurpfile desired "$ROOT_DIR/config/clients/klyrow-portal.json" '
  .["klyrow-portal"].representation == $desired[0]
' "$state_file" >/dev/null

converged_dir="$test_root/converged"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$converged_dir" \
  --expected-deploy-sha "$expected_sha" >/dev/null
[[ "$(jq -er '.driftCount' "$converged_dir/plan.json")" -eq 0 ]]
[[ "$(jq -er '.blockedCount' "$converged_dir/plan.json")" -eq 0 ]]
[[ "$(jq -er '.createCount' "$converged_dir/plan.json")" -eq 0 ]]
[[ "$(jq -er '.updateCount' "$converged_dir/plan.json")" -eq 0 ]]

for client_id in moneybee-admin moneybee-borrower moneybee-lender; do
  jq -e --arg client_id "$client_id" '
    .[$client_id].representation.protocolMappers[0].name == "moneybee-api-audience"
  ' "$state_file" >/dev/null
done
for client_id in moneybee-backend breero-backend larim-a-backend transportation-backend beyvra-backend social-codestra sdk-intake alertmanager; do
  jq -e --arg client_id "$client_id" '
    .[$client_id].representation.serviceAccountsEnabled == true
    and .[$client_id].representation.publicClient == false
    and .[$client_id].representation.attributes["access.token.lifespan"] == "300"
  ' "$state_file" >/dev/null
done

jq -S 'del(."klyrow-portal")' "$state_file" >"$state_file.tmp"
mv "$state_file.tmp" "$state_file"
missing_dir="$test_root/missing-creatable"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$missing_dir" \
  --expected-deploy-sha "$expected_sha" >/dev/null
[[ "$(jq -er '.blockedCount' "$missing_dir/plan.json")" -eq 0 ]]
[[ "$(jq -er '.clients[] | select(.clientId == "klyrow-portal") | .action' "$missing_dir/plan.json")" == "create" ]]
jq -e '
  .clients[]
  | select(.clientId == "klyrow-portal")
  | .before == {}
    and .rollback.kind == "disable_then_reviewed_delete"
    and .rollback.disableFirst == true
    and .rollback.deleteRequiresSeparateReviewedRollback == true
' "$missing_dir/plan.json" >/dev/null

printf 'PLAN_GATE_TESTS=PASS\n'
printf 'INDEPENDENT_DRIFT_REVIEW_GATE=PASS\n'
printf 'ADMIN_AUTH_REALM=master\n'
printf 'TARGET_REALM=codestra\n'
printf 'REVIEWED_CREATE_TESTS=PASS\n'
printf 'CREATE_PREWRITE_RACE_GUARD=PASS\n'
printf 'ROLLBACK_EVIDENCE_TESTS=PASS\n'
printf 'MAPPER_NORMALIZATION_TESTS=PASS\n'
printf 'PRODUCT_MACHINE_CLIENT_CREATE_TESTS=PASS\n'
printf 'KLYROW_PORTAL_REVIEWED_CREATE=PASS\n'
