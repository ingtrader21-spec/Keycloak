#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
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

state_file="$test_root/client.json"
port_file="$test_root/port"
cp "$ROOT_DIR/config/clients/klyrow-portal.json" "$state_file"
jq '.redirectUris = ["https://wrong.example/callback"]' "$state_file" >"$state_file.tmp"
mv "$state_file.tmp" "$state_file"

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


class Handler(BaseHTTPRequestHandler):
    server_version = "MockKeycloak/1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/realms/codestra/protocol/openid-connect/token":
            self.send_json(200, {"access_token": "test-token", "expires_in": 60})
            return
        self.send_json(404, {"error": "not_found"})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/admin/realms/codestra/clients":
            query = parse_qs(parsed.query)
            if query.get("clientId") == ["klyrow-portal"]:
                self.send_json(200, [{"id": "client-uuid", "clientId": "klyrow-portal"}])
                return
        if parsed.path == "/admin/realms/codestra/clients/client-uuid":
            self.send_json(200, json.loads(state_path.read_text()))
            return
        self.send_json(404, {"error": "not_found"})

    def do_PUT(self) -> None:  # noqa: N802
        if self.path != "/admin/realms/codestra/clients/client-uuid":
            self.send_json(404, {"error": "not_found"})
            return
        content_length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(content_length))
        state_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        self.send_response(204)
        self.end_headers()


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
export KC_PUBLIC_URL="https://auth.codestra.co"
export KC_TARGET_REALM="codestra"
export KC_ADMIN_REALM="codestra"
export KC_ADMIN_CLIENT_ID="test-gitops-client"
: "${TEST_KC_CLIENT_SECRET:?Set TEST_KC_CLIENT_SECRET for the mock test}"
export KC_ADMIN_CLIENT_SECRET=$TEST_KC_CLIENT_SECRET
export ALLOW_INSECURE_KC_BASE_URL="true"
export ALLOW_NONCANONICAL_KC_BASE_URL_FOR_TESTS="true"
export DEPLOY_ENVIRONMENT="staging"
expected_sha="1111111111111111111111111111111111111111"

plan_dir="$test_root/plan"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$plan_dir" \
  --expected-deploy-sha "$expected_sha" >/dev/null

[[ "$(jq -er '.driftCount' "$plan_dir/plan.json")" -eq 1 ]]
[[ "$(jq -er '.blockedCount' "$plan_dir/plan.json")" -eq 0 ]]
[[ "$(jq -er '.clients[0].action' "$plan_dir/plan.json")" == "update" ]]
plan_sha256="$(awk 'NR == 1 {print $1}' "$plan_dir/plan.sha256")"
[[ "$plan_sha256" =~ ^[0-9a-f]{64}$ ]]

if "$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$plan_dir/plan.json" \
  --expected-plan-sha 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' \
  --expected-deploy-sha "$expected_sha" >/dev/null 2>&1; then
  echo 'TEST_ERROR=mismatched_plan_hash_was_accepted' >&2
  exit 1
fi

"$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$plan_dir/plan.json" \
  --expected-plan-sha "$plan_sha256" \
  --expected-deploy-sha "$expected_sha" >/dev/null

jq -e --slurpfile desired "$ROOT_DIR/config/clients/klyrow-portal.json" \
  '. == $desired[0]' "$state_file" >/dev/null

converged_dir="$test_root/converged"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$converged_dir" \
  --expected-deploy-sha "$expected_sha" >/dev/null
[[ "$(jq -er '.driftCount' "$converged_dir/plan.json")" -eq 0 ]]

printf 'PLAN_GATE_TESTS=PASS\n'
