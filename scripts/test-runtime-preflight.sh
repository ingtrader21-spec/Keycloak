#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

mkdir -p "$test_root/bin" "$test_root/repository" "$test_root/runtime" "$test_root/reports"

cat >"$test_root/bin/ssh" <<'STUB'
#!/usr/bin/env bash
printf 'ssh stub must not be called during --no-network tests\n' >&2
exit 99
STUB

cat >"$test_root/bin/ssh-keygen" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == "-y" ]]; then
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyRuntimePreflightKey\n'
  exit 0
fi
if [[ "${1:-}" == "-lf" ]]; then
  cat >/dev/null
  printf '256 SHA256:RuntimePreflightTestOnly no-comment (ED25519)\n'
  exit 0
fi
if [[ "${1:-}" == "-F" ]]; then
  printf '# Host github.com found: line 1\n'
  printf 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyKnownHost\n'
  exit 0
fi
exit 64
STUB
chmod 700 "$test_root/bin/ssh" "$test_root/bin/ssh-keygen"

cat >"$test_root/repository/compose.yaml" <<'COMPOSE'
services:
  keycloak:
    image: example.invalid/keycloak:test
COMPOSE

git -C "$test_root/repository" init --initial-branch=main --quiet
git -C "$test_root/repository" config user.name 'Runtime Preflight Test'
git -C "$test_root/repository" config user.email 'runtime-preflight@example.invalid'
git -C "$test_root/repository" add compose.yaml
git -C "$test_root/repository" commit --quiet -m 'test fixture'
git -C "$test_root/repository" remote add origin git@github.com:appolon1908-hue/Keycloak.git
expected_sha="$(git -C "$test_root/repository" rev-parse HEAD)"

printf 'TEST_FIXTURE=not-a-secret\n' >"$test_root/runtime/keycloak.env"
printf 'auth.codestra.co { reverse_proxy 127.0.0.1:8080 }\n' >"$test_root/runtime/auth.codestra.co.caddy"
printf 'test-only-private-key-placeholder\n' >"$test_root/runtime/github-keycloak-readonly"
printf 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyKnownHost\n' >"$test_root/runtime/github-known-hosts"

chmod 755 "$test_root/repository"
chmod 644 "$test_root/repository/compose.yaml" "$test_root/runtime/auth.codestra.co.caddy"
chmod 600 "$test_root/runtime/keycloak.env" "$test_root/runtime/github-keycloak-readonly" "$test_root/runtime/github-known-hosts"

export PATH="$test_root/bin:$PATH"
export RUNTIME_REPO_DIR="$test_root/repository"
export RUNTIME_COMPOSE_FILE="$test_root/repository/compose.yaml"
export RUNTIME_ENV_FILE="$test_root/runtime/keycloak.env"
export RUNTIME_CADDY_FILE="$test_root/runtime/auth.codestra.co.caddy"
export RUNTIME_GIT_SSH_KEY="$test_root/runtime/github-keycloak-readonly"
export RUNTIME_GIT_KNOWN_HOSTS="$test_root/runtime/github-known-hosts"
export RUNTIME_GIT_REMOTE='git@github.com:appolon1908-hue/Keycloak.git'
export RUNTIME_GIT_BRANCH='main'

report_file="$test_root/reports/runtime-preflight.txt"
output="$(
  "$ROOT_DIR/scripts/runtime-preflight.sh" \
    --no-network \
    --expected-deploy-sha "$expected_sha" \
    --report "$report_file"
)"

grep -qx 'RUNTIME_PREFLIGHT=PASS' <<<"$output"
grep -qx "EXPECTED_DEPLOY_SHA=${expected_sha}" <<<"$output"
grep -qx 'GITHUB_KNOWN_HOSTS_EXCLUSIVE=PASS' <<<"$output"
grep -qx 'GITHUB_SSH_READ_ACCESS=SKIPPED_OFFLINE' <<<"$output"
grep -qx 'LIVE_SERVICE_CHANGES=NONE' <<<"$output"
[[ -f "$report_file" ]]

fingerprint="$(awk -F= '$1 == "RUNTIME_PATHS_FINGERPRINT" {print $2}' <<<"$output")"
[[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]]

approved_output="$(
  "$ROOT_DIR/scripts/runtime-preflight.sh" \
    --no-network \
    --expected-deploy-sha "$expected_sha" \
    --require-approved "$fingerprint"
)"
grep -qx 'RUNTIME_PATHS_APPROVAL=PASS' <<<"$approved_output"

if "$ROOT_DIR/scripts/runtime-preflight.sh" \
  --no-network \
  --expected-deploy-sha "$expected_sha" \
  --require-approved '' \
  >/dev/null 2>&1; then
  printf 'TEST_ERROR=empty_approved_fingerprint_was_accepted\n' >&2
  exit 1
fi

if "$ROOT_DIR/scripts/runtime-preflight.sh" \
  --no-network \
  --expected-deploy-sha "$expected_sha" \
  --require-approved 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' \
  >/dev/null 2>&1; then
  printf 'TEST_ERROR=mismatched_fingerprint_was_accepted\n' >&2
  exit 1
fi

if "$ROOT_DIR/scripts/runtime-preflight.sh" \
  --no-network \
  --expected-deploy-sha '0000000000000000000000000000000000000000' \
  >/dev/null 2>&1; then
  printf 'TEST_ERROR=runtime_sha_mismatch_was_accepted\n' >&2
  exit 1
fi

chmod 644 "$RUNTIME_GIT_SSH_KEY"
if "$ROOT_DIR/scripts/runtime-preflight.sh" \
  --no-network \
  --expected-deploy-sha "$expected_sha" \
  >/dev/null 2>&1; then
  printf 'TEST_ERROR=insecure_deploy_key_permissions_were_accepted\n' >&2
  exit 1
fi
chmod 600 "$RUNTIME_GIT_SSH_KEY"

printf 'other.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly\n' >>"$RUNTIME_GIT_KNOWN_HOSTS"
if "$ROOT_DIR/scripts/runtime-preflight.sh" \
  --no-network \
  --expected-deploy-sha "$expected_sha" \
  >/dev/null 2>&1; then
  printf 'TEST_ERROR=nonexclusive_known_hosts_was_accepted\n' >&2
  exit 1
fi

printf 'RUNTIME_PREFLIGHT_TESTS=PASS\n'
