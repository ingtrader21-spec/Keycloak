#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT

mkdir -p "$test_root/bin" "$test_root/runner-temp" "$test_root/home"
cat >"$test_root/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-}" in
  login)
    _token=''
    IFS= read -r _token || [[ -n "$_token" ]]
    printf 'login\n' >>"$DOCKER_TEST_LOG"
    ;;
  logout)
    printf 'logout\n' >>"$DOCKER_TEST_LOG"
    ;;
  *)
    printf 'unexpected:%s\n' "${1:-}" >>"$DOCKER_TEST_LOG"
    exit 1
    ;;
esac
EOF
chmod 700 "$test_root/bin/docker"

run_case() {
  local mode="$1"
  local case_root="$test_root/$mode"
  mkdir -p "$case_root"
  : >"$case_root/docker.log"
  set +e
  PATH="$test_root/bin:$PATH" \
  HOME="$test_root/home" \
  RUNNER_TEMP="$test_root/runner-temp" \
  GHCR_USERNAME='stage6-reader' \
  GHCR_TOKEN='test-token-must-not-be-logged' \
  DOCKER_TEST_LOG="$case_root/docker.log" \
  AUTH_SCRIPT="$ROOT_DIR/scripts/ephemeral-docker-auth.sh" \
    bash -c 'set -Eeuo pipefail; source "$AUTH_SCRIPT"; printf "%s\n" "$DOCKER_CONFIG" >"$DOCKER_TEST_LOG.path"; [[ "$(stat -c %a "$DOCKER_CONFIG")" == 700 ]]; [[ "$1" == success ]] || false' _ "$mode" \
    >"$case_root/stdout" 2>"$case_root/stderr"
  local status=$?
  set -e
  if [[ "$mode" == success ]]; then
    [[ $status -eq 0 ]]
  else
    [[ $status -ne 0 ]]
  fi
  local config_path
  config_path="$(cat "$case_root/docker.log.path")"
  [[ "$config_path" == "$test_root/runner-temp/"docker-config.* ]]
  [[ ! -e "$config_path" ]]
  [[ "$(tr '\n' ' ' <"$case_root/docker.log")" == 'login logout ' ]]
  ! grep -R -Fq 'test-token-must-not-be-logged' "$case_root/stdout" "$case_root/stderr" "$case_root/docker.log"
}

run_case success
run_case failure
[[ ! -e "$test_root/home/.docker" ]]
printf 'EPHEMERAL_DOCKER_CONFIG_TEST=PASS\n'
