#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

REPORT_FILE=""
NO_NETWORK=false
APPROVED_FINGERPRINT=""
REQUIRE_APPROVED=false
EXPECTED_DEPLOY_SHA="${EXPECTED_DEPLOY_SHA:-}"

usage() {
  cat <<'USAGE'
Usage: scripts/runtime-preflight.sh [OPTIONS]

Read-only verification of the server paths, exact runtime release identity, and
GitHub SSH read access used by the Keycloak deployment workflow. This script
does not fetch or pull code, restart containers, reload Caddy, or call a
mutating Keycloak endpoint.

Options:
  --report PATH                 Write a redacted report to PATH.
  --expected-deploy-sha SHA     Require runtime HEAD and remote main to equal
                                this exact 40-character Git commit SHA.
  --require-approved SHA256     Require the stable runtime-path fingerprint to
                                equal the approved 64-character SHA-256 value.
  --no-network                  Skip git ls-remote. Intended only for CI tests.
  -h, --help                    Show this help.

Required environment variables:
  RUNTIME_REPO_DIR
  RUNTIME_COMPOSE_FILE
  RUNTIME_ENV_FILE
  RUNTIME_CADDY_FILE
  RUNTIME_GIT_SSH_KEY
  RUNTIME_GIT_KNOWN_HOSTS

Optional environment variables:
  RUNTIME_GIT_REMOTE            Defaults to the canonical repository SSH URL.
  RUNTIME_GIT_BRANCH            Defaults to main.
USAGE
}

fail() {
  printf 'RUNTIME_PREFLIGHT_ERROR=%s\n' "$*" >&2
  exit 1
}

require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 ||
    fail "Required command is not installed: $command_name"
}

require_env() {
  local variable_name="$1"
  [[ -n "${!variable_name:-}" ]] ||
    fail "Required environment variable is not set: $variable_name"
}

while (($#)); do
  case "$1" in
    --report)
      [[ $# -ge 2 ]] || fail "--report requires a path"
      REPORT_FILE="$2"
      shift 2
      ;;
    --expected-deploy-sha)
      [[ $# -ge 2 ]] || fail "--expected-deploy-sha requires a commit SHA"
      EXPECTED_DEPLOY_SHA="$2"
      shift 2
      ;;
    --require-approved)
      [[ $# -ge 2 ]] || fail "--require-approved requires a SHA-256 value"
      APPROVED_FINGERPRINT="$2"
      REQUIRE_APPROVED=true
      shift 2
      ;;
    --no-network)
      NO_NETWORK=true
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "Unknown option: $1"
      ;;
  esac
done

for command_name in git realpath sha256sum stat ssh ssh-keygen awk timeout grep; do
  require_command "$command_name"
done

for variable_name in \
  RUNTIME_REPO_DIR \
  RUNTIME_COMPOSE_FILE \
  RUNTIME_ENV_FILE \
  RUNTIME_CADDY_FILE \
  RUNTIME_GIT_SSH_KEY \
  RUNTIME_GIT_KNOWN_HOSTS; do
  require_env "$variable_name"
done

[[ "$EXPECTED_DEPLOY_SHA" =~ ^[0-9a-f]{40}$ ]] ||
  fail "Expected deployment SHA must be 40 lowercase hexadecimal characters"

RUNTIME_GIT_REMOTE="${RUNTIME_GIT_REMOTE:-git@github.com:appolon1908-hue/Keycloak.git}"
RUNTIME_GIT_BRANCH="${RUNTIME_GIT_BRANCH:-main}"
readonly EXPECTED_REMOTE='git@github.com:appolon1908-hue/Keycloak.git'
readonly EXPECTED_BRANCH='main'

[[ "$RUNTIME_GIT_REMOTE" == "$EXPECTED_REMOTE" ]] ||
  fail "RUNTIME_GIT_REMOTE must equal the canonical repository SSH URL"
[[ "$RUNTIME_GIT_BRANCH" == "$EXPECTED_BRANCH" ]] ||
  fail "RUNTIME_GIT_BRANCH must equal main"

resolve_path() {
  local variable_name="$1"
  local expected_type="$2"
  local configured_path="${!variable_name}"
  local resolved_path

  [[ "$configured_path" == /* ]] ||
    fail "$variable_name must be an absolute path"
  [[ "$configured_path" != *$'\n'* && "$configured_path" != *$'\r'* ]] ||
    fail "$variable_name contains a line break"
  [[ ! -L "$configured_path" ]] ||
    fail "$variable_name must point directly to the approved target, not a symlink"

  resolved_path="$(realpath -e -- "$configured_path")" ||
    fail "$variable_name does not resolve: $configured_path"
  [[ "$resolved_path" == "$configured_path" ]] ||
    fail "$variable_name must use its canonical real path"

  case "$expected_type" in
    directory)
      [[ -d "$resolved_path" ]] || fail "$variable_name is not a directory"
      ;;
    file)
      [[ -f "$resolved_path" ]] || fail "$variable_name is not a regular file"
      ;;
    *)
      fail "Internal error: unsupported expected path type"
      ;;
  esac

  printf -v "$variable_name" '%s' "$resolved_path"
}

mode_number() {
  local path="$1"
  local mode
  mode="$(stat -c '%a' -- "$path")"
  printf '%d\n' "$((8#$mode))"
}

require_no_group_world_write() {
  local label="$1"
  local path="$2"
  local numeric_mode
  numeric_mode="$(mode_number "$path")"
  (( (numeric_mode & 8#022) == 0 )) ||
    fail "$label must not be group- or world-writable"
}

require_private_file() {
  local label="$1"
  local path="$2"
  local numeric_mode
  numeric_mode="$(mode_number "$path")"
  (( (numeric_mode & 8#077) == 0 )) ||
    fail "$label must not grant any group or world permissions"
}

resolve_path RUNTIME_REPO_DIR directory
resolve_path RUNTIME_COMPOSE_FILE file
resolve_path RUNTIME_ENV_FILE file
resolve_path RUNTIME_CADDY_FILE file
resolve_path RUNTIME_GIT_SSH_KEY file
resolve_path RUNTIME_GIT_KNOWN_HOSTS file

case "$RUNTIME_COMPOSE_FILE" in
  "$RUNTIME_REPO_DIR"/*)
    ;;
  *)
    fail "RUNTIME_COMPOSE_FILE must be inside RUNTIME_REPO_DIR"
    ;;
esac

for sensitive_path in \
  "$RUNTIME_ENV_FILE" \
  "$RUNTIME_GIT_SSH_KEY" \
  "$RUNTIME_GIT_KNOWN_HOSTS"; do
  case "$sensitive_path" in
    "$RUNTIME_REPO_DIR"/*)
      fail "Secret-bearing runtime files and SSH material must remain outside the Git checkout"
      ;;
  esac
done

require_no_group_world_write "Runtime repository directory" "$RUNTIME_REPO_DIR"
require_no_group_world_write "Compose file" "$RUNTIME_COMPOSE_FILE"
require_no_group_world_write "Caddy file" "$RUNTIME_CADDY_FILE"
require_private_file "Runtime environment file" "$RUNTIME_ENV_FILE"
require_private_file "GitHub deploy key" "$RUNTIME_GIT_SSH_KEY"
require_private_file "GitHub known_hosts file" "$RUNTIME_GIT_KNOWN_HOSTS"

runner_uid="$(id -u)"
for owned_file in "$RUNTIME_GIT_SSH_KEY" "$RUNTIME_GIT_KNOWN_HOSTS"; do
  [[ "$(stat -c '%u' -- "$owned_file")" == "$runner_uid" ]] ||
    fail "GitHub SSH material must be owned by the workflow runner user: $owned_file"
done

while IFS= read -r known_host_line; do
  [[ "$known_host_line" =~ ^github\.com[[:space:]]+ssh-ed25519[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]] ||
    fail "The dedicated known_hosts file may contain only explicit github.com ssh-ed25519 entries"
done < <(grep -Ev '^[[:space:]]*(#|$)' "$RUNTIME_GIT_KNOWN_HOSTS")

grep -Eq '^github\.com[[:space:]]+ssh-ed25519[[:space:]]+' "$RUNTIME_GIT_KNOWN_HOSTS" ||
  fail "The dedicated known_hosts file does not contain a github.com Ed25519 key"
ssh-keygen -F github.com -f "$RUNTIME_GIT_KNOWN_HOSTS" >/dev/null ||
  fail "The dedicated known_hosts file cannot resolve github.com"

safe_repo_git() {
  GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 \
    git \
      -c core.hooksPath=/dev/null \
      -c core.fsmonitor=false \
      -C "$RUNTIME_REPO_DIR" \
      "$@"
}

[[ "$(safe_repo_git rev-parse --is-inside-work-tree)" == "true" ]] ||
  fail "RUNTIME_REPO_DIR is not a Git working tree"

origin_url="$(safe_repo_git remote get-url origin)"
[[ "$origin_url" == "$RUNTIME_GIT_REMOTE" ]] ||
  fail "The runtime repository origin does not match the approved SSH remote"

repository_branch="$(safe_repo_git symbolic-ref --quiet --short HEAD || true)"
[[ "$repository_branch" == "$RUNTIME_GIT_BRANCH" ]] ||
  fail "The runtime repository must be checked out on the approved branch"

repository_status="$(safe_repo_git status --porcelain=v1 --untracked-files=normal)"
[[ -z "$repository_status" ]] ||
  fail "The runtime repository contains tracked or untracked changes"

repository_head="$(safe_repo_git rev-parse HEAD)"
[[ "$repository_head" == "$EXPECTED_DEPLOY_SHA" ]] ||
  fail "Runtime repository HEAD does not equal the selected GitHub deployment SHA"

key_fingerprint="$(
  timeout 10 ssh-keygen -y -f "$RUNTIME_GIT_SSH_KEY" |
    timeout 10 ssh-keygen -lf - -E sha256 |
    awk 'NR == 1 {print $2}'
)"
[[ "$key_fingerprint" == SHA256:* ]] ||
  fail "Unable to derive the GitHub deploy-key fingerprint"

known_hosts_digest="$(sha256sum "$RUNTIME_GIT_KNOWN_HOSTS" | awk '{print $1}')"
[[ "$known_hosts_digest" =~ ^[0-9a-f]{64}$ ]] ||
  fail "Unable to hash the GitHub known_hosts file"

fingerprint_payload="$(
  printf '%s\n' \
    "schema=2" \
    "repo_dir=${RUNTIME_REPO_DIR}" \
    "compose_file=${RUNTIME_COMPOSE_FILE}" \
    "env_file=${RUNTIME_ENV_FILE}" \
    "caddy_file=${RUNTIME_CADDY_FILE}" \
    "ssh_key=${RUNTIME_GIT_SSH_KEY}" \
    "known_hosts=${RUNTIME_GIT_KNOWN_HOSTS}" \
    "remote=${RUNTIME_GIT_REMOTE}" \
    "branch=${RUNTIME_GIT_BRANCH}" \
    "key_fingerprint=${key_fingerprint}" \
    "known_hosts_digest=${known_hosts_digest}"
)"
runtime_fingerprint="$(printf '%s' "$fingerprint_payload" | sha256sum | awk '{print $1}')"
[[ "$runtime_fingerprint" =~ ^[0-9a-f]{64}$ ]] ||
  fail "Unable to calculate the runtime-path fingerprint"

remote_branch_sha="SKIPPED_OFFLINE"
ssh_read_access_status="SKIPPED_OFFLINE"
if [[ "$NO_NETWORK" == "false" ]]; then
  temporary_directory="$(mktemp -d)"
  trap 'rm -rf "$temporary_directory"' EXIT
  ssh_wrapper="$temporary_directory/git-ssh"
  cat >"$ssh_wrapper" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
unset SSH_AUTH_SOCK
exec ssh \
  -F /dev/null \
  -i "$RUNTIME_GIT_SSH_KEY" \
  -o BatchMode=yes \
  -o IdentitiesOnly=yes \
  -o IdentityAgent=none \
  -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o StrictHostKeyChecking=yes \
  -o UpdateHostKeys=no \
  -o VerifyHostKeyDNS=no \
  -o CheckHostIP=no \
  -o GlobalKnownHostsFile=/dev/null \
  -o "UserKnownHostsFile=$RUNTIME_GIT_KNOWN_HOSTS" \
  -o HostKeyAlgorithms=ssh-ed25519 \
  -o ConnectTimeout=10 \
  -o ServerAliveInterval=5 \
  -o ServerAliveCountMax=1 \
  "$@"
WRAPPER
  chmod 700 "$ssh_wrapper"
  export RUNTIME_GIT_SSH_KEY RUNTIME_GIT_KNOWN_HOSTS

  remote_output="$(
    GIT_CONFIG_NOSYSTEM=1 \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_SSH_COMMAND="$ssh_wrapper" \
      GIT_SSH_VARIANT=ssh \
      git ls-remote --exit-code \
      "$RUNTIME_GIT_REMOTE" \
      "refs/heads/${RUNTIME_GIT_BRANCH}"
  )" || fail "GitHub SSH read-access verification failed"

  remote_branch_sha="$(awk 'NR == 1 {print $1}' <<<"$remote_output")"
  [[ "$remote_branch_sha" == "$EXPECTED_DEPLOY_SHA" ]] ||
    fail "Remote main SHA does not equal the selected GitHub deployment SHA"
  ssh_read_access_status="PASS"
fi

approval_status="PENDING"
if [[ "$REQUIRE_APPROVED" == "true" ]]; then
  [[ "$APPROVED_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] ||
    fail "The approved runtime-path fingerprint is missing or malformed"
  [[ "$runtime_fingerprint" == "$APPROVED_FINGERPRINT" ]] ||
    fail "The runtime paths no longer match the approved fingerprint"
  approval_status="PASS"
fi

release_identity_payload="$(
  printf '%s\n' \
    "schema=1" \
    "expected=${EXPECTED_DEPLOY_SHA}" \
    "runtime=${repository_head}" \
    "remote=${remote_branch_sha}" \
    "paths=${runtime_fingerprint}"
)"
release_identity_sha256="$(printf '%s' "$release_identity_payload" | sha256sum | awk '{print $1}')"

report="$(cat <<REPORT
RUNTIME_PREFLIGHT=PASS
RUNTIME_PATHS_FINGERPRINT=${runtime_fingerprint}
RUNTIME_PATHS_APPROVAL=${approval_status}
EXPECTED_DEPLOY_SHA=${EXPECTED_DEPLOY_SHA}
REPOSITORY_ORIGIN=PASS
REPOSITORY_CLEAN=PASS
REPOSITORY_BRANCH=${repository_branch}
REPOSITORY_HEAD_SHA=${repository_head}
GITHUB_DEPLOY_KEY_READ_ACCESS=PASS
GITHUB_KNOWN_HOSTS_EXCLUSIVE=PASS
GITHUB_SSH_READ_ACCESS=${ssh_read_access_status}
REMOTE_MAIN_SHA=${remote_branch_sha}
RELEASE_IDENTITY_SHA256=${release_identity_sha256}
LIVE_SERVICE_CHANGES=NONE
REPORT
)"

printf '%s\n' "$report"

if [[ -n "$REPORT_FILE" ]]; then
  [[ "$REPORT_FILE" == /* ]] || fail "--report must use an absolute path"
  report_parent="$(dirname -- "$REPORT_FILE")"
  [[ -d "$report_parent" ]] || fail "The report parent directory does not exist"
  printf '%s\n' "$report" >"$REPORT_FILE"
  chmod 600 "$REPORT_FILE"
fi
