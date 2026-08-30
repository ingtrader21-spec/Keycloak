#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

EXPECTED_DEPLOY_SHA="${EXPECTED_DEPLOY_SHA:-}"

fail() {
  printf 'RUNTIME_SYNC_ERROR=%s\n' "$*" >&2
  exit 1
}

[[ "$EXPECTED_DEPLOY_SHA" =~ ^[0-9a-f]{40}$ ]] ||
  fail "EXPECTED_DEPLOY_SHA must be 40 lowercase hexadecimal characters"

for variable_name in RUNTIME_REPO_DIR RUNTIME_GIT_SSH_KEY RUNTIME_GIT_KNOWN_HOSTS; do
  [[ -n "${!variable_name:-}" ]] || fail "Required variable is unset: $variable_name"
  [[ "${!variable_name}" == /* ]] || fail "$variable_name must be an absolute path"
  [[ "${!variable_name}" != *$'\n'* && "${!variable_name}" != *$'\r'* ]] ||
    fail "$variable_name contains a line break"
  [[ "${!variable_name}" != *[[:space:]]* ]] ||
    fail "$variable_name must not contain whitespace"
  [[ ! -L "${!variable_name}" ]] || fail "$variable_name must not be a symlink"
done

RUNTIME_GIT_REMOTE="${RUNTIME_GIT_REMOTE:-git@github.com:appolon1908-hue/Keycloak.git}"
RUNTIME_GIT_BRANCH="${RUNTIME_GIT_BRANCH:-main}"
[[ "$RUNTIME_GIT_REMOTE" == 'git@github.com:appolon1908-hue/Keycloak.git' ]] ||
  fail "Runtime remote is not canonical"
[[ "$RUNTIME_GIT_BRANCH" == 'main' ]] || fail "Runtime branch must be main"

repo_dir="$(realpath -e -- "$RUNTIME_REPO_DIR")"
ssh_key="$(realpath -e -- "$RUNTIME_GIT_SSH_KEY")"
known_hosts="$(realpath -e -- "$RUNTIME_GIT_KNOWN_HOSTS")"
[[ "$repo_dir" == "$RUNTIME_REPO_DIR" && -d "$repo_dir" ]] || fail "Invalid runtime repository"
[[ "$ssh_key" == "$RUNTIME_GIT_SSH_KEY" && -f "$ssh_key" ]] || fail "Invalid deploy key"
[[ "$known_hosts" == "$RUNTIME_GIT_KNOWN_HOSTS" && -f "$known_hosts" ]] || fail "Invalid known_hosts file"

runner_uid="$(id -u)"
for private_file in "$ssh_key" "$known_hosts"; do
  [[ "$(stat -c '%u' -- "$private_file")" == "$runner_uid" ]] ||
    fail "SSH material must be owned by the runner"
  mode="$(stat -c '%a' -- "$private_file")"
  (( (8#$mode & 8#077) == 0 )) || fail "SSH material must be private"
done

grep -Eq '^github\.com[[:space:]]+ssh-ed25519[[:space:]]+' "$known_hosts" ||
  fail "known_hosts lacks an explicit GitHub Ed25519 key"
if grep -Ev '^[[:space:]]*(#|$|github\.com[[:space:]]+ssh-ed25519[[:space:]])' "$known_hosts" | grep -q .; then
  fail "known_hosts contains a non-approved host or key type"
fi

safe_git() {
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    git -c core.hooksPath=/dev/null -c core.fsmonitor=false -C "$repo_dir" "$@"
}

[[ "$(safe_git rev-parse --is-inside-work-tree)" == true ]] || fail "Runtime path is not a Git checkout"
[[ "$(safe_git remote get-url origin)" == "$RUNTIME_GIT_REMOTE" ]] || fail "Runtime origin mismatch"
[[ "$(safe_git symbolic-ref --quiet --short HEAD)" == "$RUNTIME_GIT_BRANCH" ]] || fail "Runtime branch mismatch"
[[ -z "$(safe_git status --porcelain=v1 --untracked-files=normal)" ]] || fail "Runtime checkout is not clean"

ssh_command="ssh -i ${ssh_key} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${known_hosts}"
GIT_SSH_COMMAND="$ssh_command" safe_git fetch --no-tags origin "refs/heads/${RUNTIME_GIT_BRANCH}"
fetched_sha="$(safe_git rev-parse FETCH_HEAD)"
[[ "$fetched_sha" == "$EXPECTED_DEPLOY_SHA" ]] || fail "Remote main does not equal the selected deployment SHA"
safe_git merge-base --is-ancestor HEAD "$fetched_sha" || fail "Runtime checkout cannot fast-forward to selected main"
safe_git merge --ff-only --no-edit "$fetched_sha" >/dev/null
[[ "$(safe_git rev-parse HEAD)" == "$EXPECTED_DEPLOY_SHA" ]] || fail "Fast-forward did not reach selected main"
[[ -z "$(safe_git status --porcelain=v1 --untracked-files=normal)" ]] || fail "Runtime checkout became dirty"

printf 'RUNTIME_REPOSITORY_SHA=%s\n' "$EXPECTED_DEPLOY_SHA"
printf 'RUNTIME_REPOSITORY_SYNC=FAST_FORWARD_ONLY\n'
