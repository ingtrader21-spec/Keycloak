#!/usr/bin/env bash

# Source this file inside each workflow step that needs private GHCR access.
# The EXIT trap is scoped to that step, so credentials are removed on both
# success and failure before the runner can accept another job.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf 'ERROR=ephemeral_docker_auth_must_be_sourced\n' >&2
  exit 2
fi

: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GHCR_USERNAME:?GHCR_USERNAME is required}"
: "${GHCR_TOKEN:?GHCR_TOKEN is required}"

credential_dir="$(mktemp -d "$RUNNER_TEMP/docker-config.XXXXXX")"
chmod 700 "$credential_dir"
export DOCKER_CONFIG="$credential_dir"

cleanup() {
  docker logout ghcr.io >/dev/null 2>&1 || true
  rm -rf "$credential_dir"
}
trap cleanup EXIT

printf '%s' "$GHCR_TOKEN" |
  docker login ghcr.io \
    --username "$GHCR_USERNAME" \
    --password-stdin >/dev/null
