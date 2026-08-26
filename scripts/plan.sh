#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/keycloak-admin.sh
source "$ROOT_DIR/scripts/lib/keycloak-admin.sh"

OUTPUT_DIR=""
EXPECTED_DEPLOY_SHA="${EXPECTED_DEPLOY_SHA:-}"
DEPLOY_ENVIRONMENT="${DEPLOY_ENVIRONMENT:-}"

usage() {
  cat <<'USAGE'
Usage: scripts/plan.sh --output-dir PATH --expected-deploy-sha SHA

Generates a deterministic, reviewable Keycloak client plan. The plan contains
only fields declared by the Git-managed client overlays and performs no writes.

Required environment:
  KC_BASE_URL
  KC_PUBLIC_URL
  KC_TARGET_REALM
  KC_ADMIN_REALM
  KC_ADMIN_CLIENT_ID
  KC_ADMIN_CLIENT_SECRET
  DEPLOY_ENVIRONMENT=staging|production
USAGE
}

while (($#)); do
  case "$1" in
    --output-dir)
      [[ $# -ge 2 ]] || die "--output-dir requires a path"
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --expected-deploy-sha)
      [[ $# -ge 2 ]] || die "--expected-deploy-sha requires a commit SHA"
      EXPECTED_DEPLOY_SHA="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "Unknown option: $1"
      ;;
  esac
done

[[ -n "$OUTPUT_DIR" ]] || die "--output-dir is required"
[[ "$OUTPUT_DIR" == /* ]] || die "--output-dir must be an absolute path"
[[ ! -L "$OUTPUT_DIR" ]] || die "--output-dir must not be a symlink"
[[ "$EXPECTED_DEPLOY_SHA" =~ ^[0-9a-f]{40}$ ]] ||
  die "Expected deployment SHA must be 40 lowercase hexadecimal characters"
case "$DEPLOY_ENVIRONMENT" in
  staging | production)
    ;;
  *)
    die "DEPLOY_ENVIRONMENT must be staging or production"
    ;;
esac

"$ROOT_DIR/scripts/validate.sh"
keycloak_authenticate

mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"; unset KC_ACCESS_TOKEN' EXIT
resources_ndjson="$tmp_dir/resources.ndjson"
: >"$resources_ndjson"

canonical_hash() {
  local json_file="$1"
  jq -S -c . "$json_file" | sha256sum | awk '{print $1}'
}

project_live_to_desired_shape() {
  local live_file="$1"
  local desired_file="$2"
  local destination="$3"

  jq -S -n \
    --slurpfile live "$live_file" \
    --slurpfile desired "$desired_file" '
      def project($current; $wanted):
        if ($wanted | type) == "object" then
          reduce ($wanted | keys_unsorted[]) as $key
            ({}; .[$key] = project($current[$key]; $wanted[$key]))
        elif ($wanted | type) == "array" then
          ($current // [])
        else
          $current
        end;
      project($live[0]; $desired[0])
    ' >"$destination"
}

managed_policy="$ROOT_DIR/config/policy/managed-clients.json"
mapfile -t managed_clients < <(jq -er '.clients[]' "$managed_policy")
((${#managed_clients[@]} > 0)) || die "No managed clients are declared"

for client_id in "${managed_clients[@]}"; do
  mapfile -t matching_files < <(
    while IFS= read -r file; do
      [[ "$(jq -er '.clientId' "$file")" == "$client_id" ]] && printf '%s\n' "$file"
    done < <(find "$ROOT_DIR/config/clients" -maxdepth 1 -type f -name '*.json' -print | sort)
  )
  ((${#matching_files[@]} == 1)) ||
    die "Expected exactly one desired-state file for clientId=${client_id}"

  desired_file="${matching_files[0]}"
  encoded_client_id="$(urlencode "$client_id")"
  safe_client_id="$(printf '%s' "$client_id" | LC_ALL=C tr -c '[:alnum:]_.-' '_')"
  client_list_file="$tmp_dir/client-list-${safe_client_id}.json"

  keycloak_api GET \
    "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients?clientId=${encoded_client_id}&exact=true" \
    >"$client_list_file"

  matches="$(jq -er 'length' "$client_list_file")"
  [[ "$matches" -le 1 ]] || die "Multiple Keycloak clients matched clientId=${client_id}"

  before_file="$tmp_dir/before-${safe_client_id}.json"
  action="noop"
  if [[ "$matches" -eq 0 ]]; then
    printf '{}\n' >"$before_file"
    action="blocked_missing"
  else
    client_uuid="$(jq -er '.[0].id' "$client_list_file")"
    live_file="$tmp_dir/live-${safe_client_id}.json"
    keycloak_api GET \
      "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" \
      >"$live_file"
    project_live_to_desired_shape "$live_file" "$desired_file" "$before_file"
    if ! jq -e -n \
      --slurpfile before "$before_file" \
      --slurpfile desired "$desired_file" \
      '$before[0] == $desired[0]' >/dev/null; then
      action="update"
    fi
  fi

  before_sha256="$(canonical_hash "$before_file")"
  desired_sha256="$(canonical_hash "$desired_file")"

  jq -c -n \
    --arg resource_type client \
    --arg client_id "$client_id" \
    --arg action "$action" \
    --arg before_sha256 "$before_sha256" \
    --arg desired_sha256 "$desired_sha256" \
    --slurpfile before "$before_file" \
    --slurpfile desired "$desired_file" '
      {
        resourceType: $resource_type,
        clientId: $client_id,
        action: $action,
        beforeSha256: $before_sha256,
        desiredSha256: $desired_sha256,
        before: $before[0],
        desired: $desired[0]
      }
    ' >>"$resources_ndjson"
done

endpoint_file="$ROOT_DIR/config/endpoints/codestra.json"

plan_file="$OUTPUT_DIR/plan.json"
canonical_plan_file="$OUTPUT_DIR/plan.canonical.json"
plan_hash_file="$OUTPUT_DIR/plan.sha256"

jq -S -s \
  --arg repository_sha "$EXPECTED_DEPLOY_SHA" \
  --arg environment "$DEPLOY_ENVIRONMENT" \
  --arg target_realm "$KC_TARGET_REALM" \
  --slurpfile api "$endpoint_file" '
    sort_by(.clientId) as $clients
    | {
        schemaVersion: 1,
        repositorySha: $repository_sha,
        environment: $environment,
        targetRealm: $target_realm,
        api: $api[0],
        clients: $clients,
        driftCount: ($clients | map(select(.action != "noop")) | length),
        blockedCount: ($clients | map(select(.action == "blocked_missing")) | length)
      }
  ' "$resources_ndjson" >"$plan_file"

jq -S -c . "$plan_file" >"$canonical_plan_file"
plan_sha256="$(sha256sum "$canonical_plan_file" | awk '{print $1}')"
printf '%s  plan.canonical.json\n' "$plan_sha256" >"$plan_hash_file"
chmod 600 "$plan_file" "$canonical_plan_file" "$plan_hash_file"

drift_count="$(jq -er '.driftCount' "$plan_file")"
blocked_count="$(jq -er '.blockedCount' "$plan_file")"

printf 'PLAN_FILE=%s\n' "$plan_file"
printf 'PLAN_CANONICAL_FILE=%s\n' "$canonical_plan_file"
printf 'PLAN_SHA256=%s\n' "$plan_sha256"
printf 'DRIFT_COUNT=%s\n' "$drift_count"
printf 'BLOCKED_COUNT=%s\n' "$blocked_count"
printf 'PLAN=READY_FOR_REVIEW\n'
