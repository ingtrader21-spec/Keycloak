#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/keycloak-admin.sh
source "$ROOT_DIR/scripts/lib/keycloak-admin.sh"

PLAN_FILE=""
EXPECTED_PLAN_SHA256=""
REVIEW_FILE=""
EXPECTED_REVIEW_SHA256=""
EXPECTED_DEPLOY_SHA="${EXPECTED_DEPLOY_SHA:-}"
DEPLOY_ENVIRONMENT="${DEPLOY_ENVIRONMENT:-}"

usage() {
  cat <<'USAGE'
Usage: scripts/apply-plan.sh \
  --plan PATH \
  --expected-plan-sha SHA256 \
  --review PATH \
  --expected-review-sha SHA256 \
  --expected-deploy-sha SHA

Applies only a previously generated and human-reviewed plan. Before the first
write, the script verifies the plan hash, repository SHA, environment, managed
client set, desired-state hashes, every existing client's pre-change hash, and
re-checks that every reviewed create target is still absent. A changed live
state invalidates the entire plan.
USAGE
}

while (($#)); do
  case "$1" in
    --plan)
      [[ $# -ge 2 ]] || die "--plan requires a path"
      PLAN_FILE="$2"
      shift 2
      ;;
    --expected-plan-sha)
      [[ $# -ge 2 ]] || die "--expected-plan-sha requires a SHA-256 value"
      EXPECTED_PLAN_SHA256="$2"
      shift 2
      ;;
    --review)
      [[ $# -ge 2 ]] || die "--review requires a path"
      REVIEW_FILE="$2"
      shift 2
      ;;
    --expected-review-sha)
      [[ $# -ge 2 ]] || die "--expected-review-sha requires a SHA-256 value"
      EXPECTED_REVIEW_SHA256="$2"
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

[[ -n "$PLAN_FILE" ]] || die "--plan is required"
[[ "$PLAN_FILE" == /* ]] || die "--plan must use an absolute path"
[[ -f "$PLAN_FILE" && ! -L "$PLAN_FILE" ]] || die "Plan must be a regular non-symlink file"
[[ "$EXPECTED_PLAN_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
  die "Expected plan hash must be 64 lowercase hexadecimal characters"
[[ "$REVIEW_FILE" == /* && -f "$REVIEW_FILE" && ! -L "$REVIEW_FILE" ]] ||
  die "Review must be an absolute regular non-symlink file"
[[ "$EXPECTED_REVIEW_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
  die "Expected review hash must be 64 lowercase hexadecimal characters"
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
jq -e . "$PLAN_FILE" >/dev/null || die "Plan is not valid JSON"

canonical_plan_sha256="$(jq -S -c . "$PLAN_FILE" | sha256sum | awk '{print $1}')"
[[ "$canonical_plan_sha256" == "$EXPECTED_PLAN_SHA256" ]] ||
  die "Reviewed plan hash does not match the supplied plan"
canonical_review_sha256="$(jq -S -c . "$REVIEW_FILE" | sha256sum | awk '{print $1}')"
[[ "$canonical_review_sha256" == "$EXPECTED_REVIEW_SHA256" ]] ||
  die "Drift-review hash does not match the supplied review"
jq -e \
  --arg plan_sha "$EXPECTED_PLAN_SHA256" \
  --arg repository_sha "$EXPECTED_DEPLOY_SHA" \
  --arg environment "$DEPLOY_ENVIRONMENT" \
  --slurpfile plan "$PLAN_FILE" '
    .schemaVersion == 1
    and .decision == "approved"
    and .planSha256 == $plan_sha
    and .repositorySha == $repository_sha
    and .environment == $environment
    and .targetRealm == "codestra"
    and .reviewerId != .changeAuthorId
    and (.reviewerId | type == "string" and length >= 3)
    and (.changeTicket | type == "string" and length >= 3)
    and .reviewedActions == [
      $plan[0].clients[] | {clientId, action, beforeSha256, desiredSha256}
    ]
    and .reviewedRealmPolicy == ($plan[0].realmPolicy | {
      resourceType, realm, action, beforeSha256, desiredSha256
    })
  ' "$REVIEW_FILE" >/dev/null || die "Independent drift-review evidence is invalid"

jq -e \
  --arg repository_sha "$EXPECTED_DEPLOY_SHA" \
  --arg environment "$DEPLOY_ENVIRONMENT" \
  --arg target_realm "${KC_TARGET_REALM:-codestra}" '
    .schemaVersion == 1
    and .repositorySha == $repository_sha
    and .environment == $environment
    and .targetRealm == $target_realm
    and (.clients | type == "array")
    and (.realmPolicy.resourceType == "realm")
    and (.realmPolicy.realm == $target_realm)
    and (.realmPolicy.action == "noop" or .realmPolicy.action == "update")
    and (.blockedCount == 0)
    and (.createCount == ([.clients[] | select(.action == "create")] | length))
    and (.updateCount == (
      ([.clients[] | select(.action == "update")] | length)
      + (if .realmPolicy.action == "update" then 1 else 0 end)
    ))
    and (.driftCount == (
      ([.clients[] | select(.action != "noop")] | length)
      + (if .realmPolicy.action == "update" then 1 else 0 end)
    ))
  ' "$PLAN_FILE" >/dev/null ||
  die "Plan metadata, counters, target environment, or blocked-resource policy is invalid"

endpoint_file="$ROOT_DIR/config/endpoints/codestra.json"
jq -e \
  --slurpfile expected_api "$endpoint_file" \
  '.api == $expected_api[0]' \
  "$PLAN_FILE" >/dev/null || die "Plan API URLs do not match the canonical Codestra endpoints"

mapfile -t policy_clients < <(jq -r '.clients[]' "$ROOT_DIR/config/policy/managed-clients.json" | sort)
mapfile -t creatable_clients < <(jq -r '.clients[]' "$ROOT_DIR/config/policy/creatable-clients.json" | sort)
mapfile -t plan_clients < <(jq -r '.clients[].clientId' "$PLAN_FILE" | sort)
[[ "${policy_clients[*]}" == "${plan_clients[*]}" ]] ||
  die "Plan client set does not match the reviewed managed-client policy"

declare -A creatable_client_set=()
for client_id in "${creatable_clients[@]}"; do
  creatable_client_set["$client_id"]=1
done

keycloak_authenticate

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"; unset KC_ACCESS_TOKEN' EXIT
apply_manifest="$tmp_dir/apply-manifest.ndjson"
: >"$apply_manifest"

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
          if all($wanted[]?; (type == "object" and has("name"))) then
            [
              $wanted[] as $wanted_item
              | (($current // []) | map(select(.name == $wanted_item.name)) | .[0] // {}) as $current_item
              | project($current_item; $wanted_item)
            ]
          else
            ($current // [])
          end
        else
          $current
        end;
      project($live[0]; $desired[0])
    ' >"$destination"
}

find_desired_file() {
  local client_id="$1"
  local -a matches=()
  local file
  while IFS= read -r file; do
    [[ "$(jq -er '.clientId' "$file")" == "$client_id" ]] && matches+=("$file")
  done < <(find "$ROOT_DIR/config/clients" -maxdepth 1 -type f -name '*.json' -print | sort)
  ((${#matches[@]} == 1)) || die "Expected exactly one desired-state file for clientId=${client_id}"
  printf '%s\n' "${matches[0]}"
}

empty_state_file="$tmp_dir/empty.json"
printf '{}\n' >"$empty_state_file"
empty_state_sha256="$(canonical_hash "$empty_state_file")"

# Validate the reviewed realm policy before any mutation.
realm_desired_file="$ROOT_DIR/config/realms/codestra.json"
realm_expected_before_sha256="$(jq -er '.realmPolicy.beforeSha256' "$PLAN_FILE")"
realm_expected_desired_sha256="$(jq -er '.realmPolicy.desiredSha256' "$PLAN_FILE")"
realm_action="$(jq -er '.realmPolicy.action' "$PLAN_FILE")"
[[ "$(canonical_hash "$realm_desired_file")" == "$realm_expected_desired_sha256" ]] ||
  die "Realm desired state changed after plan review"
jq -e '
  .realmPolicy.rollback.kind == "restore_managed_realm_overlay"
  and .realmPolicy.rollback.requiresReviewedPlan == true
' "$PLAN_FILE" >/dev/null || die "Realm rollback metadata is invalid"
realm_live_file="$tmp_dir/realm-live.json"
realm_before_file="$tmp_dir/realm-before.json"
keycloak_api GET "/admin/realms/$(urlencode "$KC_TARGET_REALM")" >"$realm_live_file"
project_live_to_desired_shape "$realm_live_file" "$realm_desired_file" "$realm_before_file"
[[ "$(canonical_hash "$realm_before_file")" == "$realm_expected_before_sha256" ]] ||
  die "Live realm state changed after plan review"
if [[ "$realm_action" == "noop" ]]; then
  jq -e -n --slurpfile before "$realm_before_file" --slurpfile desired "$realm_desired_file" \
    '$before[0] == $desired[0]' >/dev/null || die "Plan marked realm as noop but drift exists"
else
  jq -e -n --slurpfile before "$realm_before_file" --slurpfile desired "$realm_desired_file" \
    '$before[0] != $desired[0]' >/dev/null || die "Plan marked realm for update but it is synchronized"
fi

# Phase 1: validate every resource against the reviewed plan before any write.
resource_index=0
while IFS= read -r resource; do
  client_id="$(jq -er '.clientId' <<<"$resource")"
  action="$(jq -er '.action' <<<"$resource")"
  expected_before_sha256="$(jq -er '.beforeSha256' <<<"$resource")"
  expected_desired_sha256="$(jq -er '.desiredSha256' <<<"$resource")"

  case "$action" in
    noop | update | create)
      ;;
    blocked_missing)
      die "Reviewed plan contains a blocked missing client: $client_id"
      ;;
    *)
      die "Unsupported plan action for client ${client_id}: ${action}"
      ;;
  esac

  desired_file="$(find_desired_file "$client_id")"
  [[ "$(canonical_hash "$desired_file")" == "$expected_desired_sha256" ]] ||
    die "Desired state changed after plan review for client ${client_id}"

  encoded_client_id="$(urlencode "$client_id")"
  safe_client_id="$(printf '%s' "$client_id" | LC_ALL=C tr -c '[:alnum:]_.-' '_')"
  client_list_file="$tmp_dir/client-list-${safe_client_id}.json"
  keycloak_api GET \
    "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients?clientId=${encoded_client_id}&exact=true" \
    >"$client_list_file"
  client_match_count="$(jq -er 'length' "$client_list_file")"

  if [[ "$action" == "create" ]]; then
    [[ -n "${creatable_client_set[$client_id]:-}" ]] ||
      die "Reviewed create is not allowlisted for client ${client_id}"
    [[ "$client_match_count" -eq 0 ]] ||
      die "Reviewed plan recorded absence but client now exists: ${client_id}"
    [[ "$expected_before_sha256" == "$empty_state_sha256" ]] ||
      die "Reviewed create does not contain the canonical absent-state hash: ${client_id}"
    jq -e '
      .before == {}
      and .rollback.kind == "disable_then_reviewed_delete"
      and .rollback.preApplyState == "absent"
      and .rollback.disableFirst == true
      and .rollback.deleteRequiresSeparateReviewedRollback == true
      and .rollback.requiresReviewedPlan == true
    ' <<<"$resource" >/dev/null ||
      die "Reviewed create rollback metadata is invalid for client ${client_id}"

    jq -c -n \
      --arg client_id "$client_id" \
      --arg action "$action" \
      --arg desired_file "$desired_file" '
        {
          clientId: $client_id,
          action: $action,
          desiredFile: $desired_file
        }
      ' >>"$apply_manifest"
    resource_index=$((resource_index + 1))
    continue
  fi

  [[ "$client_match_count" -eq 1 ]] ||
    die "Expected exactly one live client for clientId=${client_id}"

  client_uuid="$(jq -er '.[0].id' "$client_list_file")"
  live_file="$tmp_dir/live-${safe_client_id}.json"
  before_file="$tmp_dir/before-${safe_client_id}.json"
  merged_file="$tmp_dir/merged-${safe_client_id}.json"

  keycloak_api GET \
    "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" \
    >"$live_file"
  project_live_to_desired_shape "$live_file" "$desired_file" "$before_file"
  [[ "$(canonical_hash "$before_file")" == "$expected_before_sha256" ]] ||
    die "Live Keycloak state changed after plan review for client ${client_id}"

  jq -e '
    .rollback.kind == "restore_allowlisted_overlay"
    and .rollback.preApplyState == "existing"
    and .rollback.requiresReviewedPlan == true
  ' <<<"$resource" >/dev/null ||
    die "Existing-client rollback metadata is invalid for client ${client_id}"

  if [[ "$action" == "noop" ]]; then
    jq -e -n \
      --slurpfile before "$before_file" \
      --slurpfile desired "$desired_file" \
      '$before[0] == $desired[0]' >/dev/null ||
      die "Plan marked client ${client_id} as noop but drift exists"
  else
    jq -e -n \
      --slurpfile before "$before_file" \
      --slurpfile desired "$desired_file" \
      '$before[0] != $desired[0]' >/dev/null ||
      die "Plan marked client ${client_id} for update but it is already synchronized"
  fi

  jq -S -s '
    .[0] * .[1]
    | del(.secret, .registrationAccessToken, .access)
  ' "$live_file" "$desired_file" >"$merged_file"
  chmod 600 "$merged_file"

  jq -c -n \
    --arg client_id "$client_id" \
    --arg action "$action" \
    --arg client_uuid "$client_uuid" \
    --arg merged_file "$merged_file" '
      {
        clientId: $client_id,
        action: $action,
        clientUuid: $client_uuid,
        mergedFile: $merged_file
      }
    ' >>"$apply_manifest"
  resource_index=$((resource_index + 1))
done < <(jq -c '.clients[]' "$PLAN_FILE")

[[ "$resource_index" -eq "${#policy_clients[@]}" ]] ||
  die "Plan resource count does not match the managed-client policy"

# Phase 2: immediately before the first mutation, re-check every reviewed create
# target is still absent. Any race or operator-created client invalidates the
# whole plan before update/create writes begin.
while IFS= read -r operation; do
  [[ "$(jq -er '.action' <<<"$operation")" == "create" ]] || continue
  client_id="$(jq -er '.clientId' <<<"$operation")"
  live_matches="$(
    keycloak_api GET \
      "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients?clientId=$(urlencode "$client_id")&exact=true" |
      jq -er 'length'
  )"
  [[ "$live_matches" -eq 0 ]] ||
    die "Pre-write absence recheck failed for reviewed create: ${client_id}"
done <"$apply_manifest"

changed_count=0
created_count=0
updated_count=0
while IFS= read -r operation; do
  action="$(jq -er '.action' <<<"$operation")"
  client_id="$(jq -er '.clientId' <<<"$operation")"
  case "$action" in
    create)
      desired_file="$(jq -er '.desiredFile' <<<"$operation")"
      keycloak_api POST \
        "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients" \
        "$desired_file" >/dev/null
      created_count=$((created_count + 1))
      changed_count=$((changed_count + 1))
      [[ "$(keycloak_api GET "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients?clientId=$(urlencode "$client_id")&exact=true" | jq -er 'length')" -eq 1 ]] ||
        die "Created client could not be read back uniquely: ${client_id}"
      printf 'CREATED=client:%s\n' "$client_id"
      ;;
    update)
      client_uuid="$(jq -er '.clientUuid' <<<"$operation")"
      merged_file="$(jq -er '.mergedFile' <<<"$operation")"
      keycloak_api PUT \
        "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" \
        "$merged_file" >/dev/null
      updated_count=$((updated_count + 1))
      changed_count=$((changed_count + 1))
      printf 'UPDATED=client:%s\n' "$client_id"
      ;;
    noop)
      printf 'UNCHANGED=client:%s\n' "$client_id"
      ;;
    *)
      die "Unexpected apply-manifest action for client ${client_id}: ${action}"
      ;;
  esac
done <"$apply_manifest"

# Re-read and revalidate the realm immediately before its own PUT. The outgoing
# representation is built from this immediate live state so unmanaged realm
# fields are retained.
if [[ "$realm_action" == "update" ]]; then
  require_env KC_SMTP_USERNAME
  require_env KC_SMTP_PASSWORD
  realm_immediate_live_file="$tmp_dir/realm-immediate-live.json"
  realm_immediate_before_file="$tmp_dir/realm-immediate-before.json"
  realm_merged_file="$tmp_dir/realm-immediate-merged.json"
  keycloak_api GET "/admin/realms/$(urlencode "$KC_TARGET_REALM")" >"$realm_immediate_live_file"
  project_live_to_desired_shape \
    "$realm_immediate_live_file" "$realm_desired_file" "$realm_immediate_before_file"
  [[ "$(canonical_hash "$realm_immediate_before_file")" == "$realm_expected_before_sha256" ]] ||
    die "Immediate pre-write realm state changed"
  jq -S -s \
    --arg smtp_username "$KC_SMTP_USERNAME" \
    --arg smtp_password "$KC_SMTP_PASSWORD" '
      .[0] * .[1]
      | .smtpServer.user = $smtp_username
      | .smtpServer.password = $smtp_password
    ' "$realm_immediate_live_file" "$realm_desired_file" >"$realm_merged_file"
  chmod 600 "$realm_merged_file"
  keycloak_api PUT "/admin/realms/$(urlencode "$KC_TARGET_REALM")" "$realm_merged_file" >/dev/null
  updated_count=$((updated_count + 1))
  changed_count=$((changed_count + 1))
  printf 'UPDATED=realm:%s\n' "$KC_TARGET_REALM"
else
  printf 'UNCHANGED=realm:%s\n' "$KC_TARGET_REALM"
fi

convergence_dir="$tmp_dir/convergence"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$convergence_dir" \
  --expected-deploy-sha "$EXPECTED_DEPLOY_SHA" >/dev/null

[[ "$(jq -er '.driftCount' "$convergence_dir/plan.json")" -eq 0 ]] ||
  die "Applied configuration did not converge"
[[ "$(jq -er '.blockedCount' "$convergence_dir/plan.json")" -eq 0 ]] ||
  die "Convergence check found blocked resources"
[[ "$(jq -er '.createCount' "$convergence_dir/plan.json")" -eq 0 ]] ||
  die "Convergence check still contains create actions"
[[ "$(jq -er '.updateCount' "$convergence_dir/plan.json")" -eq 0 ]] ||
  die "Convergence check still contains update actions"

printf 'EXPECTED_PLAN_SHA256=%s\n' "$EXPECTED_PLAN_SHA256"
printf 'EXPECTED_REVIEW_SHA256=%s\n' "$EXPECTED_REVIEW_SHA256"
printf 'CREATED_COUNT=%s\n' "$created_count"
printf 'UPDATED_COUNT=%s\n' "$updated_count"
printf 'CHANGED_COUNT=%s\n' "$changed_count"
printf 'DRIFT_COUNT=0\n'
printf 'BLOCKED_COUNT=0\n'
printf 'RECONCILE=APPLIED_AND_VERIFIED\n'
