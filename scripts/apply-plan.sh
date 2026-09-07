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
RECOVERY_DIR=""
WORKFLOW_RUN_ID="${GITHUB_RUN_ID:-local}"

usage() {
  cat <<'USAGE'
Usage: scripts/apply-plan.sh \
  --plan PATH \
  --expected-plan-sha SHA256 \
  --review PATH \
  --expected-review-sha SHA256 \
  --expected-deploy-sha SHA \
  --recovery-dir PATH

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
    --recovery-dir)
      [[ $# -ge 2 ]] || die "--recovery-dir requires a path"
      RECOVERY_DIR="$2"
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
[[ -n "$RECOVERY_DIR" ]] || die "--recovery-dir is required"
[[ "$PLAN_FILE" == /* ]] || die "--plan must use an absolute path"
[[ -f "$PLAN_FILE" && ! -L "$PLAN_FILE" ]] || die "Plan must be a regular non-symlink file"
[[ "$RECOVERY_DIR" == /* && ! -L "$RECOVERY_DIR" ]] ||
  die "Recovery directory must be an absolute non-symlink path"
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

if [[ "$DEPLOY_ENVIRONMENT" == production ]]; then
  jq -e '.productionMutationAllowed == true' \
    "$ROOT_DIR/config/certification/service-identity-matrix.json" >/dev/null ||
    die "production_mutation_not_authorized_by_certification_contract"
fi

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
      resourceType, realm, action, beforeSha256, desiredSha256, smtpCredentialVersion
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

endpoint_file="$(keycloak_endpoint_file)"
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

declare -A machine_secret_environment=()
machine_secret_contract="$ROOT_DIR/config/contracts/machine-secret-destinations.json"
while IFS=$'\t' read -r client_id secret_environment; do
  machine_secret_environment["$client_id"]="$secret_environment"
done < <(jq -er '.clients[] | [.clientId, .applyEnvironment] | @tsv' "$machine_secret_contract")

# Fail before authentication or the first write if any planned machine-client
# creation lacks its externally supplied credential.
while IFS= read -r planned_create; do
  client_id="$(jq -er '.clientId' <<<"$planned_create")"
  secret_environment="${machine_secret_environment[$client_id]:-}"
  if [[ -n "$secret_environment" ]]; then
    require_env "$secret_environment"
  fi
done < <(jq -c '.clients[] | select(.action == "create")' "$PLAN_FILE")

keycloak_authenticate

tmp_dir="$(mktemp -d)"
mkdir -p "$RECOVERY_DIR"
chmod 700 "$RECOVERY_DIR"
recovery_manifest="$RECOVERY_DIR/recovery-manifest.json"
recovery_events="$RECOVERY_DIR/operation-events.ndjson"
: >"$recovery_events"
chmod 600 "$recovery_events"

mutated_count=0
active_sequence=""
mutation_started=false
apply_finished=false

record_operation_state() {
  local sequence="$1"
  local state="$2"
  local detail="${3:-}"
  local event_tmp manifest_tmp
  event_tmp="$(mktemp "$RECOVERY_DIR/.event.XXXXXX")"
  manifest_tmp="$(mktemp "$RECOVERY_DIR/.manifest.XXXXXX")"
  jq -c -n \
    --argjson sequence "$sequence" \
    --arg state "$state" \
    --arg detail "$detail" \
    --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    '{sequence: $sequence, state: $state, timestamp: $timestamp}
     + (if $detail == "" then {} else {detail: $detail} end)' >"$event_tmp"
  cat "$event_tmp" >>"$recovery_events"
  jq \
    --argjson sequence "$sequence" \
    --arg state "$state" \
    --arg detail "$detail" \
    --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" '
      .operations |= map(
        if .sequence == $sequence then
          .state = $state
          | .updatedAt = $timestamp
          | if $detail == "" then del(.detail) else .detail = $detail end
        else . end
      )
    ' "$recovery_manifest" >"$manifest_tmp"
  chmod 600 "$manifest_tmp"
  mv -f "$manifest_tmp" "$recovery_manifest"
  rm -f "$event_tmp"
}

handle_apply_exit() {
  local exit_code=$?
  trap - EXIT
  if [[ "$apply_finished" != "true" && -f "$recovery_manifest" ]]; then
    if [[ -n "$active_sequence" ]]; then
      if [[ "$mutation_started" == "true" ]]; then
        # A transport/readback failure cannot prove that Keycloak did not commit
        # the request. Preserve it as a rollback candidate and fail closed.
        record_operation_state "$active_sequence" rollback-required \
          "mutation outcome uncertain; verify live state before reviewed rollback (exit ${exit_code})" || true
      else
        record_operation_state "$active_sequence" failed \
          "apply command exited before mutation with status ${exit_code}" || true
      fi
    fi
    if ((mutated_count > 0)) || [[ "$mutation_started" == "true" ]]; then
      local manifest_tmp
      manifest_tmp="$(mktemp "$RECOVERY_DIR/.manifest.XXXXXX")"
      jq '
        .partialApply = true
        | .operations |= map(
            if (.state == "created" or .state == "updated") then
              .lastSuccessfulState = .state
              | .state = "rollback-required"
            else . end
          )
      ' "$recovery_manifest" >"$manifest_tmp" && mv -f "$manifest_tmp" "$recovery_manifest"
      printf 'PARTIAL_APPLY=true\n' >&2
      printf 'RECOVERY_MANIFEST=%s\n' "$recovery_manifest" >&2
    fi
  fi
  rm -rf "$tmp_dir"
  unset KC_ACCESS_TOKEN
  exit "$exit_code"
}
trap handle_apply_exit EXIT
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
            ({}; .[$key] = (
              if $key == "authorizationServicesEnabled"
                 and $wanted[$key] == false
                 and $current[$key] == null
              then false
              else project($current[$key]; $wanted[$key])
              end
            ))
        elif ($wanted | type) == "array" then
          if all($wanted[]?; (type == "object" and has("name"))) then
            [
              $wanted[] as $wanted_item
              | (($current // []) | map(select(.name == $wanted_item.name)) | .[0] // {}) as $current_item
              | project($current_item; $wanted_item)
            ]
          elif all($wanted[]?; (type == "object" and has("alias"))) then
            [
              $wanted[] as $wanted_item
              | (($current // []) | map(select(.alias == $wanted_item.alias)) | .[0] // {}) as $current_item
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
require_env KC_SMTP_CREDENTIAL_VERSION
[[ "$KC_SMTP_CREDENTIAL_VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] ||
  die "KC_SMTP_CREDENTIAL_VERSION must be a 1-64 character non-secret identifier"
[[ "$(jq -er '.realmPolicy.smtpCredentialVersion' "$PLAN_FILE")" == "$KC_SMTP_CREDENTIAL_VERSION" ]] ||
  die "SMTP credential version differs from the reviewed plan"
realm_desired_file="$tmp_dir/realm-desired.json"
jq -S --arg version "$KC_SMTP_CREDENTIAL_VERSION" \
  '.attributes["codestra.smtpCredentialVersion"] = $version' \
  "$ROOT_DIR/config/realms/codestra.json" >"$realm_desired_file"
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
      --arg desired_file "$desired_file" \
      --arg expected_before_sha256 "$expected_before_sha256" '
        {
          clientId: $client_id,
          action: $action,
          desiredFile: $desired_file,
          expectedBeforeSha256: $expected_before_sha256
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

  jq -c -n \
    --arg client_id "$client_id" \
    --arg action "$action" \
    --arg client_uuid "$client_uuid" \
    --arg desired_file "$desired_file" \
    --arg expected_before_sha256 "$expected_before_sha256" '
      {
        clientId: $client_id,
        action: $action,
        clientUuid: $client_uuid,
        desiredFile: $desired_file,
        expectedBeforeSha256: $expected_before_sha256
      }
    ' >>"$apply_manifest"
  resource_index=$((resource_index + 1))
done < <(jq -c '.clients[]' "$PLAN_FILE")

[[ "$resource_index" -eq "${#policy_clients[@]}" ]] ||
  die "Plan resource count does not match the managed-client policy"

# This manifest is written before the first mutation and updated atomically
# after every state transition. It intentionally contains hashes and artifact
# references, never client secrets or access tokens.
jq -S -s \
  --arg repository_sha "$EXPECTED_DEPLOY_SHA" \
  --arg environment "$DEPLOY_ENVIRONMENT" \
  --arg plan_sha256 "$EXPECTED_PLAN_SHA256" \
  --arg workflow_run_id "$WORKFLOW_RUN_ID" \
  --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --arg realm "$KC_TARGET_REALM" \
  --arg rollback_artifact "${ROLLBACK_ARTIFACT_REFERENCE:-keycloak-before-${DEPLOY_ENVIRONMENT}-${EXPECTED_DEPLOY_SHA}}" '
    {
      schemaVersion: 1,
      repositorySha: $repository_sha,
      environment: $environment,
      planSha256: $plan_sha256,
      workflowRunId: $workflow_run_id,
      createdAt: $timestamp,
      realm: $realm,
      partialApply: false,
      supportedStates: [
        "pending",
        "started",
        "created",
        "updated",
        "unchanged",
        "failed",
        "rollback-required",
        "rollback-completed"
      ],
      rollbackArtifactReference: $rollback_artifact,
      operations: (
        to_entries | map({
          sequence: (.key + 1),
          clientId: .value.clientId,
          clientUuid: (.value.clientUuid // null),
          action: .value.action,
          preStateHash: (.value.expectedBeforeSha256 // null),
          expectedPostStateHash: (
            .value.clientId as $client_id
            | $client_id
          ),
          rollbackArtifactReference: $rollback_artifact,
          state: "pending"
        })
      )
    }
  ' "$apply_manifest" >"$recovery_manifest"

# Replace the temporary client-id placeholder with the reviewed desired hash.
manifest_tmp="$(mktemp "$RECOVERY_DIR/.manifest.XXXXXX")"
jq --slurpfile plan "$PLAN_FILE" '
  .operations |= map(
    . as $operation
    | .expectedPostStateHash = (
        $plan[0].clients[]
        | select(.clientId == $operation.clientId)
        | .desiredSha256
      )
  )
' "$recovery_manifest" >"$manifest_tmp"
chmod 600 "$manifest_tmp"
mv -f "$manifest_tmp" "$recovery_manifest"
chmod 600 "$recovery_manifest"

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
  # Sequence is the manifest order, including noops, rather than mutation count.
  operation_sequence="$(jq -er --arg client_id "$(jq -er '.clientId' <<<"$operation")" '.operations[] | select(.clientId == $client_id) | .sequence' "$recovery_manifest")"
  active_sequence="$operation_sequence"
  mutation_started=false
  record_operation_state "$operation_sequence" started
  action="$(jq -er '.action' <<<"$operation")"
  client_id="$(jq -er '.clientId' <<<"$operation")"
  case "$action" in
    create)
      desired_file="$(jq -er '.desiredFile' <<<"$operation")"
      request_body_file="$desired_file"
      secret_environment="${machine_secret_environment[$client_id]:-}"
      if [[ -n "$secret_environment" ]]; then
        require_env "$secret_environment"
        create_body_file="$tmp_dir/create-${client_id}.json"
        jq -S --arg secret_environment "$secret_environment" \
          '.secret = env[$secret_environment]' "$desired_file" >"$create_body_file"
        chmod 600 "$create_body_file"
        request_body_file="$create_body_file"
      fi
      mutation_started=true
      keycloak_api POST \
        "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients" \
        "$request_body_file" >/dev/null
      created_count=$((created_count + 1))
      changed_count=$((changed_count + 1))
      mutated_count=$((mutated_count + 1))
      [[ "$(keycloak_api GET "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients?clientId=$(urlencode "$client_id")&exact=true" | jq -er 'length')" -eq 1 ]] ||
        die "Created client could not be read back uniquely: ${client_id}"
      record_operation_state "$operation_sequence" created
      active_sequence=""
      mutation_started=false
      printf 'CREATED=client:%s\n' "$client_id"
      ;;
    update)
      client_uuid="$(jq -er '.clientUuid' <<<"$operation")"
      desired_file="$(jq -er '.desiredFile' <<<"$operation")"
      expected_before_sha256="$(jq -er '.expectedBeforeSha256' <<<"$operation")"
      safe_client_id="$(printf '%s' "$client_id" | LC_ALL=C tr -c '[:alnum:]_.-' '_')"
      immediate_live_file="$tmp_dir/immediate-live-${safe_client_id}.json"
      immediate_before_file="$tmp_dir/immediate-before-${safe_client_id}.json"
      merged_file="$tmp_dir/immediate-merged-${safe_client_id}.json"
      keycloak_api GET \
        "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" \
        >"$immediate_live_file"
      project_live_to_desired_shape "$immediate_live_file" "$desired_file" "$immediate_before_file"
      [[ "$(canonical_hash "$immediate_before_file")" == "$expected_before_sha256" ]] ||
        die "Immediate pre-write state changed for client ${client_id}"
      jq -S -s '
        .[0] * .[1]
        | del(.secret, .registrationAccessToken, .access)
      ' "$immediate_live_file" "$desired_file" >"$merged_file"
      chmod 600 "$merged_file"
      mutation_started=true
      keycloak_api PUT \
        "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" \
        "$merged_file" >/dev/null
      updated_count=$((updated_count + 1))
      changed_count=$((changed_count + 1))
      mutated_count=$((mutated_count + 1))
      record_operation_state "$operation_sequence" updated
      active_sequence=""
      mutation_started=false
      printf 'UPDATED=client:%s\n' "$client_id"
      ;;
    noop)
      record_operation_state "$operation_sequence" unchanged
      active_sequence=""
      mutation_started=false
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
printf 'PARTIAL_APPLY=false\n'
printf 'RECOVERY_MANIFEST=%s\n' "$recovery_manifest"
apply_finished=true
