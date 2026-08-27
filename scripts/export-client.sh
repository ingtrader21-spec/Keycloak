#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/keycloak-admin.sh
source "$ROOT_DIR/scripts/lib/keycloak-admin.sh"

output_root="$ROOT_DIR/exports"
declare -a client_ids=()

usage() {
  cat <<'USAGE'
Usage: scripts/export-client.sh [--output PATH] CLIENT_ID [CLIENT_ID ...]

Exports rollback evidence into PATH.

For an existing managed client, writes an allowlisted before-state overlay to:
  PATH/config/clients/<client-id>.json

For an absent client, absence is accepted only when the client is explicitly
listed in config/policy/creatable-clients.json. The artifact then records
preApplyState=absent plus disable-first/separate-reviewed-delete rollback
metadata. Missing non-creatable clients remain a hard failure.

This script performs read-only Keycloak calls and no mutations.
USAGE
}

while (($#)); do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || die "--output requires a path"
      output_root="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --*)
      die "Unknown option: $1"
      ;;
    *)
      client_ids+=("$1")
      shift
      ;;
  esac
done

((${#client_ids[@]} > 0)) || {
  usage >&2
  exit 64
}
[[ "$output_root" == /* ]] || die "--output must be an absolute path"
[[ ! -L "$output_root" ]] || die "Output path must not be a symlink"

"$ROOT_DIR/scripts/validate.sh"
keycloak_authenticate
trap 'unset KC_ACCESS_TOKEN' EXIT

mkdir -p "$output_root/config/clients"
chmod 700 "$output_root" "$output_root/config" "$output_root/config/clients"

managed_policy="$ROOT_DIR/config/policy/managed-clients.json"
creatable_policy="$ROOT_DIR/config/policy/creatable-clients.json"
mapfile -t managed_ids < <(jq -r '.clients[]' "$managed_policy" | sort)
mapfile -t creatable_ids < <(jq -r '.clients[]' "$creatable_policy" | sort)

declare -A managed_set=()
declare -A creatable_set=()
for client_id in "${managed_ids[@]}"; do
  managed_set["$client_id"]=1
done
for client_id in "${creatable_ids[@]}"; do
  creatable_set["$client_id"]=1
done

metadata_ndjson="$output_root/rollback-metadata.ndjson"
: >"$metadata_ndjson"
chmod 600 "$metadata_ndjson"

for client_id in "${client_ids[@]}"; do
  [[ -n "${managed_set[$client_id]:-}" ]] ||
    die "Rollback export requested for unmanaged clientId=${client_id}"

  safe_filename="$(printf '%s' "$client_id" | LC_ALL=C tr -c '[:alnum:]_.-' '_')"
  allowlist_file="$ROOT_DIR/config/export-allowlists/${safe_filename}.json"
  [[ -f "$allowlist_file" && ! -L "$allowlist_file" ]] ||
    die "Reviewed export allowlist is missing for clientId=${client_id}"
  [[ "$(jq -er '.clientId' "$allowlist_file")" == "$client_id" ]] ||
    die "Export allowlist clientId does not match ${client_id}"

  top_level_fields="$(jq -c '.topLevelFields' "$allowlist_file")"
  attribute_fields="$(jq -c '.attributeFields' "$allowlist_file")"

  encoded_client_id="$(urlencode "$client_id")"
  client_list="$(
    keycloak_api GET \
      "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients?clientId=${encoded_client_id}&exact=true"
  )"
  matches="$(jq -er 'length' <<<"$client_list")"
  [[ "$matches" -le 1 ]] ||
    die "Multiple live clients matched clientId=${client_id}"

  if [[ "$matches" -eq 0 ]]; then
    [[ -n "${creatable_set[$client_id]:-}" ]] ||
      die "Missing non-creatable client cannot produce safe rollback evidence: ${client_id}"

    jq -c -n \
      --arg client_id "$client_id" '
        {
          clientId: $client_id,
          preApplyState: "absent",
          evidenceKind: "reviewed-create-candidate",
          rollback: {
            strategy: "disable_then_reviewed_delete",
            disablePatch: {enabled: false},
            disableFirst: true,
            deleteAllowedAfterDisable: true,
            deletionRequiresSeparateReviewedRollback: true,
            requiresReviewedPlan: true
          }
        }
      ' >>"$metadata_ndjson"
    printf 'EXPORTED_ABSENCE_ROLLBACK=%s\n' "$client_id"
    continue
  fi

  client_uuid="$(jq -er '.[0].id' <<<"$client_list")"
  destination="$output_root/config/clients/${safe_filename}.json"

  keycloak_api GET \
    "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" |
    jq -S \
      --argjson top_level_fields "$top_level_fields" \
      --argjson attribute_fields "$attribute_fields" '
        . as $source
        | reduce $top_level_fields[] as $field
            ({}; if ($source | has($field)) then .[$field] = $source[$field] else . end)
        | if has("attributes") then
            .attributes = (
              (.attributes // {}) as $attributes
              | reduce $attribute_fields[] as $field
                  ({}; if ($attributes | has($field)) then .[$field] = $attributes[$field] else . end)
            )
          else
            .
          end
      ' >"$destination"

  [[ "$(jq -er '.clientId' "$destination")" == "$client_id" ]] ||
    die "Allowlisted rollback export lost clientId=${client_id}"
  chmod 600 "$destination"
  before_sha256="$(jq -S -c . "$destination" | sha256sum | awk '{print $1}')"

  jq -c -n \
    --arg client_id "$client_id" \
    --arg before_sha256 "$before_sha256" \
    --arg overlay "config/clients/${safe_filename}.json" '
      {
        clientId: $client_id,
        preApplyState: "existing",
        evidenceKind: "allowlisted-before-overlay",
        beforeSha256: $before_sha256,
        rollback: {
          strategy: "restore_allowlisted_overlay_via_reviewed_plan",
          overlayPath: $overlay,
          requiresReviewedPlan: true
        }
      }
    ' >>"$metadata_ndjson"
  printf 'EXPORTED_ALLOWLISTED=%s\n' "$destination"
done

metadata_file="$output_root/rollback-metadata.json"
jq -S -s \
  --arg target_realm "$KC_TARGET_REALM" '
    {
      schemaVersion: 1,
      targetRealm: $target_realm,
      clients: sort_by(.clientId),
      existingClientCount: ([.[] | select(.preApplyState == "existing")] | length),
      absentCreatableClientCount: ([.[] | select(.preApplyState == "absent")] | length)
    }
  ' "$metadata_ndjson" >"$metadata_file"
chmod 600 "$metadata_file"
rm -f "$metadata_ndjson"

jq -e '
  all(.clients[];
    if .preApplyState == "existing" then
      .rollback.strategy == "restore_allowlisted_overlay_via_reviewed_plan"
      and .rollback.requiresReviewedPlan == true
    else
      .preApplyState == "absent"
      and .rollback.strategy == "disable_then_reviewed_delete"
      and .rollback.disablePatch == {"enabled": false}
      and .rollback.disableFirst == true
      and .rollback.deletionRequiresSeparateReviewedRollback == true
      and .rollback.requiresReviewedPlan == true
    end
  )
' "$metadata_file" >/dev/null ||
  die "Generated rollback metadata failed validation"

printf 'ROLLBACK_METADATA=%s\n' "$metadata_file"
printf 'ROLLBACK_EVIDENCE=READY\n'
