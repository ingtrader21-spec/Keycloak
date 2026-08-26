#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/keycloak-admin.sh
source "$ROOT_DIR/scripts/lib/keycloak-admin.sh"

MODE="check"
CONFIG_ROOT="${CONFIG_ROOT:-$ROOT_DIR/config}"

usage() {
  cat <<'USAGE'
Usage: scripts/reconcile.sh [--check|--apply]

--check  Compare Git desired state with Keycloak. Exit 2 when drift exists.
--apply  Apply only declared realm/client overlays, then verify convergence.

Environment:
  KC_BASE_URL
  KC_TARGET_REALM
  KC_ADMIN_REALM
  KC_ADMIN_CLIENT_ID
  KC_ADMIN_CLIENT_SECRET
or:
  KC_ADMIN_USERNAME
  KC_ADMIN_PASSWORD

Optional:
  CONFIG_ROOT             Alternate desired-state root for rollback/testing.
  ALLOW_REALM_CREATE=true Permit creation when the target realm is absent.
USAGE
}

case "${1:-}" in
  "" | --check)
    MODE="check"
    ;;
  --apply)
    MODE="apply"
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 64
    ;;
esac

"$ROOT_DIR/scripts/validate.sh"

keycloak_authenticate

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"; unset KC_ACCESS_TOKEN' EXIT

drift_count=0
changed_count=0
checked_count=0

mark_drift() {
  local resource="$1"
  drift_count=$((drift_count + 1))
  printf 'DRIFT=%s\n' "$resource"
}

merge_is_noop() {
  local live_file="$1"
  local desired_file="$2"
  jq -e -s '.[0] * .[1] == .[0]' "$live_file" "$desired_file" >/dev/null
}

apply_overlay() {
  local live_file="$1"
  local desired_file="$2"
  local merged_file="$3"

  jq -s '
    .[0] * .[1]
    | del(
        .secret,
        .registrationAccessToken,
        .access
      )
  ' "$live_file" "$desired_file" >"$merged_file"
}

realm_file="$CONFIG_ROOT/realms/${KC_TARGET_REALM}.json"
if [[ -f "$realm_file" ]]; then
  checked_count=$((checked_count + 1))
  live_realm="$tmp_dir/realm-live.json"

  if keycloak_api GET "/admin/realms/$(urlencode "$KC_TARGET_REALM")" >"$live_realm"; then
    if ! merge_is_noop "$live_realm" "$realm_file"; then
      mark_drift "realm:${KC_TARGET_REALM}"
      if [[ "$MODE" == "apply" ]]; then
        merged_realm="$tmp_dir/realm-merged.json"
        apply_overlay "$live_realm" "$realm_file" "$merged_realm"
        keycloak_api PUT "/admin/realms/$(urlencode "$KC_TARGET_REALM")" "$merged_realm" >/dev/null
        changed_count=$((changed_count + 1))
        printf 'APPLIED=realm:%s\n' "$KC_TARGET_REALM"
      fi
    else
      printf 'IN_SYNC=realm:%s\n' "$KC_TARGET_REALM"
    fi
  else
    if [[ "$MODE" == "apply" && "${ALLOW_REALM_CREATE:-false}" == "true" ]]; then
      keycloak_api POST "/admin/realms" "$realm_file" >/dev/null
      changed_count=$((changed_count + 1))
      drift_count=$((drift_count + 1))
      printf 'CREATED=realm:%s\n' "$KC_TARGET_REALM"
    else
      die "Target realm does not exist or is not accessible: ${KC_TARGET_REALM}"
    fi
  fi
fi

client_dir="$CONFIG_ROOT/clients"
if [[ -d "$client_dir" ]]; then
  mapfile -t client_files < <(find "$client_dir" -maxdepth 1 -type f -name '*.json' -print | sort)
else
  client_files=()
fi

for client_file in "${client_files[@]}"; do
  checked_count=$((checked_count + 1))
  client_id="$(jq -er '.clientId' "$client_file")"
  encoded_client_id="$(urlencode "$client_id")"
  safe_client_id="$(printf '%s' "$client_id" | LC_ALL=C tr -c '[:alnum:]_.-' '_')"
  client_list_file="$tmp_dir/client-list-${safe_client_id}.json"

  keycloak_api GET \
    "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients?clientId=${encoded_client_id}&exact=true" \
    >"$client_list_file"

  matches="$(jq 'length' "$client_list_file")"
  if [[ "$matches" -gt 1 ]]; then
    die "Multiple Keycloak clients matched clientId=${client_id}"
  fi

  if [[ "$matches" -eq 0 ]]; then
    mark_drift "client:${client_id}:missing"
    if [[ "$MODE" == "apply" ]]; then
      keycloak_api POST \
        "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients" \
        "$client_file" >/dev/null
      changed_count=$((changed_count + 1))
      printf 'CREATED=client:%s\n' "$client_id"
    fi
    continue
  fi

  client_uuid="$(jq -er '.[0].id' "$client_list_file")"
  live_client="$tmp_dir/client-${client_uuid}-live.json"
  merged_client="$tmp_dir/client-${client_uuid}-merged.json"

  keycloak_api GET \
    "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" \
    >"$live_client"

  if merge_is_noop "$live_client" "$client_file"; then
    printf 'IN_SYNC=client:%s\n' "$client_id"
    continue
  fi

  mark_drift "client:${client_id}"
  if [[ "$MODE" == "apply" ]]; then
    apply_overlay "$live_client" "$client_file" "$merged_client"
    keycloak_api PUT \
      "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" \
      "$merged_client" >/dev/null
    changed_count=$((changed_count + 1))
    printf 'APPLIED=client:%s\n' "$client_id"
  fi
done

if [[ "$MODE" == "apply" && "$changed_count" -gt 0 ]]; then
  log "Verifying that applied configuration converged"
  CONFIG_ROOT="$CONFIG_ROOT" "$0" --check
  printf 'RECONCILE=APPLIED_AND_VERIFIED\n'
  exit 0
fi

printf 'MODE=%s\n' "$MODE"
printf 'RESOURCES_CHECKED=%s\n' "$checked_count"
printf 'DRIFT_COUNT=%s\n' "$drift_count"
printf 'CHANGED_COUNT=%s\n' "$changed_count"

if [[ "$drift_count" -gt 0 ]]; then
  printf 'RECONCILE=DRIFT\n'
  exit 2
fi

printf 'RECONCILE=IN_SYNC\n'
