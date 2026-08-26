#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/keycloak-admin.sh
source "$ROOT_DIR/scripts/lib/keycloak-admin.sh"

output_root="$ROOT_DIR/exports"
declare -a client_ids=()

usage() {
  cat <<'USAGE'
Usage: scripts/export-client.sh [--output PATH] CLIENT_ID [CLIENT_ID ...]

Exports sanitized client representations into:
  PATH/config/clients/<client-id>.json

The export removes internal IDs, secrets, registration tokens, and access
metadata. Review the output before committing it.
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

keycloak_authenticate
trap 'unset KC_ACCESS_TOKEN' EXIT

mkdir -p "$output_root/config/clients"

for client_id in "${client_ids[@]}"; do
  encoded_client_id="$(urlencode "$client_id")"
  client_list="$(
    keycloak_api GET \
      "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients?clientId=${encoded_client_id}&exact=true"
  )"

  [[ "$(jq 'length' <<<"$client_list")" -eq 1 ]] ||
    die "Expected exactly one client for clientId=${client_id}"

  client_uuid="$(jq -er '.[0].id' <<<"$client_list")"
  safe_filename="$(printf '%s' "$client_id" | LC_ALL=C tr -c '[:alnum:]_.-' '_')"
  destination="$output_root/config/clients/${safe_filename}.json"

  keycloak_api GET \
    "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" |
    jq '
      del(
        .id,
        .secret,
        .registrationAccessToken,
        .access
      )
    ' >"$destination"

  chmod 600 "$destination"
  printf 'EXPORTED=%s\n' "$destination"
done
