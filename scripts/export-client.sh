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

Exports rollback overlays into:
  PATH/config/clients/<client-id>.json

Each client must have a reviewed field allowlist under
config/export-allowlists/. Fields not explicitly allowed for that client are
never written to the artifact.
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

for client_id in "${client_ids[@]}"; do
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

  [[ "$(jq -er 'length' <<<"$client_list")" -eq 1 ]] ||
    die "Expected exactly one client for clientId=${client_id}"

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
  printf 'EXPORTED_ALLOWLISTED=%s\n' "$destination"
done
