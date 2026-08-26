#!/usr/bin/env bash

if [[ -n "${KEYCLOAK_ADMIN_LIB_LOADED:-}" ]]; then
  return 0
fi
readonly KEYCLOAK_ADMIN_LIB_LOADED=1
KEYCLOAK_REPOSITORY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly KEYCLOAK_REPOSITORY_ROOT

log() {
  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 ||
    die "Required command is not installed: $command_name"
}

require_env() {
  local variable_name="$1"
  [[ -n "${!variable_name:-}" ]] ||
    die "Required environment variable is not set: $variable_name"
}

urlencode() {
  jq -rn --arg value "$1" '$value | @uri'
}

keycloak_assert_canonical_configuration() {
  require_command jq
  local endpoint_file="$KEYCLOAK_REPOSITORY_ROOT/config/endpoints/codestra.json"
  [[ -f "$endpoint_file" ]] || die "Canonical endpoint file is missing: $endpoint_file"

  local expected_base_url expected_public_url expected_realm
  expected_base_url="$(jq -er '.adminApiBaseUrl' "$endpoint_file")"
  expected_public_url="$(jq -er '.publicUrl' "$endpoint_file")"
  expected_realm="$(jq -er '.realm' "$endpoint_file")"

  if [[ "${KC_BASE_URL%/}" != "$expected_base_url" ]]; then
    case "${KC_BASE_URL%/}" in
      http://127.0.0.1:* | http://localhost:*)
        [[ "${ALLOW_NONCANONICAL_KC_BASE_URL_FOR_TESTS:-false}" == "true" ]] ||
          die "KC_BASE_URL must equal the canonical Codestra API URL: $expected_base_url"
        ;;
      *)
        die "KC_BASE_URL must equal the canonical Codestra API URL: $expected_base_url"
        ;;
    esac
  fi
  [[ "${KC_PUBLIC_URL:-$expected_public_url}" == "$expected_public_url" ]] ||
    die "KC_PUBLIC_URL must equal the canonical Codestra public URL: $expected_public_url"
  [[ "${KC_TARGET_REALM:-$expected_realm}" == "$expected_realm" ]] ||
    die "KC_TARGET_REALM must equal $expected_realm"
  [[ "${KC_ADMIN_REALM:-$expected_realm}" == "$expected_realm" ]] ||
    die "KC_ADMIN_REALM must equal $expected_realm"
}

keycloak_initialize() {
  require_command curl
  require_command jq
  require_env KC_BASE_URL
  require_env KC_ADMIN_CLIENT_ID

  KC_BASE_URL="${KC_BASE_URL%/}"
  KC_ADMIN_REALM="${KC_ADMIN_REALM:-codestra}"
  KC_TARGET_REALM="${KC_TARGET_REALM:-codestra}"
  KC_CONNECT_TIMEOUT="${KC_CONNECT_TIMEOUT:-10}"
  KC_MAX_TIME="${KC_MAX_TIME:-45}"

  case "$KC_BASE_URL" in
    https://*)
      KC_CURL_PROTOCOL='=https'
      ;;
    http://127.0.0.1:* | http://localhost:*)
      [[ "${ALLOW_INSECURE_KC_BASE_URL:-false}" == "true" ]] ||
        die "Local HTTP Keycloak access requires ALLOW_INSECURE_KC_BASE_URL=true"
      KC_CURL_PROTOCOL='=http'
      ;;
    *)
      die "KC_BASE_URL must use HTTPS; only explicitly approved localhost HTTP is allowed"
      ;;
  esac

  export KC_BASE_URL KC_ADMIN_REALM KC_TARGET_REALM KC_CONNECT_TIMEOUT KC_MAX_TIME KC_CURL_PROTOCOL
}

keycloak_transport_arguments() {
  printf '%s\0' --proto "$KC_CURL_PROTOCOL"
  if [[ "$KC_CURL_PROTOCOL" == '=https' ]]; then
    printf '%s\0' --tlsv1.2
  fi
}

keycloak_authenticate() {
  keycloak_initialize
  keycloak_assert_canonical_configuration

  local token_endpoint
  token_endpoint="${KC_BASE_URL}/realms/$(urlencode "$KC_ADMIN_REALM")/protocol/openid-connect/token"

  local -a form
  if [[ -n "${KC_ADMIN_CLIENT_SECRET:-}" ]]; then
    form=(
      --data-urlencode "grant_type=client_credentials"
      --data-urlencode "client_id=${KC_ADMIN_CLIENT_ID}"
      --data-urlencode "client_secret=${KC_ADMIN_CLIENT_SECRET}"
    )
  elif [[ -n "${KC_ADMIN_USERNAME:-}" && -n "${KC_ADMIN_PASSWORD:-}" ]]; then
    form=(
      --data-urlencode "grant_type=password"
      --data-urlencode "client_id=${KC_ADMIN_CLIENT_ID}"
      --data-urlencode "username=${KC_ADMIN_USERNAME}"
      --data-urlencode "password=${KC_ADMIN_PASSWORD}"
    )
  else
    die "Set KC_ADMIN_CLIENT_SECRET, or set both KC_ADMIN_USERNAME and KC_ADMIN_PASSWORD"
  fi

  local -a transport_arguments=()
  mapfile -d '' -t transport_arguments < <(keycloak_transport_arguments)

  local token_response
  token_response="$(
    curl --silent --show-error --fail-with-body \
      "${transport_arguments[@]}" \
      --connect-timeout "$KC_CONNECT_TIMEOUT" \
      --max-time "$KC_MAX_TIME" \
      --request POST \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      "${form[@]}" \
      "$token_endpoint"
  )" || die "Keycloak token request failed"

  KC_ACCESS_TOKEN="$(jq -er '.access_token' <<<"$token_response")" ||
    die "Keycloak token response did not contain an access token"

  export KC_ACCESS_TOKEN
}

keycloak_api() {
  local method="$1"
  local path="$2"
  local body_file="${3:-}"

  [[ -n "${KC_ACCESS_TOKEN:-}" ]] ||
    die "keycloak_authenticate must be called before keycloak_api"
  [[ "$path" == /* ]] || die "Keycloak API path must begin with /"

  local -a transport_arguments=()
  mapfile -d '' -t transport_arguments < <(keycloak_transport_arguments)

  local -a arguments=(
    --silent
    --show-error
    --fail-with-body
    "${transport_arguments[@]}"
    --connect-timeout "$KC_CONNECT_TIMEOUT"
    --max-time "$KC_MAX_TIME"
    --request "$method"
    --header "Authorization: Bearer ${KC_ACCESS_TOKEN}"
    --header 'Accept: application/json'
  )

  case "$method" in
    GET | HEAD | OPTIONS)
      arguments+=(
        --retry 3
        --retry-delay 2
        --retry-connrefused
      )
      ;;
    POST | PUT | PATCH | DELETE)
      # Mutations are deliberately not retried. A transport failure after the
      # server accepted a write is ambiguous and must be reconciled explicitly.
      ;;
    *)
      die "Unsupported Keycloak API method: $method"
      ;;
  esac

  if [[ -n "$body_file" ]]; then
    [[ -f "$body_file" ]] || die "Request body file does not exist: $body_file"
    arguments+=(
      --header 'Content-Type: application/json'
      --data-binary "@${body_file}"
    )
  fi

  curl "${arguments[@]}" "${KC_BASE_URL}${path}"
}
