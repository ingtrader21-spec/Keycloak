#!/usr/bin/env bash

if [[ -n "${KEYCLOAK_ADMIN_LIB_LOADED:-}" ]]; then
  return 0
fi
readonly KEYCLOAK_ADMIN_LIB_LOADED=1

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

  export KC_BASE_URL KC_ADMIN_REALM KC_TARGET_REALM KC_CONNECT_TIMEOUT KC_MAX_TIME
}

keycloak_authenticate() {
  keycloak_initialize

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

  local token_response
  token_response="$(
    curl --silent --show-error --fail-with-body \
      --retry 3 --retry-delay 2 --retry-connrefused \
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

  local -a arguments=(
    --silent
    --show-error
    --fail-with-body
    --retry 3
    --retry-delay 2
    --retry-connrefused
    --connect-timeout "$KC_CONNECT_TIMEOUT"
    --max-time "$KC_MAX_TIME"
    --request "$method"
    --header "Authorization: Bearer ${KC_ACCESS_TOKEN}"
    --header 'Accept: application/json'
  )

  if [[ -n "$body_file" ]]; then
    [[ -f "$body_file" ]] || die "Request body file does not exist: $body_file"
    arguments+=(
      --header 'Content-Type: application/json'
      --data-binary "@${body_file}"
    )
  fi

  curl "${arguments[@]}" "${KC_BASE_URL}${path}"
}
