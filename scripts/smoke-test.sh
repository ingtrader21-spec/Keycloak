#!/usr/bin/env bash
set -Eeuo pipefail

command -v curl >/dev/null 2>&1 || {
  printf 'ERROR=curl_is_required\n' >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  printf 'ERROR=jq_is_required\n' >&2
  exit 1
}

KC_PUBLIC_URL="${KC_PUBLIC_URL:-${KC_BASE_URL:-https://auth.codestra.co}}"
KC_PUBLIC_URL="${KC_PUBLIC_URL%/}"
KC_TARGET_REALM="${KC_TARGET_REALM:-codestra}"
SMOKE_CLIENT_ID="${SMOKE_CLIENT_ID:-klyrow-portal}"
SMOKE_REDIRECT_URI="${SMOKE_REDIRECT_URI:-https://klyrow.com/}"

discovery_url="${KC_PUBLIC_URL}/realms/${KC_TARGET_REALM}/.well-known/openid-configuration"
discovery="$(
  curl --silent --show-error --fail-with-body \
    --retry 3 --retry-delay 2 --retry-connrefused \
    --connect-timeout 10 --max-time 30 \
    "$discovery_url"
)"

expected_issuer="${KC_PUBLIC_URL}/realms/${KC_TARGET_REALM}"
actual_issuer="$(jq -er '.issuer' <<<"$discovery")"
[[ "$actual_issuer" == "$expected_issuer" ]] || {
  printf 'ERROR=issuer_mismatch expected=%s actual=%s\n' "$expected_issuer" "$actual_issuer" >&2
  exit 1
}

authorization_endpoint="$(jq -er '.authorization_endpoint' <<<"$discovery")"
encoded_redirect="$(jq -rn --arg value "$SMOKE_REDIRECT_URI" '$value | @uri')"
encoded_client="$(jq -rn --arg value "$SMOKE_CLIENT_ID" '$value | @uri')"

tmp_headers="$(mktemp)"
tmp_body="$(mktemp)"
trap 'rm -f "$tmp_headers" "$tmp_body"' EXIT

http_status="$(
  curl --silent --show-error \
    --output "$tmp_body" \
    --dump-header "$tmp_headers" \
    --write-out '%{http_code}' \
    --connect-timeout 10 --max-time 30 \
    "${authorization_endpoint}?client_id=${encoded_client}&response_type=code&scope=openid%20profile%20email&redirect_uri=${encoded_redirect}&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256&state=gitops-smoke&nonce=gitops-smoke"
)"

if grep -Eqi 'invalid[ _-]?redirect|invalid parameter:[[:space:]]*redirect_uri' "$tmp_headers" "$tmp_body"; then
  printf 'ERROR=redirect_uri_rejected client=%s redirect_uri=%s\n' \
    "$SMOKE_CLIENT_ID" "$SMOKE_REDIRECT_URI" >&2
  exit 1
fi

case "$http_status" in
  200 | 302 | 303)
    ;;
  *)
    printf 'ERROR=unexpected_authorization_status status=%s\n' "$http_status" >&2
    exit 1
    ;;
esac

printf 'DISCOVERY=PASS\n'
printf 'ISSUER=PASS\n'
printf 'CLIENT=%s\n' "$SMOKE_CLIENT_ID"
printf 'REDIRECT_URI=%s\n' "$SMOKE_REDIRECT_URI"
printf 'REDIRECT_VALIDATION=PASS\n'
printf 'SMOKE_TEST=PASS\n'
