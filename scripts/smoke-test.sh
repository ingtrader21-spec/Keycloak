#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/keycloak-admin.sh
source "$ROOT_DIR/scripts/lib/keycloak-admin.sh"
endpoint_file="$(keycloak_endpoint_file)"

command -v curl >/dev/null 2>&1 || {
  printf 'ERROR=curl_is_required\n' >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  printf 'ERROR=jq_is_required\n' >&2
  exit 1
}

canonical_public_url="$(jq -er '.publicUrl' "$endpoint_file")"
canonical_realm="$(jq -er '.realm' "$endpoint_file")"
canonical_discovery_url="$(jq -er '.discoveryUrl' "$endpoint_file")"

KC_PUBLIC_URL="${KC_PUBLIC_URL:-${KC_BASE_URL:-$canonical_public_url}}"
KC_PUBLIC_URL="${KC_PUBLIC_URL%/}"
KC_TARGET_REALM="${KC_TARGET_REALM:-$canonical_realm}"
SMOKE_CLIENT_ID="${SMOKE_CLIENT_ID:-klyrow-portal}"
SMOKE_REDIRECT_URI="${SMOKE_REDIRECT_URI:-https://klyrow.com/}"

[[ "$KC_PUBLIC_URL" == "$canonical_public_url" ]] || {
  printf 'ERROR=noncanonical_public_url actual=%s expected=%s\n' \
    "$KC_PUBLIC_URL" "$canonical_public_url" >&2
  exit 1
}
[[ "$KC_TARGET_REALM" == "$canonical_realm" ]] || {
  printf 'ERROR=noncanonical_realm actual=%s expected=%s\n' \
    "$KC_TARGET_REALM" "$canonical_realm" >&2
  exit 1
}

discovery="$(
  curl --silent --show-error --fail-with-body \
    --proto '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 --retry-connrefused \
    --connect-timeout 10 --max-time 30 \
    "$canonical_discovery_url"
)"

expected_issuer="$(jq -er '.issuer' "$endpoint_file")"
actual_issuer="$(jq -er '.issuer' <<<"$discovery")"
[[ "$actual_issuer" == "$expected_issuer" ]] || {
  printf 'ERROR=issuer_mismatch expected=%s actual=%s\n' "$expected_issuer" "$actual_issuer" >&2
  exit 1
}

authorization_endpoint="$(jq -er '.authorization_endpoint' <<<"$discovery")"
expected_authorization_endpoint="$(jq -er '.authorizationEndpoint' "$endpoint_file")"
[[ "$authorization_endpoint" == "$expected_authorization_endpoint" ]] || {
  printf 'ERROR=authorization_endpoint_mismatch\n' >&2
  exit 1
}
encoded_redirect="$(jq -rn --arg value "$SMOKE_REDIRECT_URI" '$value | @uri')"
encoded_client="$(jq -rn --arg value "$SMOKE_CLIENT_ID" '$value | @uri')"

tmp_headers="$(mktemp)"
tmp_body="$(mktemp)"
trap 'rm -f "$tmp_headers" "$tmp_body"' EXIT

http_status="$(
  curl --silent --show-error \
    --proto '=https' --tlsv1.2 \
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

printf 'PUBLIC_URL=%s\n' "$KC_PUBLIC_URL"
printf 'DISCOVERY_URL=%s\n' "$canonical_discovery_url"
printf 'DISCOVERY=PASS\n'
printf 'ISSUER=PASS\n'
printf 'CLIENT=%s\n' "$SMOKE_CLIENT_ID"
printf 'REDIRECT_URI=%s\n' "$SMOKE_REDIRECT_URI"
printf 'REDIRECT_VALIDATION=PASS\n'
printf 'SMOKE_TEST=PASS\n'
