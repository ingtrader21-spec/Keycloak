#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() { printf 'KONG_CERTIFICATION=FAIL\nERROR=%s\n' "$*" >&2; exit 1; }
for command_name in curl jq base64 install date; do command -v "$command_name" >/dev/null || fail "missing command: $command_name"; done
for variable in KONG_TEST_URL CERT_CLIENT_ID CERT_CLIENT_SECRET DISABLED_CLIENT_ID DISABLED_CLIENT_SECRET EXPECTED_AUDIENCE EXPECTED_SCOPE KONG_EVIDENCE_FILE; do
  [[ -n "${!variable:-}" ]] || fail "required environment variable is missing: $variable"
done
[[ "$KONG_TEST_URL" == https://* ]] || fail "KONG_TEST_URL must use HTTPS"
[[ "$KONG_EVIDENCE_FILE" == /* && ! -L "$KONG_EVIDENCE_FILE" ]] || fail "KONG_EVIDENCE_FILE must be an absolute non-symlink path"

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
token_endpoint="$(jq -er '.tokenEndpoint' "$root_dir/config/endpoints/codestra.json")"
expected_issuer="$(jq -er '.issuer' "$root_dir/config/endpoints/codestra.json")"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"; unset CERT_CLIENT_SECRET valid_token' EXIT

valid_response="$tmp_dir/valid-token.json"
token_status="$(curl --silent --show-error --output "$valid_response" --write-out '%{http_code}' \
  --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
  --request POST "$token_endpoint" \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode "client_id=$CERT_CLIENT_ID" \
  --data-urlencode "client_secret=$CERT_CLIENT_SECRET")"
[[ "$token_status" == 200 ]] || fail "Client Credentials token request returned HTTP $token_status"
valid_token="$(jq -er '.access_token' "$valid_response")"

jwt_payload="$(cut -d. -f2 <<<"$valid_token" | tr '_-' '/+' )"
case $((${#jwt_payload} % 4)) in 2) jwt_payload+='==' ;; 3) jwt_payload+='=' ;; 1) fail 'invalid JWT payload encoding' ;; esac
claims="$tmp_dir/claims.json"
printf '%s' "$jwt_payload" | base64 --decode >"$claims" 2>/dev/null || fail 'cannot decode JWT claims'
jq -e --arg issuer "$expected_issuer" --arg audience "$EXPECTED_AUDIENCE" --arg scope "$EXPECTED_SCOPE" --arg client "$CERT_CLIENT_ID" '
  .iss == $issuer
  and ((.aud == $audience) or (.aud | type == "array" and index($audience) != null))
  and ((.scope // "") | split(" ") | index($scope) != null)
  and ((.azp // .client_id) == $client)
  and (.exp | type == "number")
' "$claims" >/dev/null || fail 'valid token claims do not match the reviewed contract'

decode_claims() {
  local token="$1" destination="$2" payload
  payload="$(cut -d. -f2 <<<"$token" | tr '_-' '/+')"
  case $((${#payload} % 4)) in 2) payload+='==' ;; 3) payload+='=' ;; 1) fail 'invalid negative JWT payload encoding' ;; esac
  printf '%s' "$payload" | base64 --decode >"$destination" 2>/dev/null || fail 'cannot decode negative JWT claims'
  jq -e . "$destination" >/dev/null || fail 'negative JWT claims are not JSON'
}

declare -A statuses=()
request_kong() {
  local name="$1" token="${2:-}" expected="$3" status
  if [[ -n "$token" ]]; then
    status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 --header "Authorization: Bearer $token" "$KONG_TEST_URL")"
  else
    status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 "$KONG_TEST_URL")"
  fi
  [[ "$status" =~ $expected ]] || fail "$name returned unexpected HTTP $status"
  statuses["$name"]="$status"
}

request_kong valid "$valid_token" '^2[0-9][0-9]$'
request_kong missing '' '^(401|403)$'
request_kong malformed 'not-a-jwt' '^(401|403)$'
now="$(date +%s)"
for case_name in wrong_issuer wrong_audience insufficient_scope expired; do
  variable="KONG_TOKEN_${case_name^^}"
  [[ -n "${!variable:-}" ]] || fail "required negative test token is missing: $variable"
  negative_claims="$tmp_dir/${case_name}.json"
  decode_claims "${!variable}" "$negative_claims"
  case "$case_name" in
    wrong_issuer) jq -e --arg issuer "$expected_issuer" --argjson now "$now" '.iss != $issuer and .exp > $now' "$negative_claims" >/dev/null || fail 'wrong-issuer fixture is not isolated' ;;
    wrong_audience) jq -e --arg audience "$EXPECTED_AUDIENCE" --arg issuer "$expected_issuer" --argjson now "$now" '.iss == $issuer and .exp > $now and ((.aud == $audience or (.aud|type == "array" and index($audience) != null)) | not)' "$negative_claims" >/dev/null || fail 'wrong-audience fixture is not isolated' ;;
    insufficient_scope) jq -e --arg audience "$EXPECTED_AUDIENCE" --arg scope "$EXPECTED_SCOPE" --arg issuer "$expected_issuer" --argjson now "$now" '.iss == $issuer and .exp > $now and (.aud == $audience or (.aud|type == "array" and index($audience) != null)) and (((.scope // "")|split(" ")|index($scope) != null)|not)' "$negative_claims" >/dev/null || fail 'insufficient-scope fixture is not isolated' ;;
    expired) jq -e --argjson now "$now" '.exp <= $now' "$negative_claims" >/dev/null || fail 'expired fixture is not expired' ;;
  esac
  request_kong "$case_name" "${!variable}" '^(401|403)$'
done
last_character="${valid_token: -1}"
replacement='A'; [[ "$last_character" == A ]] && replacement='B'
invalid_signature_token="${valid_token::-1}${replacement}"
request_kong invalid_signature "$invalid_signature_token" '^(401|403)$'

disabled_status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 --request POST "$token_endpoint" --data-urlencode 'grant_type=client_credentials' --data-urlencode "client_id=$DISABLED_CLIENT_ID" --data-urlencode "client_secret=$DISABLED_CLIENT_SECRET")"
[[ "$disabled_status" =~ ^(400|401)$ ]] || fail "disabled client unexpectedly obtained a token (HTTP $disabled_status)"

install -d -m 0700 -- "$(dirname -- "$KONG_EVIDENCE_FILE")"
jq -S -n \
  --arg repositorySha "${GITHUB_SHA:-$(git -C "$root_dir" rev-parse HEAD)}" \
  --arg issuer "$expected_issuer" --arg audience "$EXPECTED_AUDIENCE" --arg scope "$EXPECTED_SCOPE" \
  --arg valid "${statuses[valid]}" --arg missing "${statuses[missing]}" --arg malformed "${statuses[malformed]}" \
  --arg wrongIssuer "${statuses[wrong_issuer]}" --arg wrongAudience "${statuses[wrong_audience]}" \
  --arg insufficientScope "${statuses[insufficient_scope]}" --arg expired "${statuses[expired]}" \
  --arg invalidSignature "${statuses[invalid_signature]}" --arg disabledClient "$disabled_status" '
  {schemaVersion:1, repositorySha:$repositorySha, issuer:$issuer, audience:$audience, scope:$scope,
   results:{valid:$valid,missing:$missing,malformed:$malformed,wrongIssuer:$wrongIssuer,
   wrongAudience:$wrongAudience,insufficientScope:$insufficientScope,expired:$expired,
   invalidSignature:$invalidSignature,disabledClient:$disabledClient}}
' >"$KONG_EVIDENCE_FILE"
chmod 600 "$KONG_EVIDENCE_FILE"
printf 'KONG_CERTIFICATION=PASS\nEVIDENCE_FILE=%s\n' "$KONG_EVIDENCE_FILE"
