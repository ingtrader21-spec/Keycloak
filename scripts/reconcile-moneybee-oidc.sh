#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/keycloak-admin.sh
source "$ROOT_DIR/scripts/lib/keycloak-admin.sh"

MODE="plan"
EXPECTED_DEPLOY_SHA=""
CONTRACT_FILE="$ROOT_DIR/config/identity/moneybee-oidc-clients.json"

usage() {
  cat <<'USAGE'
Usage: scripts/reconcile-moneybee-oidc.sh [--plan|--apply] --expected-deploy-sha SHA

Plans or reconciles the three MoneyBee public PKCE clients from the reviewed
Git contract. Plan mode is the default and performs no writes.

Required environment for both modes:
  KC_BASE_URL=https://auth.codestra.co
  KC_PUBLIC_URL=https://auth.codestra.co
  KC_TARGET_REALM=codestra
  KC_ADMIN_REALM=codestra
  KC_ADMIN_CLIENT_ID
  plus either KC_ADMIN_CLIENT_SECRET or KC_ADMIN_USERNAME/KC_ADMIN_PASSWORD

Additional requirement for --apply:
  MONEYBEE_OIDC_APPLY_CONFIRM=YES
USAGE
}

while (($#)); do
  case "$1" in
    --plan)
      MODE="plan"
      shift
      ;;
    --apply)
      MODE="apply"
      shift
      ;;
    --expected-deploy-sha)
      [[ $# -ge 2 ]] || die "--expected-deploy-sha requires a SHA"
      EXPECTED_DEPLOY_SHA="$2"
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

[[ "$EXPECTED_DEPLOY_SHA" =~ ^[0-9a-f]{40}$ ]] ||
  die "Expected deployment SHA must be 40 lowercase hexadecimal characters"
[[ -f "$CONTRACT_FILE" && ! -L "$CONTRACT_FILE" ]] ||
  die "MoneyBee OIDC contract is missing"

current_sha="$(git -C "$ROOT_DIR" rev-parse HEAD)"
[[ "$current_sha" == "$EXPECTED_DEPLOY_SHA" ]] ||
  die "Checked-out Git SHA does not match the reviewed deployment SHA"
[[ -z "$(git -C "$ROOT_DIR" status --short)" ]] ||
  die "Keycloak working tree must be clean before MoneyBee OIDC reconciliation"

if [[ "$MODE" == "apply" ]]; then
  [[ "${MONEYBEE_OIDC_APPLY_CONFIRM:-}" == "YES" ]] ||
    die "Set MONEYBEE_OIDC_APPLY_CONFIRM=YES to permit MoneyBee client writes"
fi

python3 "$ROOT_DIR/scripts/validate-moneybee-oidc-contract.py"
keycloak_authenticate

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"; unset KC_ACCESS_TOKEN' EXIT

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
            ({}; .[$key] = project($current[$key]; $wanted[$key]))
        elif ($wanted | type) == "array" then
          ($current // [])
        else
          $current
        end;
      project($live[0]; $desired[0])
    ' >"$destination"
}

write_desired_client() {
  local contract_json="$1"
  local destination="$2"
  jq -S '
    {
      clientId: .clientId,
      name: (
        if .portal == "borrower" then "MoneyBee Borrower Portal"
        elif .portal == "lender" then "MoneyBee Lender Portal"
        elif .portal == "admin" then "MoneyBee Admin Portal"
        else error("unsupported MoneyBee portal")
        end
      ),
      description: ("MoneyBee " + .portal + " browser portal using Authorization Code Flow with PKCE S256."),
      enabled: true,
      protocol: "openid-connect",
      publicClient: true,
      bearerOnly: false,
      consentRequired: false,
      standardFlowEnabled: true,
      implicitFlowEnabled: false,
      directAccessGrantsEnabled: false,
      serviceAccountsEnabled: false,
      frontchannelLogout: true,
      rootUrl: .origin,
      baseUrl: (.origin + "/"),
      redirectUris: .redirectUris,
      webOrigins: .webOrigins,
      attributes: {
        "pkce.code.challenge.method": "S256",
        "post.logout.redirect.uris": .postLogoutRedirectUris[0],
        "oauth2.device.authorization.grant.enabled": "false",
        "oidc.ciba.grant.enabled": "false"
      }
    }
  ' <<<"$contract_json" >"$destination"
  chmod 600 "$destination"
}

changed_count=0
created_count=0
updated_count=0
noop_count=0

while IFS= read -r client; do
  client_id="$(jq -er '.clientId' <<<"$client")"
  portal="$(jq -er '.portal' <<<"$client")"
  safe_client_id="$(printf '%s' "$client_id" | LC_ALL=C tr -c '[:alnum:]_.-' '_')"
  desired_file="$tmp_dir/desired-${safe_client_id}.json"
  list_file="$tmp_dir/list-${safe_client_id}.json"
  live_file="$tmp_dir/live-${safe_client_id}.json"
  projected_file="$tmp_dir/projected-${safe_client_id}.json"
  merged_file="$tmp_dir/merged-${safe_client_id}.json"

  write_desired_client "$client" "$desired_file"
  keycloak_api GET \
    "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients?clientId=$(urlencode "$client_id")&exact=true" \
    >"$list_file"

  matches="$(jq -er 'length' "$list_file")"
  [[ "$matches" -le 1 ]] || die "Multiple live Keycloak clients matched ${client_id}"

  if [[ "$matches" -eq 0 ]]; then
    action="create"
  else
    client_uuid="$(jq -er '.[0].id' "$list_file")"
    keycloak_api GET \
      "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" \
      >"$live_file"
    project_live_to_desired_shape "$live_file" "$desired_file" "$projected_file"
    if jq -e -n \
      --slurpfile live "$projected_file" \
      --slurpfile desired "$desired_file" \
      '$live[0] == $desired[0]' >/dev/null; then
      action="noop"
    else
      action="update"
    fi
  fi

  printf 'MONEYBEE_OIDC_PLAN portal=%s client=%s action=%s\n' "$portal" "$client_id" "$action"

  if [[ "$MODE" != "apply" ]]; then
    continue
  fi

  case "$action" in
    create)
      keycloak_api POST \
        "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients" \
        "$desired_file" >/dev/null
      created_count=$((created_count + 1))
      changed_count=$((changed_count + 1))
      ;;
    update)
      jq -S -s '
        .[0] * .[1]
        | del(.secret, .registrationAccessToken, .access)
      ' "$live_file" "$desired_file" >"$merged_file"
      chmod 600 "$merged_file"
      keycloak_api PUT \
        "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" \
        "$merged_file" >/dev/null
      updated_count=$((updated_count + 1))
      changed_count=$((changed_count + 1))
      ;;
    noop)
      noop_count=$((noop_count + 1))
      ;;
    *)
      die "Unsupported MoneyBee reconciliation action: $action"
      ;;
  esac
done < <(jq -c '.clients[]' "$CONTRACT_FILE")

if [[ "$MODE" == "plan" ]]; then
  printf 'MONEYBEE_OIDC_MODE=PLAN_ONLY\n'
  printf 'MONEYBEE_OIDC_WRITES=0\n'
  exit 0
fi

while IFS= read -r client; do
  client_id="$(jq -er '.clientId' <<<"$client")"
  safe_client_id="$(printf '%s' "$client_id" | LC_ALL=C tr -c '[:alnum:]_.-' '_')"
  desired_file="$tmp_dir/verify-desired-${safe_client_id}.json"
  list_file="$tmp_dir/verify-list-${safe_client_id}.json"
  live_file="$tmp_dir/verify-live-${safe_client_id}.json"
  projected_file="$tmp_dir/verify-projected-${safe_client_id}.json"

  write_desired_client "$client" "$desired_file"
  keycloak_api GET \
    "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients?clientId=$(urlencode "$client_id")&exact=true" \
    >"$list_file"
  [[ "$(jq -er 'length' "$list_file")" -eq 1 ]] ||
    die "MoneyBee client did not converge: $client_id"
  client_uuid="$(jq -er '.[0].id' "$list_file")"
  keycloak_api GET \
    "/admin/realms/$(urlencode "$KC_TARGET_REALM")/clients/$(urlencode "$client_uuid")" \
    >"$live_file"
  project_live_to_desired_shape "$live_file" "$desired_file" "$projected_file"
  jq -e -n \
    --slurpfile live "$projected_file" \
    --slurpfile desired "$desired_file" \
    '$live[0] == $desired[0]' >/dev/null ||
    die "MoneyBee client configuration did not converge: $client_id"
done < <(jq -c '.clients[]' "$CONTRACT_FILE")

printf 'MONEYBEE_OIDC_MODE=APPLY\n'
printf 'MONEYBEE_OIDC_CREATED=%s\n' "$created_count"
printf 'MONEYBEE_OIDC_UPDATED=%s\n' "$updated_count"
printf 'MONEYBEE_OIDC_UNCHANGED=%s\n' "$noop_count"
printf 'MONEYBEE_OIDC_CHANGED=%s\n' "$changed_count"
printf 'MONEYBEE_OIDC_RECONCILE=APPLIED_AND_VERIFIED\n'
