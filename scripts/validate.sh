#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_ROOT="${CONFIG_ROOT:-$ROOT_DIR/config}"
cd "$ROOT_DIR"

fail() {
  printf 'VALIDATION_ERROR=%s\n' "$*" >&2
  exit 1
}

for command_name in jq python3; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done
python3 -c 'import yaml' >/dev/null 2>&1 || fail "PyYAML is required"
[[ -d "$CONFIG_ROOT" ]] || fail "Configuration root does not exist: $CONFIG_ROOT"

mapfile -t json_files < <(find "$CONFIG_ROOT" -type f -name '*.json' -print | sort)
((${#json_files[@]} > 0)) || fail "No JSON configuration files were found under $CONFIG_ROOT"

for file in "${json_files[@]}"; do
  jq -e . "$file" >/dev/null || fail "Invalid JSON: $file"

  if ! jq -e '
    [
      paths(scalars) as $path
      | ($path[-1] | tostring | ascii_downcase) as $key
      | select(
          $key
          | test(
              "^(secret|clientsecret|client_secret|password|privatekey|private_key|access_token|accesstoken|refresh_token|refreshtoken|credential)$"
            )
        )
      | select((getpath($path) // "") != "")
    ]
    | length == 0
  ' "$file" >/dev/null; then
    fail "A prohibited secret-bearing field is populated in $file"
  fi
done

endpoint_file="$CONFIG_ROOT/endpoints/codestra.json"
[[ -f "$endpoint_file" ]] || fail "Canonical endpoint contract is missing"
jq -e '
  .publicUrl == "https://auth.codestra.co"
  and .adminApiBaseUrl == "https://auth.codestra.co"
  and .realm == "codestra"
  and .issuer == "https://auth.codestra.co/realms/codestra"
  and .discoveryUrl == "https://auth.codestra.co/realms/codestra/.well-known/openid-configuration"
  and .authorizationEndpoint == "https://auth.codestra.co/realms/codestra/protocol/openid-connect/auth"
  and .tokenEndpoint == "https://auth.codestra.co/realms/codestra/protocol/openid-connect/token"
  and .userInfoEndpoint == "https://auth.codestra.co/realms/codestra/protocol/openid-connect/userinfo"
  and .jwksUri == "https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs"
  and .introspectionEndpoint == "https://auth.codestra.co/realms/codestra/protocol/openid-connect/token/introspect"
  and .logoutEndpoint == "https://auth.codestra.co/realms/codestra/protocol/openid-connect/logout"
  and .adminRealmEndpoint == "https://auth.codestra.co/admin/realms/codestra"
' "$endpoint_file" >/dev/null || fail "Canonical Codestra API URLs are invalid"

legacy_host='auth.codestra'".agency"
if grep -RInF --exclude-dir=.git "$legacy_host" .; then
  fail "Legacy Codestra authentication hostname is prohibited"
fi

realm_file="$CONFIG_ROOT/realms/codestra.json"
[[ -f "$realm_file" ]] || fail "codestra realm invariant is missing"
jq -e '.realm == "codestra" and .enabled == true' "$realm_file" >/dev/null ||
  fail "codestra realm invariant must identify an enabled codestra realm"

managed_policy="$CONFIG_ROOT/policy/managed-clients.json"
[[ -f "$managed_policy" ]] || fail "Managed-client policy is missing"
jq -e '
  (.clients | type == "array" and length > 0)
  and ((.clients | unique | length) == (.clients | length))
  and (.clients == ["klyrow-portal"])
' "$managed_policy" >/dev/null ||
  fail "Normal protected deployment must remain scoped only to klyrow-portal"

ruleset_file="$CONFIG_ROOT/github/main-ruleset.json"
[[ -f "$ruleset_file" ]] || fail "Main-branch ruleset desired state is missing"
jq -e '
  .name == "Protect main"
  and .target == "branch"
  and .enforcement == "active"
  and (.conditions.ref_name.include == ["~DEFAULT_BRANCH"])
  and ([.rules[].type] | index("deletion") != null)
  and ([.rules[].type] | index("non_fast_forward") != null)
  and ([.rules[].type] | index("pull_request") != null)
  and ([.rules[].type] | index("required_status_checks") != null)
  and (
    [.rules[] | select(.type == "pull_request")][0].parameters
    | .required_approving_review_count == 1
      and .dismiss_stale_reviews_on_push == true
      and .require_last_push_approval == true
      and .required_review_thread_resolution == true
  )
  and (
    [.rules[] | select(.type == "required_status_checks")][0].parameters.required_status_checks
    | map(.context) == ["validate-source", "validate-merge-result"]
  )
' "$ruleset_file" >/dev/null || fail "Main-branch ruleset desired state is invalid"

machine_contract="$CONFIG_ROOT/contracts/machine-clients.json"
[[ -f "$machine_contract" ]] || fail "Machine-client identity contract is missing"
jq -e '
  .issuer == "https://auth.codestra.co/realms/codestra"
  and .grantType == "client_credentials"
  and (.maximumAccessTokenLifetimeSeconds | type == "number" and . > 0 and . <= 300)
  and (.clients | type == "array" and length == 12)
  and ((.clients | map(.clientId) | unique | length) == 12)
  and ([.clients[].clientId] == [
    "kong-gateway",
    "middleware-api",
    "middleware-worker",
    "odoo-integration",
    "n8n-automation",
    "vicidial-adapter",
    "telnexa-gateway",
    "klyrow-gateway",
    "kyqra-gateway",
    "postly-adapter",
    "provisioning-service",
    "monitoring-readonly"
  ])
  and all(
    .clients[];
    .clientType == "confidential"
    and .serviceAccountsEnabled == true
    and .standardFlowEnabled == false
    and .implicitFlowEnabled == false
    and .directAccessGrantsEnabled == false
    and (.audience == .clientId)
    and (.scopes | type == "array" and length == 1)
    and .provisioningState == "declared-not-created"
  )
' "$machine_contract" >/dev/null || fail "Machine-client identity contract is invalid"

client_dir="$CONFIG_ROOT/clients"
mapfile -t client_files < <(find "$client_dir" -maxdepth 1 -type f -name '*.json' -print | sort)
((${#client_files[@]} > 0)) || fail "No client configuration files were found"

mapfile -t declared_client_ids < <(jq -r '.clients[]' "$managed_policy" | sort)
mapfile -t configured_client_ids < <(
  for file in "${client_files[@]}"; do
    jq -er '.clientId' "$file"
  done | sort
)
[[ "${declared_client_ids[*]}" == "${configured_client_ids[*]}" ]] ||
  fail "Configured clients must exactly match the managed-client policy"

allowed_top_level_fields='[
  "clientId",
  "name",
  "description",
  "enabled",
  "protocol",
  "publicClient",
  "bearerOnly",
  "consentRequired",
  "standardFlowEnabled",
  "implicitFlowEnabled",
  "directAccessGrantsEnabled",
  "serviceAccountsEnabled",
  "frontchannelLogout",
  "rootUrl",
  "baseUrl",
  "redirectUris",
  "webOrigins",
  "attributes"
]'
allowed_attribute_fields='[
  "pkce.code.challenge.method",
  "post.logout.redirect.uris",
  "oauth2.device.authorization.grant.enabled",
  "oidc.ciba.grant.enabled"
]'

for file in "${client_files[@]}"; do
  client_id="$(jq -er '.clientId' "$file")"
  safe_client_id="$(printf '%s' "$client_id" | LC_ALL=C tr -c '[:alnum:]_.-' '_')"
  allowlist_file="$CONFIG_ROOT/export-allowlists/${safe_client_id}.json"

  jq -e '
    (.clientId | type == "string" and length > 0)
    and (.protocol == "openid-connect")
    and (.enabled == true)
    and (.redirectUris | type == "array" and length > 0)
    and (.webOrigins | type == "array" and length > 0)
    and ((.redirectUris | unique | length) == (.redirectUris | length))
    and ((.webOrigins | unique | length) == (.webOrigins | length))
  ' "$file" >/dev/null || fail "Invalid OIDC client shape: $file"

  if ! jq -e '
    [(.redirectUris[]?), (.webOrigins[]?)]
    | all(
        . != "*"
        and . != "+"
        and (endswith("/*") | not)
        and (
          startswith("https://")
          or startswith("http://localhost")
          or startswith("http://127.0.0.1")
        )
      )
  ' "$file" >/dev/null; then
    fail "Unsafe, wildcard, or non-HTTPS redirect/origin found in $file"
  fi

  if jq -e '.publicClient == true' "$file" >/dev/null; then
    jq -e '
      .standardFlowEnabled == true
      and .implicitFlowEnabled == false
      and .directAccessGrantsEnabled == false
      and .serviceAccountsEnabled == false
      and .attributes["pkce.code.challenge.method"] == "S256"
    ' "$file" >/dev/null ||
      fail "Public client must use Authorization Code + PKCE S256 only: $file"
  fi

  [[ -f "$allowlist_file" && ! -L "$allowlist_file" ]] ||
    fail "Client-specific export allowlist is missing: $allowlist_file"
  jq -e \
    --arg client_id "$client_id" \
    --argjson allowed_top "$allowed_top_level_fields" \
    --argjson allowed_attributes "$allowed_attribute_fields" '
      .clientId == $client_id
      and (.topLevelFields | type == "array" and length > 0)
      and (.attributeFields | type == "array")
      and ((.topLevelFields | unique | length) == (.topLevelFields | length))
      and ((.attributeFields | unique | length) == (.attributeFields | length))
      and ([.topLevelFields[] | select(($allowed_top | index(.)) == null)] | length == 0)
      and ([.attributeFields[] | select(($allowed_attributes | index(.)) == null)] | length == 0)
      and (.topLevelFields | index("clientId") != null)
      and (.topLevelFields | index("attributes") != null)
    ' "$allowlist_file" >/dev/null || fail "Unsafe export allowlist: $allowlist_file"

  mapfile -t desired_top_level < <(jq -r 'keys[]' "$file" | sort)
  mapfile -t allowlisted_top_level < <(jq -r '.topLevelFields[]' "$allowlist_file" | sort)
  [[ "${desired_top_level[*]}" == "${allowlisted_top_level[*]}" ]] ||
    fail "Export allowlist must exactly cover managed top-level fields for $client_id"

  mapfile -t desired_attributes < <(jq -r '.attributes | keys[]' "$file" | sort)
  mapfile -t allowlisted_attributes < <(jq -r '.attributeFields[]' "$allowlist_file" | sort)
  [[ "${desired_attributes[*]}" == "${allowlisted_attributes[*]}" ]] ||
    fail "Export allowlist must exactly cover managed attributes for $client_id"
done

while IFS= read -r script; do
  bash -n "$script" || fail "Bash syntax failed: $script"
done < <(find scripts -type f -name '*.sh' -print | sort)

if command -v shellcheck >/dev/null 2>&1; then
  mapfile -t shell_files < <(find scripts -type f -name '*.sh' -print | sort)
  shellcheck "${shell_files[@]}"
else
  printf 'VALIDATION_WARNING=shellcheck_not_installed\n'
fi

python3 "$ROOT_DIR/scripts/validate-workflows.py"

if grep -RInE --exclude-dir=.git \
  'BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY' .; then
  fail "Private key material must not be committed"
fi

if grep -RInE --include='*.sh' \
  '^[[:space:]]*(export[[:space:]]+)?(KC_ADMIN_CLIENT_SECRET|KC_ADMIN_PASSWORD|POSTGRES_PASSWORD)=[^$<[:space:]][^[:space:]]{7,}' \
  scripts; then
  fail "Potential hard-coded shell secret detected"
fi

yaml_secret_scan_roots=(.github)
[[ -f compose.yaml ]] && yaml_secret_scan_roots+=(compose.yaml)
if grep -RInE \
  --include='*.yml' \
  --include='*.yaml' \
  --exclude='.env.example' \
  '^[[:space:]]*(KC_ADMIN_CLIENT_SECRET|KC_ADMIN_PASSWORD|POSTGRES_PASSWORD):[[:space:]]*[^$<[:space:]][^[:space:]]{7,}' \
  "${yaml_secret_scan_roots[@]}"; then
  fail "Potential hard-coded YAML secret detected"
fi

"$ROOT_DIR/scripts/test-runtime-preflight.sh"

printf 'CONFIG_ROOT=%s\n' "$CONFIG_ROOT"
printf 'JSON_FILES=%s\n' "${#json_files[@]}"
printf 'CLIENT_FILES=%s\n' "${#client_files[@]}"
printf 'ENDPOINT_POLICY=PASS\n'
printf 'MACHINE_IDENTITY_CONTRACT=PASS\n'
printf 'GITHUB_RULESET_POLICY=PASS\n'
printf 'KEYCLOAK_POLICY=PASS\n'
printf 'VALIDATION=PASS\n'
