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

python3 "$ROOT_DIR/scripts/validate-authority-controls.py"
python3 "$ROOT_DIR/scripts/validate-provider-control-authority.py"
python3 -m unittest discover -s "$ROOT_DIR/tests" -p 'test_provider_control_authority.py' -v
"$ROOT_DIR/scripts/test-backup-contract.sh"

mapfile -t json_files < <(find "$CONFIG_ROOT" -type f -name '*.json' -print | sort)
((${#json_files[@]} > 0)) || fail "No JSON configuration files were found under $CONFIG_ROOT"
for file in "${json_files[@]}"; do
  jq -e . "$file" >/dev/null || fail "Invalid JSON: $file"
  if ! jq -e '
    [
      paths(scalars) as $path
      | ($path[-1] | tostring | ascii_downcase) as $key
      | select($key | test("^(secret|clientsecret|client_secret|password|privatekey|private_key|access_token|accesstoken|refresh_token|refreshtoken|credential)$"))
      | select((getpath($path) // "") != "")
    ] | length == 0
  ' "$file" >/dev/null; then
    fail "A prohibited secret-bearing field is populated in $file"
  fi
done

endpoint_file="$CONFIG_ROOT/endpoints/codestra.json"
staging_endpoint_file="$CONFIG_ROOT/endpoints/codestra-staging.json"
realm_file="$CONFIG_ROOT/realms/codestra.json"
for file in "$endpoint_file" "$staging_endpoint_file" "$realm_file"; do
  [[ -f "$file" ]] || fail "Required identity document is missing: $file"
done

jq -e '
  .publicUrl == "https://auth.codestra.co"
  and .adminApiBaseUrl == "https://auth.codestra.co"
  and .realm == "codestra"
  and .issuer == "https://auth.codestra.co/realms/codestra"
  and .discoveryUrl == "https://auth.codestra.co/realms/codestra/.well-known/openid-configuration"
  and .tokenEndpoint == "https://auth.codestra.co/realms/codestra/protocol/openid-connect/token"
  and .jwksUri == "https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs"
' "$endpoint_file" >/dev/null || fail "Canonical Codestra endpoint contract is invalid"

jq -e '
  .publicUrl == "https://auth-staging.codestra.co"
  and .adminApiBaseUrl == "https://auth-staging.codestra.co"
  and .realm == "codestra"
  and .adminAuthenticationRealm == "master"
  and .issuer == "https://auth-staging.codestra.co/realms/codestra"
  and .tokenEndpoint == "https://auth-staging.codestra.co/realms/codestra/protocol/openid-connect/token"
  and .jwksUri == "https://auth-staging.codestra.co/realms/codestra/protocol/openid-connect/certs"
' "$staging_endpoint_file" >/dev/null || fail "Canonical staging endpoint contract is invalid"

jq -e '.realm == "codestra" and .enabled == true' "$realm_file" >/dev/null ||
  fail "codestra realm invariant is invalid"

legacy_host='auth.codestra'".agency"
if grep -RInF --exclude-dir=.git "$legacy_host" .; then
  fail "Legacy Codestra authentication hostname is prohibited"
fi

managed_policy="$CONFIG_ROOT/policy/managed-clients.json"
creatable_policy="$CONFIG_ROOT/policy/creatable-clients.json"
[[ -f "$managed_policy" && -f "$creatable_policy" ]] ||
  fail "Managed/creatable client policy is missing"

expected_managed='[
  "ai-provider-adapter",
  "alertmanager",
  "beyvra-backend",
  "breero-backend",
  "codestra-ai",
  "codestra-communication",
  "codestra-marketing",
  "codestra-social",
  "klyrow-portal",
  "kong-gateway",
  "klyrow-gateway",
  "kyqra-gateway",
  "larim-a-backend",
  "marketing-provider-adapter",
  "middleware-api",
  "middleware-worker",
  "monitoring-readonly",
  "moneybee-admin",
  "moneybee-backend",
  "moneybee-borrower",
  "moneybee-lender",
  "n8n-automation",
  "n8n-editor-gateway",
  "odoo-integration",
  "postly-adapter",
  "provisioning-service",
  "sdk-intake",
  "social-codestra",
  "telnexa-gateway",
  "transportation-backend",
  "vicidial-adapter"
]'

jq -e --argjson expected "$expected_managed" '
  (.clients | type == "array")
  and ((.clients | unique | length) == (.clients | length))
  and .clients == $expected
' "$managed_policy" >/dev/null ||
  fail "Protected managed-client policy must contain the reviewed browser and machine clients in canonical order"
jq -e --slurpfile managed "$managed_policy" '
  (.clients | type == "array")
  and .clients == $managed[0].clients
' "$creatable_policy" >/dev/null ||
  fail "Creatable-client policy must exactly match managed-client policy"

mapfile -t declared_client_ids < <(jq -r '.clients[]' "$managed_policy" | sort)
mapfile -t configured_client_ids < <(
  find "$CONFIG_ROOT/clients" -maxdepth 1 -type f -name '*.json' -print0 |
    sort -z |
    xargs -0 -r -n1 jq -er '.clientId' |
    sort
)
[[ "${declared_client_ids[*]}" == "${configured_client_ids[*]}" ]] ||
  fail "Configured clients must exactly match managed-client policy"

allowed_top_level_fields='[
  "clientId","name","description","enabled","protocol","publicClient","bearerOnly",
  "consentRequired","standardFlowEnabled","implicitFlowEnabled",
  "directAccessGrantsEnabled","serviceAccountsEnabled",
  "authorizationServicesEnabled","frontchannelLogout","fullScopeAllowed",
  "rootUrl","baseUrl","redirectUris","webOrigins","defaultClientScopes",
  "optionalClientScopes","attributes","protocolMappers"
]'
allowed_attribute_fields='[
  "pkce.code.challenge.method","post.logout.redirect.uris",
  "oauth2.device.authorization.grant.enabled","oidc.ciba.grant.enabled",
  "access.token.lifespan"
]'

for file in "$CONFIG_ROOT"/clients/*.json; do
  client_id="$(jq -er '.clientId' "$file")"
  allowlist_file="$CONFIG_ROOT/export-allowlists/${client_id}.json"
  [[ -f "$allowlist_file" && ! -L "$allowlist_file" ]] ||
    fail "Client-specific export allowlist is missing: $allowlist_file"

  jq -e '
    .protocol == "openid-connect"
    and .enabled == true
    and (.redirectUris | type == "array")
    and (.webOrigins | type == "array")
    and (
      if .serviceAccountsEnabled == true then
        .publicClient == false
        and .standardFlowEnabled == false
        and .implicitFlowEnabled == false
        and .directAccessGrantsEnabled == false
        and .fullScopeAllowed == false
        and (.redirectUris | length == 0)
        and (.webOrigins | length == 0)
        and ((.attributes["access.token.lifespan"] | tonumber) <= 300)
      else
        (.redirectUris | length > 0) and (.webOrigins | length > 0)
      end
    )
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
    ' "$file" >/dev/null || fail "Public client must use Authorization Code + PKCE S256 only: $file"
  fi

  case "$client_id" in
    moneybee-admin | moneybee-borrower | moneybee-lender)
      jq -e '
        (.protocolMappers | type == "array" and length == 1)
        and .protocolMappers[0].name == "moneybee-api-audience"
        and .protocolMappers[0].protocol == "openid-connect"
        and .protocolMappers[0].protocolMapper == "oidc-audience-mapper"
        and .protocolMappers[0].consentRequired == false
        and .protocolMappers[0].config["included.custom.audience"] == "moneybee-api"
        and .protocolMappers[0].config["access.token.claim"] == "true"
        and .protocolMappers[0].config["id.token.claim"] == "false"
      ' "$file" >/dev/null || fail "MoneyBee portal must emit the moneybee-api access-token audience: $file"
      ;;
    klyrow-portal)
      jq -e 'has("protocolMappers") | not' "$file" >/dev/null ||
        fail "Klyrow desired state changed unexpectedly"
      ;;
    n8n-editor-gateway)
      jq -e '
        .publicClient == false
        and .standardFlowEnabled == true
        and .implicitFlowEnabled == false
        and .directAccessGrantsEnabled == false
        and .serviceAccountsEnabled == false
        and .fullScopeAllowed == false
        and .rootUrl == "https://n8n.codestra.co"
        and .baseUrl == "https://n8n.codestra.co/"
        and .redirectUris == [
          "https://n8n.codestra.co/oauth2/callback",
          "https://n8n-staging.codestra.co/oauth2/callback"
        ]
        and .webOrigins == [
          "https://n8n.codestra.co",
          "https://n8n-staging.codestra.co"
        ]
        and .attributes["pkce.code.challenge.method"] == "S256"
        and .attributes["access.token.lifespan"] == "300"
        and .attributes["post.logout.redirect.uris"] == "https://n8n.codestra.co/##https://n8n-staging.codestra.co/"
      ' "$file" >/dev/null || fail "n8n editor gateway must be confidential Authorization Code + PKCE only"
      ;;
  esac

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
    ' "$allowlist_file" >/dev/null || fail "Unsafe export allowlist: $allowlist_file"

  mapfile -t desired_top_level < <(jq -r 'keys[]' "$file" | sort)
  mapfile -t allowlisted_top_level < <(jq -r '.topLevelFields[]' "$allowlist_file" | sort)
  [[ "${desired_top_level[*]}" == "${allowlisted_top_level[*]}" ]] ||
    fail "Export allowlist must exactly cover managed top-level fields for $client_id"

  mapfile -t desired_attributes < <(jq -r '.attributes | keys[]?' "$file" | sort)
  mapfile -t allowlisted_attributes < <(jq -r '.attributeFields[]' "$allowlist_file" | sort)
  [[ "${desired_attributes[*]}" == "${allowlisted_attributes[*]}" ]] ||
    fail "Export allowlist must exactly cover managed attributes for $client_id"
done

ruleset_file="$CONFIG_ROOT/github/main-ruleset.json"
jq -e '
  .name == "Protect main"
  and .target == "branch"
  and .enforcement == "active"
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
    | map({context, integration_id}) == [
        {"context":"validate", "integration_id":15368},
        {"context":"orchestrator-contract", "integration_id":15368}
      ]
  )
' "$ruleset_file" >/dev/null || fail "Main-branch ruleset desired state is invalid"

python3 "$ROOT_DIR/scripts/validate-service-integrations.py"
python3 -m unittest discover -s "$ROOT_DIR/tests" -p 'test_platform_api_identities.py' -v
python3 "$ROOT_DIR/scripts/render-machine-client-overlays.py" --check
python3 "$ROOT_DIR/scripts/validate-moneybee-oidc-contract.py"
python3 "$ROOT_DIR/scripts/validate-domain-application-registry.py"
python3 "$ROOT_DIR/scripts/validate-beyvra-oidc-contract.py"
python3 "$ROOT_DIR/scripts/validate-product-middleware-clients.py"
python3 "$ROOT_DIR/scripts/observability_desired_state.py" --check
python3 -m unittest discover -s "$ROOT_DIR/tests" -p 'test_observability_desired_state.py' -v

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
python3 "$ROOT_DIR/scripts/validate-runtime-security.py"
python3 "$ROOT_DIR/scripts/validate-machine-secret-contract.py"
python3 "$ROOT_DIR/scripts/validate-password-reset-e2e.py"
python3 "$ROOT_DIR/scripts/validate-realm-security-policy.py"

if grep -RInE --exclude-dir=.git 'BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY' .; then
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
  --include='*.yml' --include='*.yaml' --exclude='.env.example' \
  '^[[:space:]]*(KC_ADMIN_CLIENT_SECRET|KC_ADMIN_PASSWORD|POSTGRES_PASSWORD):[[:space:]]*[^$<[:space:]][^[:space:]]{7,}' \
  "${yaml_secret_scan_roots[@]}"; then
  fail "Potential hard-coded YAML secret detected"
fi

"$ROOT_DIR/scripts/test-runtime-preflight.sh"
"$ROOT_DIR/scripts/test-ephemeral-docker-auth.sh"

printf 'CONFIG_ROOT=%s\n' "$CONFIG_ROOT"
printf 'JSON_FILES=%s\n' "${#json_files[@]}"
printf 'CLIENT_FILES=%s\n' "${#configured_client_ids[@]}"
printf 'MACHINE_CLIENTS=%s\n' "$(jq '.clients | length' "$CONFIG_ROOT/contracts/machine-clients.json")"
printf 'SDK_INTAKE_IDENTITY=PASS\n'
printf 'ALERTMANAGER_WRITE_ONLY_IDENTITY=PASS\n'
printf 'STATIC_SHARED_TENANT_MAPPERS=0\n'
printf 'ENDPOINT_POLICY=PASS\n'
printf 'MANAGED_CLIENT_POLICY=PASS\n'
printf 'CREATABLE_CLIENT_POLICY=PASS\n'
printf 'GITHUB_RULESET_POLICY=PASS\n'
printf 'KEYCLOAK_POLICY=PASS\n'
printf 'VALIDATION=PASS\n'
