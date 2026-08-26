#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_ROOT="${CONFIG_ROOT:-$ROOT_DIR/config}"
cd "$ROOT_DIR"

fail() {
  printf 'VALIDATION_ERROR=%s\n' "$*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
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

realm_file="$CONFIG_ROOT/realms/codestra.json"
if [[ -f "$realm_file" ]]; then
  jq -e '.realm == "codestra" and .enabled == true' "$realm_file" >/dev/null ||
    fail "codestra realm overlay must identify an enabled codestra realm"
fi

client_dir="$CONFIG_ROOT/clients"
if [[ -d "$client_dir" ]]; then
  mapfile -t client_files < <(find "$client_dir" -maxdepth 1 -type f -name '*.json' -print | sort)
else
  client_files=()
fi
((${#client_files[@]} > 0)) || fail "No client configuration files were found"

for file in "${client_files[@]}"; do
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
    [
      (.redirectUris[]?),
      (.webOrigins[]?)
    ]
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

if grep -RInE --exclude-dir=.git \
  'BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY' .; then
  fail "Private key material must not be committed"
fi

if grep -RInE --include='*.sh' \
  '^[[:space:]]*(export[[:space:]]+)?(KC_ADMIN_CLIENT_SECRET|KC_ADMIN_PASSWORD|POSTGRES_PASSWORD)=[^$<[:space:]][^[:space:]]{7,}' \
  scripts; then
  fail "Potential hard-coded shell secret detected"
fi

if grep -RInE \
  --include='*.yml' \
  --include='*.yaml' \
  --exclude='.env.example' \
  '^[[:space:]]*(KC_ADMIN_CLIENT_SECRET|KC_ADMIN_PASSWORD|POSTGRES_PASSWORD):[[:space:]]*[^$<[:space:]][^[:space:]]{7,}' \
  .github compose.yaml; then
  fail "Potential hard-coded YAML secret detected"
fi

printf 'CONFIG_ROOT=%s\n' "$CONFIG_ROOT"
printf 'JSON_FILES=%s\n' "${#json_files[@]}"
printf 'CLIENT_FILES=%s\n' "${#client_files[@]}"
printf 'KEYCLOAK_POLICY=PASS\n'
printf 'VALIDATION=PASS\n'
