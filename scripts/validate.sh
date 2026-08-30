#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
  printf 'VALIDATION_ERROR=%s\n' "$*" >&2
  exit 1
}

for command_name in jq python3 shellcheck; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done
python3 -c 'import yaml' >/dev/null 2>&1 || fail 'PyYAML is required'

python3 -m py_compile \
  scripts/observability_identity_policy.py \
  scripts/protected_identity_engine.py \
  scripts/validate-source.py \
  scripts/validate-observability-oidc-contract.py \
  scripts/validate-observability-managed-identities.py \
  scripts/test-protected-identity-engine.py \
  scripts/protected_identity_test_server.py \
  scripts/protected_identity/*.py

python3 scripts/validate-source.py
python3 scripts/render-machine-client-overlays.py --check
python3 scripts/validate-observability-oidc-contract.py
python3 scripts/validate-observability-managed-identities.py
python3 scripts/validate-moneybee-oidc-contract.py
python3 scripts/validate-domain-application-registry.py
python3 scripts/validate-beyvra-oidc-contract.py
python3 scripts/validate-product-middleware-clients.py
python3 scripts/validate-service-integrations.py
python3 scripts/validate-kong-oidc-contract.py
python3 scripts/validate-n8n-flow.py
python3 scripts/validate-password-reset-contract.py
python3 scripts/validate-workflows.py

legacy_host='auth.codestra'".agency"
if grep -RInF --exclude-dir=.git --exclude='*.pyc' "$legacy_host" .; then
  fail 'legacy Codestra authentication hostname is prohibited'
fi

mapfile -t shell_files < <(find scripts -type f -name '*.sh' -print | sort)
((${#shell_files[@]} > 0)) || fail 'no shell scripts found'
shellcheck "${shell_files[@]}"

printf 'JSON_CONFIGURATION=PASS\n'
printf 'PROTECTED_CLIENT_PLAN_REVIEW_APPLY=PASS\n'
printf 'PROTECTED_REALM_ROLE_PLAN_REVIEW_APPLY=PASS\n'
printf 'CLIENT_SECRET_REDACTION=PASS\n'
printf 'VALIDATION=PASS\n'
