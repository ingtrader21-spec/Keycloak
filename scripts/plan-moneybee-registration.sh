#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/keycloak-admin.sh
source "$ROOT_DIR/scripts/lib/keycloak-admin.sh"

output_dir=''
expected_deploy_sha=''
while (($#)); do
  case "$1" in
    --output-dir) output_dir="$2"; shift 2 ;;
    --expected-deploy-sha) expected_deploy_sha="$2"; shift 2 ;;
    *) die "Unknown argument: $1" ;;
  esac
done
[[ -n "$output_dir" ]] || die '--output-dir is required'
[[ "$expected_deploy_sha" =~ ^[0-9a-f]{40}$ ]] || die '--expected-deploy-sha must be a 40-character SHA'
[[ "$(git -C "$ROOT_DIR" rev-parse HEAD)" == "$expected_deploy_sha" ]] || die 'Repository SHA mismatch'

mkdir -p "$output_dir"
chmod 700 "$output_dir"
keycloak_authenticate

realm_path="/admin/realms/$(urlencode "$KC_TARGET_REALM")"
auth_path="$realm_path/authentication"
keycloak_api GET "$realm_path" >"$output_dir/realm.json"
keycloak_api GET "$auth_path/form-action-providers" >"$output_dir/form-action-providers.json"
keycloak_api GET "$auth_path/required-actions" >"$output_dir/required-actions.json"
keycloak_api GET "$auth_path/unregistered-required-actions" >"$output_dir/unregistered-required-actions.json"
keycloak_api GET "$auth_path/flows" >"$output_dir/flows.json"

blocked=()
actions='[]'

if ! jq -e 'any(.[]; .id == "moneybee-registration-gate")' "$output_dir/form-action-providers.json" >/dev/null; then
  blocked+=("moneybee-registration-gate provider is not installed in the running Keycloak image")
fi

required_registered=false
if jq -e 'any(.[]; .alias == "moneybee-verify-email-otp")' "$output_dir/required-actions.json" >/dev/null; then
  required_registered=true
elif ! jq -e 'any(.[]; .providerId == "moneybee-verify-email-otp")' "$output_dir/unregistered-required-actions.json" >/dev/null; then
  blocked+=("moneybee-verify-email-otp provider is not installed in the running Keycloak image")
fi

if [[ "$required_registered" != true ]]; then
  actions="$(jq -c '. + [{action:"register_required_action", providerId:"moneybee-verify-email-otp"}]' <<<"$actions")"
fi

flow_exists=false
if jq -e 'any(.[]; .alias == "moneybee-registration")' "$output_dir/flows.json" >/dev/null; then
  flow_exists=true
  keycloak_api GET "$auth_path/flows/$(urlencode moneybee-registration)/executions" >"$output_dir/moneybee-registration-executions.json"

  gate_present=false
  gate_required_in_form=false
  if jq -e 'any(.[]; .providerId == "moneybee-registration-gate")' "$output_dir/moneybee-registration-executions.json" >/dev/null; then
    gate_present=true
  fi
  if jq -e 'any(.[];
      .providerId == "moneybee-registration-gate"
      and .requirement == "REQUIRED"
      and ((.authenticationFlow // false) == false)
      and ((.level // 0) > 0)
    )' "$output_dir/moneybee-registration-executions.json" >/dev/null; then
    gate_required_in_form=true
  fi

  if [[ "$gate_required_in_form" != true ]]; then
    if [[ "$gate_present" == true ]]; then
      blocked+=("moneybee-registration-gate exists but is not REQUIRED inside the registration-form scope")
    else
      actions="$(jq -c '. + [{action:"ensure_registration_gate", providerId:"moneybee-registration-gate", requirement:"REQUIRED", scope:"registration-form"}]' <<<"$actions")"
    fi
  fi
else
  actions="$(jq -c '. + [{action:"copy_registration_flow", source:"registration", target:"moneybee-registration"},{action:"ensure_registration_gate", providerId:"moneybee-registration-gate", requirement:"REQUIRED", scope:"registration-form"}]' <<<"$actions")"
fi

realm_changes='{}'
check_realm() {
  local field="$1" expected_json="$2"
  if ! jq -e --arg field "$field" --argjson expected "$expected_json" '.[$field] == $expected' "$output_dir/realm.json" >/dev/null; then
    realm_changes="$(jq -c --arg field "$field" --argjson expected "$expected_json" '. + {($field): $expected}' <<<"$realm_changes")"
  fi
}
check_realm registrationAllowed true
check_realm registrationEmailAsUsername true
check_realm loginWithEmailAllowed true
check_realm duplicateEmailsAllowed false
check_realm resetPasswordAllowed true
check_realm verifyEmail false
check_realm loginTheme '"codestra-identity"'
check_realm emailTheme '"codestra-identity"'
check_realm registrationFlow '"moneybee-registration"'

if [[ "$(jq 'length' <<<"$realm_changes")" -gt 0 ]]; then
  actions="$(jq -c --argjson changes "$realm_changes" '. + [{action:"update_realm", changes:$changes}]' <<<"$actions")"
fi

blocked_json='[]'
for value in "${blocked[@]:-}"; do
  [[ -n "$value" ]] || continue
  blocked_json="$(jq -c --arg value "$value" '. + [$value]' <<<"$blocked_json")"
done

jq -n \
  --arg repositorySha "$expected_deploy_sha" \
  --arg environment "${DEPLOY_ENVIRONMENT:-unknown}" \
  --arg realm "$KC_TARGET_REALM" \
  --argjson actions "$actions" \
  --argjson blocked "$blocked_json" \
  --argjson flowExists "$flow_exists" \
  '{
    schemaVersion: 1,
    repositorySha: $repositorySha,
    environment: $environment,
    realm: $realm,
    desiredRegistrationFlow: "moneybee-registration",
    existingRegistrationFlowPresent: $flowExists,
    actions: $actions,
    driftCount: ($actions | length),
    blocked: $blocked,
    blockedCount: ($blocked | length)
  }' >"$output_dir/plan.json"

jq -cS . "$output_dir/plan.json" >"$output_dir/plan.canonical.json"
(
  cd "$output_dir"
  sha256sum plan.canonical.json >plan.sha256
)
chmod 600 "$output_dir"/*
printf 'MONEYBEE_REGISTRATION_DRIFT=%s\n' "$(jq -r '.driftCount' "$output_dir/plan.json")"
printf 'MONEYBEE_REGISTRATION_BLOCKED=%s\n' "$(jq -r '.blockedCount' "$output_dir/plan.json")"
printf 'PLAN_SHA256=%s\n' "$(awk 'NR == 1 {print $1}' "$output_dir/plan.sha256")"
