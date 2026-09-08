#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  printf 'GOVERNANCE_VALIDATION_ERROR=%s\n' "$*" >&2
  exit 1
}

for command_name in awk jq; do
  command -v "$command_name" >/dev/null 2>&1 ||
    fail "$command_name is required"
done

codeowners_file="$ROOT_DIR/.github/CODEOWNERS"
bootstrap_ruleset="$ROOT_DIR/config/github/bootstrap-main-ruleset.json"
final_ruleset="$ROOT_DIR/config/github/main-ruleset.json"

[[ -f "$codeowners_file" && ! -L "$codeowners_file" ]] ||
  fail "CODEOWNERS must be a regular non-symlink file"
[[ -f "$bootstrap_ruleset" && ! -L "$bootstrap_ruleset" ]] ||
  fail "Bootstrap main ruleset is missing"
[[ -f "$final_ruleset" && ! -L "$final_ruleset" ]] ||
  fail "Final main ruleset is missing"

declare -a protected_patterns=(
  '*'
  '/config/'
  '/.github/workflows/'
  '/scripts/'
  '/deploy/'
  '/docs/GITHUB_SECURITY.md'
  '/docs/SERVER_GIT_SSH.md'
)

for protected_pattern in "${protected_patterns[@]}"; do
  awk -v expected_pattern="$protected_pattern" '
    $1 == expected_pattern {
      primary_owner = 0
      independent_owner = 0
      for (field = 2; field <= NF; field += 1) {
        if ($field == "@appolon1908-hue") {
          primary_owner = 1
        }
        if ($field == "@kazan555") {
          independent_owner = 1
        }
      }
      if (primary_owner == 1 && independent_owner == 1) {
        matched = 1
      }
    }
    END {
      exit(matched == 1 ? 0 : 1)
    }
  ' "$codeowners_file" ||
    fail "CODEOWNERS pattern ${protected_pattern} must include @appolon1908-hue and @kazan555"
done

validate_ruleset() {
  local ruleset_file="$1"
  local expected_name="$2"
  local expected_codeowner_requirement="$3"

  jq -e \
    --arg expected_name "$expected_name" \
    --argjson expected_codeowner_requirement "$expected_codeowner_requirement" '
      .name == $expected_name
      and .target == "branch"
      and .enforcement == "active"
      and .bypass_actors == []
      and .conditions.ref_name.include == ["~DEFAULT_BRANCH"]
      and .conditions.ref_name.exclude == []
      and ([.rules[].type] | sort) == [
        "deletion",
        "non_fast_forward",
        "pull_request",
        "required_status_checks"
      ]
      and (
        [.rules[] | select(.type == "pull_request")][0].parameters
        | .required_approving_review_count == 1
          and .dismiss_stale_reviews_on_push == true
          and .require_code_owner_review == $expected_codeowner_requirement
          and .require_last_push_approval == true
          and .required_review_thread_resolution == true
          and .allowed_merge_methods == ["squash"]
      )
      and (
        [.rules[] | select(.type == "required_status_checks")][0].parameters
        | .strict_required_status_checks_policy == true
          and .do_not_enforce_on_create == false
          and (.required_status_checks | map({context, integration_id})) == [
            {"context":"validate", "integration_id":15368},
            {"context":"validate-merge-result", "integration_id":15368},
            {"context":"orchestrator-contract", "integration_id":15368}
          ]
      )
    ' "$ruleset_file" >/dev/null ||
    fail "Invalid ruleset policy: $ruleset_file"
}

validate_ruleset "$bootstrap_ruleset" "Bootstrap protect main" false
validate_ruleset "$final_ruleset" "Protect main" true

printf 'CODEOWNERS_POLICY=PASS\n'
printf 'BOOTSTRAP_RULESET_POLICY=PASS\n'
printf 'FINAL_RULESET_POLICY=PASS\n'
printf 'GOVERNANCE_VALIDATION=PASS\n'
