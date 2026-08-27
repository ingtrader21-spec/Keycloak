#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_DEPLOY_SHA=""

usage() {
  cat <<'USAGE'
Usage: scripts/reconcile-moneybee-oidc.sh [--plan] --expected-deploy-sha SHA

Read-only MoneyBee diagnostic helper. It delegates to the protected generic
plan engine, filters the resulting plan to the three MoneyBee portal clients,
and performs no writes.

Production writes are intentionally prohibited here. Use the protected
"Deploy Keycloak configuration" workflow check -> reviewed plan hash -> apply
path on a reviewed main-branch SHA.
USAGE
}

while (($#)); do
  case "$1" in
    --plan)
      shift
      ;;
    --apply)
      echo 'MONEYBEE_OIDC_ERROR=independent_apply_path_is_prohibited' >&2
      echo 'MONEYBEE_OIDC_APPLY=USE_PROTECTED_DEPLOY_WORKFLOW' >&2
      exit 1
      ;;
    --expected-deploy-sha)
      [[ $# -ge 2 ]] || { usage >&2; exit 64; }
      EXPECTED_DEPLOY_SHA="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 64
      ;;
  esac
done

[[ "$EXPECTED_DEPLOY_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'MONEYBEE_OIDC_ERROR=expected_deploy_sha_invalid' >&2
  exit 1
}
current_sha="$(git -C "$ROOT_DIR" rev-parse HEAD)"
[[ "$current_sha" == "$EXPECTED_DEPLOY_SHA" ]] || {
  echo 'MONEYBEE_OIDC_ERROR=checked_out_sha_does_not_match_expected_sha' >&2
  exit 1
}
[[ -z "$(git -C "$ROOT_DIR" status --short)" ]] || {
  echo 'MONEYBEE_OIDC_ERROR=working_tree_must_be_clean' >&2
  exit 1
}

python3 "$ROOT_DIR/scripts/validate-moneybee-oidc-contract.py"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
plan_dir="$tmp_dir/plan"

"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$plan_dir" \
  --expected-deploy-sha "$EXPECTED_DEPLOY_SHA" >/dev/null

jq -c '
  .clients[]
  | select(.clientId == "moneybee-admin" or .clientId == "moneybee-borrower" or .clientId == "moneybee-lender")
  | {
      clientId,
      action,
      beforeSha256,
      desiredSha256,
      rollback
    }
' "$plan_dir/plan.json" |
while IFS= read -r item; do
  printf 'MONEYBEE_OIDC_PLAN=%s\n' "$item"
done

moneybee_blocked="$(jq '[.clients[] | select((.clientId | startswith("moneybee-")) and .action == "blocked_missing")] | length' "$plan_dir/plan.json")"
moneybee_create="$(jq '[.clients[] | select((.clientId | startswith("moneybee-")) and .action == "create")] | length' "$plan_dir/plan.json")"
moneybee_update="$(jq '[.clients[] | select((.clientId | startswith("moneybee-")) and .action == "update")] | length' "$plan_dir/plan.json")"
moneybee_noop="$(jq '[.clients[] | select((.clientId | startswith("moneybee-")) and .action == "noop")] | length' "$plan_dir/plan.json")"

printf 'MONEYBEE_OIDC_MODE=DIAGNOSTIC_ONLY\n'
printf 'MONEYBEE_OIDC_BLOCKED=%s\n' "$moneybee_blocked"
printf 'MONEYBEE_OIDC_CREATE=%s\n' "$moneybee_create"
printf 'MONEYBEE_OIDC_UPDATE=%s\n' "$moneybee_update"
printf 'MONEYBEE_OIDC_NOOP=%s\n' "$moneybee_noop"
printf 'MONEYBEE_OIDC_WRITES=0\n'
printf 'MONEYBEE_OIDC_APPLY=PROTECTED_DEPLOY_WORKFLOW_ONLY\n'
