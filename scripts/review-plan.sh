#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_FILE=""
EXPECTED_PLAN_SHA256=""
EXPECTED_DEPLOY_SHA=""
OUTPUT_FILE=""
DEPLOY_ENVIRONMENT="${DEPLOY_ENVIRONMENT:-}"

die() { printf 'REVIEW_ERROR=%s\n' "$*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    --plan) PLAN_FILE="${2:-}"; shift 2 ;;
    --expected-plan-sha) EXPECTED_PLAN_SHA256="${2:-}"; shift 2 ;;
    --expected-deploy-sha) EXPECTED_DEPLOY_SHA="${2:-}"; shift 2 ;;
    --output) OUTPUT_FILE="${2:-}"; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$PLAN_FILE" == /* && -f "$PLAN_FILE" && ! -L "$PLAN_FILE" ]] || die "plan must be an absolute regular non-symlink file"
[[ "$OUTPUT_FILE" == /* && ! -L "$OUTPUT_FILE" ]] || die "output must be an absolute non-symlink path"
[[ "$EXPECTED_PLAN_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "invalid expected plan hash"
[[ "$EXPECTED_DEPLOY_SHA" =~ ^[0-9a-f]{40}$ ]] || die "invalid expected deployment SHA"
[[ "$DEPLOY_ENVIRONMENT" == staging || "$DEPLOY_ENVIRONMENT" == production ]] || die "invalid deployment environment"
[[ "${KEYCLOAK_REVIEWER_ID:-}" =~ ^[A-Za-z0-9_.@-]{3,128}$ ]] || die "KEYCLOAK_REVIEWER_ID is required"
[[ "${KEYCLOAK_CHANGE_AUTHOR_ID:-}" =~ ^[A-Za-z0-9_.@-]{3,128}$ ]] || die "KEYCLOAK_CHANGE_AUTHOR_ID is required"
[[ "$KEYCLOAK_REVIEWER_ID" != "$KEYCLOAK_CHANGE_AUTHOR_ID" ]] || die "reviewer must be independent from change author"
[[ "${KEYCLOAK_CHANGE_TICKET:-}" =~ ^[A-Za-z0-9_.:/-]{3,128}$ ]] || die "KEYCLOAK_CHANGE_TICKET is required"

"$ROOT_DIR/scripts/validate.sh" >/dev/null
actual_plan_sha256="$(jq -S -c . "$PLAN_FILE" | sha256sum | awk '{print $1}')"
[[ "$actual_plan_sha256" == "$EXPECTED_PLAN_SHA256" ]] || die "plan hash mismatch"

jq -e \
  --arg sha "$EXPECTED_DEPLOY_SHA" \
  --arg environment "$DEPLOY_ENVIRONMENT" '
    .schemaVersion == 1
    and .repositorySha == $sha
    and .environment == $environment
    and .targetRealm == "codestra"
    and .blockedCount == 0
    and (.clients | length > 0)
    and all(.clients[]; .action == "noop" or .action == "create" or .action == "update")
  ' "$PLAN_FILE" >/dev/null || die "plan is not eligible for review"

mkdir -p "$(dirname -- "$OUTPUT_FILE")"
jq -S -c -n \
  --arg planSha256 "$EXPECTED_PLAN_SHA256" \
  --arg repositorySha "$EXPECTED_DEPLOY_SHA" \
  --arg environment "$DEPLOY_ENVIRONMENT" \
  --arg reviewer "$KEYCLOAK_REVIEWER_ID" \
  --arg author "$KEYCLOAK_CHANGE_AUTHOR_ID" \
  --arg ticket "$KEYCLOAK_CHANGE_TICKET" \
  --slurpfile plan "$PLAN_FILE" '
    {
      schemaVersion: 1,
      decision: "approved",
      planSha256: $planSha256,
      repositorySha: $repositorySha,
      environment: $environment,
      targetRealm: "codestra",
      reviewerId: $reviewer,
      changeAuthorId: $author,
      changeTicket: $ticket,
      reviewedActions: [
        $plan[0].clients[] | {
          clientId,
          action,
          beforeSha256,
          desiredSha256
        }
      ]
    }
  ' >"$OUTPUT_FILE"
chmod 600 "$OUTPUT_FILE"
review_sha256="$(sha256sum "$OUTPUT_FILE" | awk '{print $1}')"
printf '%s  %s\n' "$review_sha256" "$(basename -- "$OUTPUT_FILE")" >"${OUTPUT_FILE}.sha256"
chmod 600 "${OUTPUT_FILE}.sha256"

printf 'REVIEW_FILE=%s\n' "$OUTPUT_FILE"
printf 'REVIEW_SHA256=%s\n' "$review_sha256"
printf 'PLAN_SHA256=%s\n' "$EXPECTED_PLAN_SHA256"
printf 'DRIFT_REVIEW=APPROVED\n'
