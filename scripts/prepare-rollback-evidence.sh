#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_FILE=""
OUTPUT_DIR=""

usage() {
  cat <<'USAGE'
Usage: scripts/prepare-rollback-evidence.sh --plan PATH --output PATH

Creates rollback evidence for a reviewed protected plan:
- existing noop/update clients are exported through their reviewed field allowlists;
- reviewed create clients receive explicit absent-state, disable-first, and
  separate-reviewed-delete rollback metadata.

This script does not mutate Keycloak.
USAGE
}

while (($#)); do
  case "$1" in
    --plan)
      [[ $# -ge 2 ]] || { usage >&2; exit 64; }
      PLAN_FILE="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || { usage >&2; exit 64; }
      OUTPUT_DIR="$2"
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

[[ "$PLAN_FILE" == /* && -f "$PLAN_FILE" && ! -L "$PLAN_FILE" ]] || {
  echo 'ROLLBACK_EVIDENCE_ERROR=plan_must_be_absolute_regular_file' >&2
  exit 1
}
[[ "$OUTPUT_DIR" == /* && ! -L "$OUTPUT_DIR" ]] || {
  echo 'ROLLBACK_EVIDENCE_ERROR=output_must_be_absolute_non_symlink' >&2
  exit 1
}

"$ROOT_DIR/scripts/validate.sh"
jq -e '
  .schemaVersion == 1
  and (.clients | type == "array")
  and (.blockedCount == 0)
  and all(.clients[]; (.action == "noop" or .action == "update" or .action == "create"))
' "$PLAN_FILE" >/dev/null || {
  echo 'ROLLBACK_EVIDENCE_ERROR=reviewed_plan_is_not_apply_eligible' >&2
  exit 1
}

mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"

mapfile -t existing_clients < <(
  jq -r '.clients[] | select(.action == "noop" or .action == "update") | .clientId' "$PLAN_FILE" | sort
)

if ((${#existing_clients[@]} > 0)); then
  "$ROOT_DIR/scripts/export-client.sh" \
    --output "$OUTPUT_DIR" \
    "${existing_clients[@]}"
fi

plan_sha256="$(jq -S -c . "$PLAN_FILE" | sha256sum | awk '{print $1}')"
metadata_file="$OUTPUT_DIR/rollback-metadata.json"
jq -S \
  --arg plan_sha256 "$plan_sha256" '
    {
      schemaVersion: 1,
      repositorySha: .repositorySha,
      environment: .environment,
      targetRealm: .targetRealm,
      planSha256: $plan_sha256,
      existingClients: [
        .clients[]
        | select(.action == "noop" or .action == "update")
        | {
            clientId,
            plannedAction: .action,
            beforeSha256,
            rollback: {
              strategy: "restore_allowlisted_overlay_via_reviewed_plan",
              overlayPath: ("config/clients/" + .clientId + ".json"),
              requiresReviewedPlan: true
            }
          }
      ],
      createdClients: [
        .clients[]
        | select(.action == "create")
        | {
            clientId,
            plannedAction: .action,
            preApplyState: "absent",
            desiredSha256,
            rollback: {
              strategy: "disable_then_reviewed_delete",
              disablePatch: {enabled: false},
              disableFirst: true,
              deleteAllowedAfterDisable: true,
              deletionRequiresSeparateReviewedRollback: true,
              requiresReviewedPlan: true
            }
          }
      ]
    }
  ' "$PLAN_FILE" >"$metadata_file"
chmod 600 "$metadata_file"

jq -e '
  all(.createdClients[];
    .preApplyState == "absent"
    and .rollback.disablePatch == {"enabled": false}
    and .rollback.disableFirst == true
    and .rollback.deletionRequiresSeparateReviewedRollback == true
    and .rollback.requiresReviewedPlan == true
  )
  and all(.existingClients[]; .rollback.requiresReviewedPlan == true)
' "$metadata_file" >/dev/null || {
  echo 'ROLLBACK_EVIDENCE_ERROR=metadata_validation_failed' >&2
  exit 1
}

printf 'ROLLBACK_EVIDENCE=%s\n' "$OUTPUT_DIR"
printf 'ROLLBACK_PLAN_SHA256=%s\n' "$plan_sha256"
printf 'EXISTING_CLIENT_ROLLBACKS=%s\n' "${#existing_clients[@]}"
printf 'CREATED_CLIENT_ROLLBACKS=%s\n' "$(jq -er '.createdClients | length' "$metadata_file")"
printf 'ROLLBACK_EVIDENCE=READY\n'
