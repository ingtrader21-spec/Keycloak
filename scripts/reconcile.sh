#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  scripts/reconcile.sh --check --expected-deploy-sha SHA
  scripts/reconcile.sh --apply --plan PATH --expected-plan-sha SHA256 \
    --expected-deploy-sha SHA

--check generates a deterministic plan and exits 2 when drift exists.
--apply delegates to apply-plan.sh and cannot run without a reviewed plan hash.
Direct, unplanned mutation is intentionally unsupported.
USAGE
}

mode="${1:-}"
case "$mode" in
  --check)
    shift
    expected_sha=""
    while (($#)); do
      case "$1" in
        --expected-deploy-sha)
          [[ $# -ge 2 ]] || { usage >&2; exit 64; }
          expected_sha="$2"
          shift 2
          ;;
        *)
          usage >&2
          exit 64
          ;;
      esac
    done
    [[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]] || {
      usage >&2
      exit 64
    }
    output_dir="$(mktemp -d)"
    trap 'rm -rf "$output_dir"' EXIT
    "$ROOT_DIR/scripts/plan.sh" \
      --output-dir "$output_dir" \
      --expected-deploy-sha "$expected_sha"
    drift_count="$(jq -er '.driftCount' "$output_dir/plan.json")"
    if [[ "$drift_count" -gt 0 ]]; then
      printf 'RECONCILE=DRIFT\n'
      exit 2
    fi
    printf 'RECONCILE=IN_SYNC\n'
    ;;
  --apply)
    shift
    exec "$ROOT_DIR/scripts/apply-plan.sh" "$@"
    ;;
  -h | --help)
    usage
    ;;
  *)
    usage >&2
    exit 64
    ;;
esac
