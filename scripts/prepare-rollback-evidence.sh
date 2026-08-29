#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
"$ROOT_DIR/scripts/validate.sh" >/dev/null
exec python3 "$ROOT_DIR/scripts/protected_identity_engine.py" prepare-rollback "$@"
