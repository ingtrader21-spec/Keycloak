#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() { printf 'RESTORE_TEST_STATUS=FAILED\nRESTORE_TEST_ERROR=%s\n' "$*" >&2; exit 1; }
[[ $# -eq 1 ]] || fail "usage: verify-backup.sh /absolute/path/to/backup.sql.age"
backup="$1"
[[ "$backup" == /* && -f "$backup" && ! -L "$backup" ]] || fail "backup must be an absolute regular file"
checksum_file="${backup}.sha256"
[[ -f "$checksum_file" && ! -L "$checksum_file" ]] || fail "checksum must be a regular file"
: "${BACKUP_AGE_IDENTITY_FILE:?BACKUP_AGE_IDENTITY_FILE is required}"
: "${RESTORE_TEST_DATABASE_URL:?RESTORE_TEST_DATABASE_URL is required and must identify an isolated database}"
: "${RESTORE_TEST_PGPASSFILE:?RESTORE_TEST_PGPASSFILE is required}"
[[ "${ALLOW_DESTRUCTIVE_RESTORE_TEST:-}" == "isolated-database-confirmed" ]] ||
  fail "set ALLOW_DESTRUCTIVE_RESTORE_TEST=isolated-database-confirmed"
for command_name in age pg_restore sha256sum basename awk python3 stat id; do command -v "$command_name" >/dev/null || fail "missing command: $command_name"; done
[[ "$RESTORE_TEST_PGPASSFILE" == /* && -f "$RESTORE_TEST_PGPASSFILE" && ! -L "$RESTORE_TEST_PGPASSFILE" ]] ||
  fail "RESTORE_TEST_PGPASSFILE must be an absolute regular file"
case "$(stat -c '%a' "$RESTORE_TEST_PGPASSFILE")" in
  400|600) ;;
  *) fail "RESTORE_TEST_PGPASSFILE mode must be 0400 or 0600" ;;
esac
[[ "$(stat -c '%u' "$RESTORE_TEST_PGPASSFILE")" == "$(id -u)" ]] ||
  fail "RESTORE_TEST_PGPASSFILE must be owned by the restore account"
python3 - <<'PY' || fail "RESTORE_TEST_DATABASE_URL must be a credential-free PostgreSQL URI"
import os
from urllib.parse import parse_qsl, urlsplit

url = os.environ["RESTORE_TEST_DATABASE_URL"]
parsed = urlsplit(url)
query_keys = {key.casefold() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
valid = (
    parsed.scheme in {"postgres", "postgresql"}
    and parsed.username is not None
    and parsed.password is None
    and parsed.hostname is not None
    and parsed.path not in {"", "/"}
    and parsed.fragment == ""
    and not any("password" in key or "passfile" in key for key in query_keys)
)
raise SystemExit(0 if valid else 1)
PY
read -r expected_digest recorded_name extra <"$checksum_file" || fail "checksum record is unreadable"
[[ "$expected_digest" =~ ^[0-9a-f]{64}$ && "$recorded_name" == "$(basename -- "$backup")" && -z "${extra:-}" ]] ||
  fail "checksum record is not bound to the supplied backup"
actual_digest="$(sha256sum -- "$backup" | awk '{print $1}')"
[[ "$actual_digest" == "$expected_digest" ]] || fail "checksum mismatch"
age --decrypt --identity "$BACKUP_AGE_IDENTITY_FILE" "$backup" |
  PGPASSFILE="$RESTORE_TEST_PGPASSFILE" pg_restore --dbname="$RESTORE_TEST_DATABASE_URL" --clean --if-exists --no-owner --no-acl --exit-on-error
pg_restore --list <(age --decrypt --identity "$BACKUP_AGE_IDENTITY_FILE" "$backup") >/dev/null || fail "archive inventory failed"
printf 'RESTORE_TEST_STATUS=SUCCESS\nBACKUP_FILE=%s\n' "$backup"
