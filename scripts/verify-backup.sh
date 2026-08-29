#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() { printf 'RESTORE_TEST_STATUS=FAILED\nRESTORE_TEST_ERROR=%s\n' "$*" >&2; exit 1; }
[[ $# -eq 1 ]] || fail "usage: verify-backup.sh /absolute/path/to/backup.sql.age"
backup="$1"
[[ "$backup" == /* && -f "$backup" && ! -L "$backup" ]] || fail "backup must be an absolute regular file"
: "${BACKUP_AGE_IDENTITY_FILE:?BACKUP_AGE_IDENTITY_FILE is required}"
: "${RESTORE_TEST_DATABASE_URL:?RESTORE_TEST_DATABASE_URL is required and must identify an isolated database}"
[[ "${ALLOW_DESTRUCTIVE_RESTORE_TEST:-}" == "isolated-database-confirmed" ]] ||
  fail "set ALLOW_DESTRUCTIVE_RESTORE_TEST=isolated-database-confirmed"
for command_name in age pg_restore sha256sum; do command -v "$command_name" >/dev/null || fail "missing command: $command_name"; done
sha256sum --check "${backup}.sha256" >/dev/null || fail "checksum mismatch"
age --decrypt --identity "$BACKUP_AGE_IDENTITY_FILE" "$backup" |
  pg_restore --dbname="$RESTORE_TEST_DATABASE_URL" --clean --if-exists --no-owner --no-acl --exit-on-error
pg_restore --list <(age --decrypt --identity "$BACKUP_AGE_IDENTITY_FILE" "$backup") >/dev/null || fail "archive inventory failed"
printf 'RESTORE_TEST_STATUS=SUCCESS\nBACKUP_FILE=%s\n' "$backup"
