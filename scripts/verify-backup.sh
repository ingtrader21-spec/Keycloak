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
: "${RESTORE_EVIDENCE_DIR:?RESTORE_EVIDENCE_DIR is required}"
: "${SOURCE_DATABASE_NAME:?SOURCE_DATABASE_NAME is required}"
[[ "${ALLOW_DESTRUCTIVE_RESTORE_TEST:-}" == "isolated-database-confirmed" ]] ||
  fail "set ALLOW_DESTRUCTIVE_RESTORE_TEST=isolated-database-confirmed"
for command_name in age pg_restore psql sha256sum basename awk python3 stat id install flock sync date mv; do command -v "$command_name" >/dev/null || fail "missing command: $command_name"; done
[[ "$BACKUP_AGE_IDENTITY_FILE" == /* && -f "$BACKUP_AGE_IDENTITY_FILE" && ! -L "$BACKUP_AGE_IDENTITY_FILE" ]] ||
  fail "BACKUP_AGE_IDENTITY_FILE must be an absolute regular file"
case "$(stat -c '%a' "$BACKUP_AGE_IDENTITY_FILE")" in
  400|600) ;;
  *) fail "BACKUP_AGE_IDENTITY_FILE mode must be 0400 or 0600" ;;
esac
[[ "$(stat -c '%u' "$BACKUP_AGE_IDENTITY_FILE")" == "$(id -u)" ]] ||
  fail "BACKUP_AGE_IDENTITY_FILE must be owned by the restore account"
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
target_database="$(python3 - <<'PY'
import os
from urllib.parse import urlsplit
print(urlsplit(os.environ["RESTORE_TEST_DATABASE_URL"]).path.lstrip("/"))
PY
)"
[[ "$SOURCE_DATABASE_NAME" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] || fail "source database name is invalid"
[[ "$target_database" != "$SOURCE_DATABASE_NAME" && "$target_database" =~ (^|_)restore(_|$) ]] ||
  fail "restore target is not explicitly isolated from the source database"
read -r expected_digest recorded_name extra <"$checksum_file" || fail "checksum record is unreadable"
[[ "$expected_digest" =~ ^[0-9a-f]{64}$ && "$recorded_name" == "$(basename -- "$backup")" && -z "${extra:-}" ]] ||
  fail "checksum record is not bound to the supplied backup"
actual_digest="$(sha256sum -- "$backup" | awk '{print $1}')"
[[ "$actual_digest" == "$expected_digest" ]] || fail "checksum mismatch"
age --decrypt --identity "$BACKUP_AGE_IDENTITY_FILE" "$backup" |
  PGPASSFILE="$RESTORE_TEST_PGPASSFILE" pg_restore --dbname="$RESTORE_TEST_DATABASE_URL" --clean --if-exists --no-owner --no-acl --exit-on-error
pg_restore --list <(age --decrypt --identity "$BACKUP_AGE_IDENTITY_FILE" "$backup") >/dev/null || fail "archive inventory failed"
realm_table_count="$(PGPASSFILE="$RESTORE_TEST_PGPASSFILE" psql "$RESTORE_TEST_DATABASE_URL" -XAtq -v ON_ERROR_STOP=1 -c \
  "select count(*) from information_schema.tables where table_schema='public' and table_name='realm';")"
client_table_count="$(PGPASSFILE="$RESTORE_TEST_PGPASSFILE" psql "$RESTORE_TEST_DATABASE_URL" -XAtq -v ON_ERROR_STOP=1 -c \
  "select count(*) from information_schema.tables where table_schema='public' and table_name='client';")"
[[ "$realm_table_count" == "1" && "$client_table_count" == "1" ]] || fail "required Keycloak schema verification failed"

install -d -m 0700 -- "$RESTORE_EVIDENCE_DIR"
exec 8>"$RESTORE_EVIDENCE_DIR/.restore.lock"
flock -n 8 || fail "another restore verification is publishing evidence"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
result_name="RESTORE-RESULT-${stamp}"
result_partial="$RESTORE_EVIDENCE_DIR/.${result_name}.partial"
result="$RESTORE_EVIDENCE_DIR/${result_name}"
checksum_partial="$RESTORE_EVIDENCE_DIR/.${result_name}.sha256.partial"
[[ ! -e "$result" && ! -e "${result}.sha256" && ! -e "$result_partial" && ! -e "$checksum_partial" ]] ||
  fail "restore evidence stamp collision"
trap 'rm -f -- "${result_partial:-}" "${checksum_partial:-}" "${marker_partial:-}"' EXIT
cat >"$result_partial" <<EOF
SCHEMA=codestra-keycloak-restore-result.v1
STAMP=$stamp
BACKUP_FILE=$(basename -- "$backup")
BACKUP_SHA256=$actual_digest
TARGET_CLASS=ISOLATED
REALM_TABLE=PASS
CLIENT_TABLE=PASS
RESTORE=PASS
EOF
sync -f "$result_partial"
mv -- "$result_partial" "$result"
sync -f "$result"
printf '%s  %s\n' "$(sha256sum -- "$result" | awk '{print $1}')" "$result_name" >"$checksum_partial"
sync -f "$checksum_partial"
mv -- "$checksum_partial" "${result}.sha256"
sync -f "${result}.sha256"
marker_partial="$RESTORE_EVIDENCE_DIR/.LAST_SUCCESS-${stamp}"
printf '%s\n' "$stamp" >"$marker_partial"
sync -f "$marker_partial"
mv -- "$marker_partial" "$RESTORE_EVIDENCE_DIR/LAST_SUCCESS"
sync -f "$RESTORE_EVIDENCE_DIR/LAST_SUCCESS"
sync -d "$RESTORE_EVIDENCE_DIR"
trap - EXIT
printf 'RESTORE_TEST_STATUS=SUCCESS\nBACKUP_FILE=%s\nRESTORE_EVIDENCE=%s\n' "$backup" "$result"
