#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/backups" "$fixture/relocated" "$fixture/restore-evidence"

cat >"$fixture/bin/pg_dump" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$@" >"$TEST_PG_DUMP_ARGS"
printf '%s\n' "${PGPASSFILE:-}" >"$TEST_PG_PASSFILE_OBSERVED"
printf 'fixture-custom-dump'
SH

cat >"$fixture/bin/age" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == "--decrypt" ]]; then
  cat -- "${@: -1}"
  exit 0
fi
output=''
while (($#)); do
  case "$1" in
    --output) output=$2; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "$output" ]]
cat >"$output"
SH

cat >"$fixture/bin/pg_restore" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$@" >>"$TEST_PG_RESTORE_ARGS"
printf '%s\n' "${PGPASSFILE:-}" >>"$TEST_RESTORE_PGPASS_OBSERVED"
cat >/dev/null
printf 'pg_restore-called\n' >>"$TEST_PG_RESTORE_LOG"
SH

cat >"$fixture/bin/psql" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
count=0
if [[ -f "$TEST_PSQL_COUNT" ]]; then read -r count <"$TEST_PSQL_COUNT"; fi
count=$((count + 1))
printf '%s\n' "$count" >"$TEST_PSQL_COUNT"
if ((count % 3 == 1)); then printf '%s\n' "${TEST_PRE_RESTORE_TABLES:-0}"; else printf '1\n'; fi
SH

chmod 0700 "$fixture/bin/pg_dump" "$fixture/bin/age" "$fixture/bin/pg_restore" "$fixture/bin/psql"
printf 'db.internal:5432:keycloak:keycloak:fixture-password\n' >"$fixture/backup.pgpass"
chmod 0600 "$fixture/backup.pgpass"
printf 'fixture-age-identity\n' >"$fixture/age-identity"
chmod 0600 "$fixture/age-identity"

export PATH="$fixture/bin:/usr/local/bin:/usr/bin:/bin"
export TEST_PG_DUMP_ARGS="$fixture/pg-dump.args"
export TEST_PG_PASSFILE_OBSERVED="$fixture/pgpass.observed"
export TEST_PG_RESTORE_LOG="$fixture/pg-restore.log"
export TEST_PG_RESTORE_ARGS="$fixture/pg-restore.args"
export TEST_RESTORE_PGPASS_OBSERVED="$fixture/restore-pgpass.observed"
export TEST_PSQL_COUNT="$fixture/psql.count"
export KEYCLOAK_DATABASE_URL='postgresql://keycloak@db.internal:5432/keycloak?sslmode=require'
export KEYCLOAK_PGPASSFILE="$fixture/backup.pgpass"
export BACKUP_AGE_RECIPIENT='age1fixture'
export BACKUP_DESTINATION="$fixture/backups"

output="$("$ROOT_DIR/scripts/backup-postgres.sh")"
backup="$(sed -n 's/^BACKUP_FILE=//p' <<<"$output")"
checksum="${backup}.sha256"
[[ -s "$backup" && -s "$checksum" ]]
[[ "$(awk 'NR == 1 {print $2}' "$checksum")" == "$(basename -- "$backup")" ]]
if grep -Fq "$fixture" "$checksum"; then
  printf 'ERROR=checksum_contains_absolute_source_path\n' >&2
  exit 1
fi
if grep -Fq 'fixture-password' "$TEST_PG_DUMP_ARGS"; then
  printf 'ERROR=pg_dump_arguments_contain_password\n' >&2
  exit 1
fi
grep -Fxq "$KEYCLOAK_PGPASSFILE" "$TEST_PG_PASSFILE_OBSERVED"

relocated="$fixture/relocated/$(basename -- "$backup")"
cp -- "$backup" "$relocated"
cp -- "$checksum" "${relocated}.sha256"
export BACKUP_AGE_IDENTITY_FILE="$fixture/age-identity"
export RESTORE_TEST_DATABASE_URL='postgresql://restore@isolated.internal:5432/keycloak_restore'
export RESTORE_TEST_PGPASSFILE="$fixture/backup.pgpass"
export RESTORE_EVIDENCE_DIR="$fixture/restore-evidence"
export SOURCE_DATABASE_NAME='keycloak'
export ALLOW_DESTRUCTIVE_RESTORE_TEST='isolated-database-confirmed'
export RESTORE_TEST_DATABASE_URL='postgresql://restore@isolated.internal:5432/keycloak_restore?dbname=keycloak'
if "$ROOT_DIR/scripts/verify-backup.sh" "$relocated" >/dev/null 2>&1; then
  printf 'ERROR=database_override_query_was_accepted\n' >&2
  exit 1
fi
[[ ! -e "$TEST_PSQL_COUNT" ]]
export RESTORE_TEST_DATABASE_URL='postgresql://restore@isolated.internal:5432/keycloak_restore'
"$ROOT_DIR/scripts/verify-backup.sh" "$relocated" >/dev/null
if grep -Fq 'fixture-password' "$TEST_PG_RESTORE_ARGS"; then
  printf 'ERROR=pg_restore_arguments_contain_password\n' >&2
  exit 1
fi
grep -Fxq "$RESTORE_TEST_PGPASSFILE" "$TEST_RESTORE_PGPASS_OBSERVED"
"$ROOT_DIR/scripts/check-recovery-freshness.sh" "$RESTORE_EVIDENCE_DIR" 300 >/dev/null

rm -f "$TEST_PSQL_COUNT"
export TEST_PRE_RESTORE_TABLES=1
if "$ROOT_DIR/scripts/verify-backup.sh" "$relocated" >/dev/null 2>&1; then
  printf 'ERROR=nonempty_restore_database_was_accepted\n' >&2
  exit 1
fi
unset TEST_PRE_RESTORE_TABLES

restore_result="$(find "$RESTORE_EVIDENCE_DIR" -maxdepth 1 -type f -name 'RESTORE-RESULT-*' ! -name '*.sha256' -print -quit)"
printf 'tampered\n' >>"$restore_result"
if "$ROOT_DIR/scripts/check-recovery-freshness.sh" "$RESTORE_EVIDENCE_DIR" 300 >/dev/null 2>&1; then
  printf 'ERROR=tampered_restore_evidence_was_accepted\n' >&2
  exit 1
fi

printf 'tampered' >>"$relocated"
if "$ROOT_DIR/scripts/verify-backup.sh" "$relocated" >/dev/null 2>&1; then
  printf 'ERROR=tampered_relocated_backup_was_accepted\n' >&2
  exit 1
fi

rm -f "$TEST_PG_DUMP_ARGS"
export KEYCLOAK_DATABASE_URL='postgresql://keycloak:forbidden-password@db.internal:5432/keycloak'
if "$ROOT_DIR/scripts/backup-postgres.sh" >/dev/null 2>&1; then
  printf 'ERROR=password_bearing_database_uri_was_accepted\n' >&2
  exit 1
fi
[[ ! -e "$TEST_PG_DUMP_ARGS" ]]

printf 'BACKUP_CONTRACT_TEST=PASS\n'
