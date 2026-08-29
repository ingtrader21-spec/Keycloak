#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() { printf 'BACKUP_STATUS=FAILED\nBACKUP_ERROR=%s\n' "$*" >&2; exit 1; }
for command_name in pg_dump age sha256sum install date; do
  command -v "$command_name" >/dev/null || fail "missing command: $command_name"
done
: "${KEYCLOAK_DATABASE_URL:?KEYCLOAK_DATABASE_URL is required}"
: "${BACKUP_AGE_RECIPIENT:?BACKUP_AGE_RECIPIENT is required}"
: "${BACKUP_DESTINATION:?BACKUP_DESTINATION is required}"
[[ "$BACKUP_DESTINATION" == /* ]] || fail "BACKUP_DESTINATION must be absolute"
install -d -m 0700 -- "$BACKUP_DESTINATION"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
final="$BACKUP_DESTINATION/keycloak-${stamp}.sql.age"
partial="${final}.partial"
trap 'rm -f -- "${partial:-}"' EXIT

# pipefail makes pg_dump, encryption, or storage failure fatal. A partial file
# is never promoted to a successful backup.
pg_dump --dbname="$KEYCLOAK_DATABASE_URL" --format=custom --no-owner --no-acl |
  age --recipient "$BACKUP_AGE_RECIPIENT" --output "$partial"
[[ -s "$partial" ]] || fail "encrypted dump is empty"
mv -- "$partial" "$final"
sha256sum -- "$final" >"${final}.sha256"
printf 'BACKUP_STATUS=SUCCESS\nBACKUP_FILE=%s\nCHECKSUM_FILE=%s\n' "$final" "${final}.sha256"
