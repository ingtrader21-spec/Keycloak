#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() { printf 'BACKUP_STATUS=FAILED\nBACKUP_ERROR=%s\n' "$*" >&2; exit 1; }
for command_name in pg_dump age sha256sum install date python3 stat id basename awk mv flock sync; do
  command -v "$command_name" >/dev/null || fail "missing command: $command_name"
done
: "${KEYCLOAK_DATABASE_URL:?KEYCLOAK_DATABASE_URL is required}"
: "${KEYCLOAK_PGPASSFILE:?KEYCLOAK_PGPASSFILE is required}"
: "${BACKUP_AGE_RECIPIENT:?BACKUP_AGE_RECIPIENT is required}"
: "${BACKUP_DESTINATION:?BACKUP_DESTINATION is required}"
[[ "$BACKUP_DESTINATION" == /* ]] || fail "BACKUP_DESTINATION must be absolute"
[[ "$KEYCLOAK_PGPASSFILE" == /* && -f "$KEYCLOAK_PGPASSFILE" && ! -L "$KEYCLOAK_PGPASSFILE" ]] ||
  fail "KEYCLOAK_PGPASSFILE must be an absolute regular file"
case "$(stat -c '%a' "$KEYCLOAK_PGPASSFILE")" in
  400|600) ;;
  *) fail "KEYCLOAK_PGPASSFILE mode must be 0400 or 0600" ;;
esac
[[ "$(stat -c '%u' "$KEYCLOAK_PGPASSFILE")" == "$(id -u)" ]] ||
  fail "KEYCLOAK_PGPASSFILE must be owned by the backup account"
python3 - <<'PY' || fail "KEYCLOAK_DATABASE_URL must be a credential-free PostgreSQL URI"
import os
from urllib.parse import parse_qsl, urlsplit

url = os.environ["KEYCLOAK_DATABASE_URL"]
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
install -d -m 0700 -- "$BACKUP_DESTINATION"
exec 9>"$BACKUP_DESTINATION/.backup.lock"
flock -n 9 || fail "another backup is active"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
final="$BACKUP_DESTINATION/keycloak-${stamp}.sql.age"
partial="${final}.partial"
checksum_partial="${final}.sha256.partial"
[[ ! -e "$final" && ! -e "${final}.sha256" && ! -e "$partial" && ! -e "$checksum_partial" ]] ||
  fail "backup stamp collision"
trap 'rm -f -- "${partial:-}" "${checksum_partial:-}"' EXIT

# pipefail makes pg_dump, encryption, or storage failure fatal. A partial file
# is never promoted to a successful backup.
PGPASSFILE="$KEYCLOAK_PGPASSFILE" pg_dump --dbname="$KEYCLOAK_DATABASE_URL" --format=custom --no-owner --no-acl |
  age --recipient "$BACKUP_AGE_RECIPIENT" --output "$partial"
[[ -s "$partial" ]] || fail "encrypted dump is empty"
sync -f "$partial"
mv -- "$partial" "$final"
sync -f "$final"
digest="$(sha256sum -- "$final" | awk '{print $1}')"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid backup digest"
printf '%s  %s\n' "$digest" "$(basename -- "$final")" >"$checksum_partial"
sync -f "$checksum_partial"
mv -- "$checksum_partial" "${final}.sha256"
sync -f "${final}.sha256"
sync -d "$BACKUP_DESTINATION"
printf 'BACKUP_STATUS=SUCCESS\nBACKUP_FILE=%s\nCHECKSUM_FILE=%s\n' "$final" "${final}.sha256"
