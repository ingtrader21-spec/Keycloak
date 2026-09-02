#!/usr/bin/env bash
set -Eeuo pipefail

fail() { printf 'RECOVERY_FRESHNESS=FAIL\nRECOVERY_ERROR=%s\n' "$*" >&2; exit 1; }
[[ $# -eq 2 ]] || fail "usage: check-recovery-freshness.sh /absolute/evidence/directory MAX_AGE_SECONDS"
root="$1"
max_age="$2"
[[ "$root" == /* && -d "$root" && ! -L "$root" ]] || fail "evidence directory must be an absolute real directory"
[[ "$max_age" =~ ^[1-9][0-9]*$ ]] || fail "maximum age must be a positive integer"
[[ -f "$root/LAST_SUCCESS" && ! -L "$root/LAST_SUCCESS" ]] || fail "restore success marker is missing"
stamp="$(tr -d '\r\n' <"$root/LAST_SUCCESS")"
[[ "$stamp" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || fail "invalid restore success marker"
result_name="RESTORE-RESULT-${stamp}"
[[ -f "$root/$result_name" && ! -L "$root/$result_name" ]] || fail "restore evidence is missing"
[[ -f "$root/$result_name.sha256" && ! -L "$root/$result_name.sha256" ]] || fail "restore evidence checksum is missing"
read -r expected_digest recorded_name extra <"$root/$result_name.sha256" || fail "restore evidence checksum is unreadable"
[[ "$expected_digest" =~ ^[0-9a-f]{64}$ && "$recorded_name" == "$result_name" && -z "${extra:-}" ]] ||
  fail "restore evidence checksum is not bound to the result"
[[ "$(sha256sum -- "$root/$result_name" | awk '{print $1}')" == "$expected_digest" ]] ||
  fail "restore evidence checksum failed"
python3 - "$root/$result_name" "$stamp" <<'PY' || fail "restore evidence schema is incomplete or invalid"
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected_stamp = sys.argv[2]
expected_keys = {
    "SCHEMA",
    "STAMP",
    "BACKUP_FILE",
    "BACKUP_SHA256",
    "TARGET_CLASS",
    "PRE_RESTORE_PUBLIC_TABLES",
    "REALM_TABLE",
    "CLIENT_TABLE",
    "REALM_ROWS",
    "CLIENT_ROWS",
    "RESTORE",
}
values: dict[str, str] = {}
for line in path.read_text(encoding="utf-8").splitlines():
    if "=" not in line:
        raise SystemExit(1)
    key, value = line.split("=", 1)
    if key in values or key not in expected_keys:
        raise SystemExit(1)
    values[key] = value
if set(values) != expected_keys:
    raise SystemExit(1)
if values["SCHEMA"] != "codestra-keycloak-restore-result.v1":
    raise SystemExit(1)
if values["STAMP"] != expected_stamp:
    raise SystemExit(1)
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", values["BACKUP_FILE"]):
    raise SystemExit(1)
if not re.fullmatch(r"[0-9a-f]{64}", values["BACKUP_SHA256"]):
    raise SystemExit(1)
for key, expected in {
    "TARGET_CLASS": "ISOLATED",
    "PRE_RESTORE_PUBLIC_TABLES": "0",
    "REALM_TABLE": "PASS",
    "CLIENT_TABLE": "PASS",
    "RESTORE": "PASS",
}.items():
    if values[key] != expected:
        raise SystemExit(1)
for key in ("REALM_ROWS", "CLIENT_ROWS"):
    if not values[key].isdigit() or int(values[key]) < 1:
        raise SystemExit(1)
PY
stamp_iso="${stamp:0:4}-${stamp:4:2}-${stamp:6:2}T${stamp:9:2}:${stamp:11:2}:${stamp:13:2}Z"
stamp_epoch="$(date -u -d "$stamp_iso" +%s)" || fail "restore timestamp is invalid"
now_epoch="$(date -u +%s)"
age=$((now_epoch - stamp_epoch))
(( age >= -300 )) || fail "restore evidence is unreasonably in the future"
(( age <= max_age )) || fail "restore evidence is stale"
printf 'RECOVERY_FRESHNESS=PASS\nRESTORE_AGE_SECONDS=%s\n' "$age"
