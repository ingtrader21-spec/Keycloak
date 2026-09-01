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
grep -qx 'RESTORE=PASS' "$root/$result_name" || fail "restore evidence does not record success"
stamp_iso="${stamp:0:4}-${stamp:4:2}-${stamp:6:2}T${stamp:9:2}:${stamp:11:2}:${stamp:13:2}Z"
stamp_epoch="$(date -u -d "$stamp_iso" +%s)" || fail "restore timestamp is invalid"
now_epoch="$(date -u +%s)"
age=$((now_epoch - stamp_epoch))
(( age >= -300 )) || fail "restore evidence is unreasonably in the future"
(( age <= max_age )) || fail "restore evidence is stale"
printf 'RECOVERY_FRESHNESS=PASS\nRESTORE_AGE_SECONDS=%s\n' "$age"
