#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/runner-systemd-preflight.sh --report PATH

Read and validate the current self-hosted runner systemd identity and its
Docker authorization. The script does not change users, groups, units, socket
permissions, Docker state, or credentials.
EOF
}

report=''
while (($#)); do
  case "$1" in
    --report)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      report="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'ERROR=unknown_argument:%s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$report" && "$report" == /* ]] || {
  printf 'ERROR=absolute_report_path_required\n' >&2
  exit 2
}

expected_unit='actions.runner.appolon1908-hue-Keycloak.kazan555.service'
expected_user='keycloak-deploy'
work_dir="$(dirname -- "$report")"
mkdir -p -- "$work_dir"
chmod 700 "$work_dir"
tmp_dir="$(mktemp -d "$work_dir/runner-identity.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

systemctl list-units --all '*actions*' '*runner*' --no-pager --plain >"$tmp_dir/list-units.txt"
grep -Fq "$expected_unit" "$tmp_dir/list-units.txt" || {
  printf 'ERROR=expected_runner_unit_not_found:%s\n' "$expected_unit" >&2
  exit 1
}
systemctl is-active --quiet "$expected_unit" || {
  printf 'ERROR=runner_unit_not_active:%s\n' "$expected_unit" >&2
  exit 1
}
systemctl cat "$expected_unit" --no-pager >"$tmp_dir/unit.txt"
systemctl show "$expected_unit" \
  -p User \
  -p Group \
  -p SupplementaryGroups \
  -p Environment \
  -p WorkingDirectory >"$tmp_dir/show.txt"

runner_user="$(systemctl show "$expected_unit" -p User --value)"
runner_group="$(systemctl show "$expected_unit" -p Group --value)"
runner_supplementary_groups="$(systemctl show "$expected_unit" -p SupplementaryGroups --value)"
runner_working_directory="$(systemctl show "$expected_unit" -p WorkingDirectory --value)"
[[ "$runner_user" == "$expected_user" ]] || {
  printf 'ERROR=unexpected_runner_user:%s\n' "${runner_user:-EMPTY}" >&2
  exit 1
}
[[ "$runner_user" != root && "$(id -u "$runner_user")" != 0 ]] || {
  printf 'ERROR=runner_must_not_be_root\n' >&2
  exit 1
}
[[ "$(id -un)" == "$runner_user" ]] || {
  printf 'ERROR=workflow_process_user_does_not_match_service_user\n' >&2
  exit 1
}

socket=/var/run/docker.sock
[[ -S "$socket" ]] || { printf 'ERROR=docker_socket_missing\n' >&2; exit 1; }
socket_mode="$(stat -c '%a' "$socket")"
socket_user="$(stat -c '%U' "$socket")"
socket_group="$(stat -c '%G' "$socket")"
[[ "$socket_mode" == 660 && "$socket_user" == root && "$socket_group" == docker ]] || {
  printf 'ERROR=unexpected_docker_socket_authority:%s:%s:%s\n' "$socket_mode" "$socket_user" "$socket_group" >&2
  exit 1
}

runner_groups="$(id -Gn "$runner_user")"
grep -Eq '(^|[[:space:]])docker($|[[:space:]])' <<<"$runner_groups" || {
  printf 'ERROR=runner_user_lacks_reviewable_docker_group_membership\n' >&2
  exit 1
}
docker info >/dev/null

# Unit files and systemd Environment values can contain operational material.
# Preserve the required host-administration proof while recording environment
# variable names only; secret-like values are never copied into the artifact.
environment_line="$(grep '^Environment=' "$tmp_dir/show.txt" || true)"
environment_keys="$(sed -E 's/^Environment=//' <<<"$environment_line" | tr ' ' '\n' | sed -E 's/^"?([^=]+)=.*$/\1/' | sed '/^$/d' | sort -u | paste -sd, -)"
unit_fragment_paths="$(grep -E '^# /' "$tmp_dir/unit.txt" | sed 's/^# //' | paste -sd, -)"

umask 077
{
  printf 'RUNNER_SYSTEMD_UNIT=%s\n' "$expected_unit"
  printf 'RUNNER_USER=%s\n' "$runner_user"
  printf 'RUNNER_GROUP=%s\n' "${runner_group:-DEFAULT}"
  printf 'RUNNER_SUPPLEMENTARY_GROUPS=%s\n' "${runner_supplementary_groups:-NONE_DECLARED_IN_UNIT}"
  printf 'RUNNER_EFFECTIVE_GROUPS=%s\n' "$runner_groups"
  printf 'RUNNER_WORKING_DIRECTORY=%s\n' "${runner_working_directory:-UNSET}"
  printf 'RUNNER_UNIT_FRAGMENTS=%s\n' "${unit_fragment_paths:-UNRESOLVED}"
  printf 'RUNNER_SYSTEMD_ENVIRONMENT_KEYS=%s\n' "${environment_keys:-NONE}"
  printf 'DOCKER_SOCKET_MODE=%s\n' "$socket_mode"
  printf 'DOCKER_SOCKET_OWNER=%s:%s\n' "$socket_user" "$socket_group"
  printf 'RUNNER_DOCKER_SECURITY_IMPACT=DOCKER_GROUP_CONFERS_ROOT_EQUIVALENT_HOST_CONTROL\n'
  printf 'RUNNER_DOCKER_AUTHORIZATION=PASS\n'
  printf 'RUNNER_IDENTITY=PASS\n'
} >"$report"
chmod 600 "$report"
cat "$report"
