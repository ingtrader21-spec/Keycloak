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
  -p WorkingDirectory >/dev/null

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

runner_groups="$(id -Gn)"
grep -Eq '(^|[[:space:]])docker($|[[:space:]])' <<<"$runner_groups" || {
  printf 'ERROR=runner_user_lacks_reviewable_docker_group_membership\n' >&2
  exit 1
}

docker_group_entry="$(getent group docker || true)"
IFS=: read -r docker_group_name _ docker_group_gid docker_group_members <<<"$docker_group_entry"
[[ "$docker_group_name" == docker && "$docker_group_gid" =~ ^[0-9]+$ ]] || {
  printf 'ERROR=docker_group_unresolved\n' >&2
  exit 1
}
mapfile -t docker_authorized_accounts < <(
  {
    tr ',' '\n' <<<"$docker_group_members"
    getent passwd | awk -F: -v gid="$docker_group_gid" '$4 == gid { print $1 }'
  } | sed '/^$/d' | sort -u
)
for account in "${docker_authorized_accounts[@]}"; do
  [[ "$account" == "$runner_user" ]] || {
    printf 'ERROR=unexpected_docker_authorized_account:%s\n' "$account" >&2
    exit 1
  }
done
if ! grep -Eq '(^|[[:space:]])docker($|[[:space:]])' <<<"$runner_supplementary_groups" \
  && [[ ! ",${docker_group_members}," == *",${runner_user},"* ]] \
  && [[ "$(id -g "$runner_user")" != "$docker_group_gid" ]]; then
  printf 'ERROR=docker_access_not_explicitly_bound_to_runner_identity\n' >&2
  exit 1
fi
docker info >/dev/null

# Unit files and systemd Environment values can contain operational material.
# The required systemctl show command above inspects Environment, but no value or
# fragment is retained in the uploaded artifact.
unit_fragment_paths="$(grep -E '^# /' "$tmp_dir/unit.txt" | sed 's/^# //' | paste -sd, -)"
docker_authorized_accounts_csv="$(printf '%s\n' "${docker_authorized_accounts[@]}" | sed '/^$/d' | paste -sd, -)"

umask 077
{
  printf 'RUNNER_SYSTEMD_UNIT=%s\n' "$expected_unit"
  printf 'RUNNER_USER=%s\n' "$runner_user"
  printf 'RUNNER_GROUP=%s\n' "${runner_group:-DEFAULT}"
  printf 'RUNNER_SUPPLEMENTARY_GROUPS=%s\n' "${runner_supplementary_groups:-NONE_DECLARED_IN_UNIT}"
  printf 'RUNNER_EFFECTIVE_GROUPS=%s\n' "$runner_groups"
  printf 'RUNNER_WORKING_DIRECTORY=%s\n' "${runner_working_directory:-UNSET}"
  printf 'RUNNER_UNIT_FRAGMENTS=%s\n' "${unit_fragment_paths:-UNRESOLVED}"
  printf 'RUNNER_SYSTEMD_ENVIRONMENT=INSPECTED_NOT_RECORDED\n'
  printf 'DOCKER_SOCKET_MODE=%s\n' "$socket_mode"
  printf 'DOCKER_SOCKET_OWNER=%s:%s\n' "$socket_user" "$socket_group"
  printf 'DOCKER_AUTHORIZED_NON_ROOT_ACCOUNTS=%s\n' "${docker_authorized_accounts_csv:-UNIT_BOUND_RUNNER_ONLY}"
  printf 'RUNNER_DOCKER_SECURITY_IMPACT=DOCKER_GROUP_CONFERS_ROOT_EQUIVALENT_HOST_CONTROL\n'
  printf 'RUNNER_DOCKER_AUTHORIZATION=PASS\n'
  printf 'RUNNER_IDENTITY=PASS\n'
} >"$report"
chmod 600 "$report"
cat "$report"
