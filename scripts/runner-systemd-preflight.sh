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
for command_name in systemctl getent getfacl docker realpath find sort cat awk grep sed id stat; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'ERROR=required_command_missing:%s\n' "$command_name" >&2
    exit 1
  }
done
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
command -v getfacl >/dev/null 2>&1 || {
  printf 'ERROR=getfacl_required_for_docker_socket_authorization\n' >&2
  exit 1
}
if ! docker_socket_acl="$(getfacl --absolute-names --omit-header --numeric "$socket")"; then
  printf 'ERROR=docker_socket_acl_unreadable\n' >&2
  exit 1
fi
expected_socket_acl=$'user::rw-\ngroup::rw-\nother::---'
[[ "$docker_socket_acl" == "$expected_socket_acl" ]] || {
  printf 'ERROR=unexpected_docker_socket_acl\n' >&2
  exit 1
}

runner_groups="$(id -Gn)"
grep -Eq '(^|[[:space:]])docker($|[[:space:]])' <<<"$runner_groups" || {
  printf 'ERROR=runner_user_lacks_reviewable_docker_group_membership\n' >&2
  exit 1
}

if ! docker_group_entry="$(getent group docker)"; then
  printf 'ERROR=docker_group_nss_lookup_failed\n' >&2
  exit 1
fi
IFS=: read -r docker_group_name _ docker_group_gid docker_group_members <<<"$docker_group_entry"
[[ "$docker_group_name" == docker && "$docker_group_gid" =~ ^[0-9]+$ ]] || {
  printf 'ERROR=docker_group_unresolved\n' >&2
  exit 1
}
passwd_snapshot="$tmp_dir/passwd.txt"
group_snapshot="$tmp_dir/group.txt"
nsswitch=/etc/nsswitch.conf
[[ -r "$nsswitch" ]] || { printf 'ERROR=nsswitch_configuration_unreadable\n' >&2; exit 1; }
passwd_nss_sources="$(awk '$1 == "passwd:" { $1=""; sub(/^ /, ""); print; exit }' "$nsswitch")"
group_nss_sources="$(awk '$1 == "group:" { $1=""; sub(/^ /, ""); print; exit }' "$nsswitch")"
[[ -n "$passwd_nss_sources" && -n "$group_nss_sources" ]] || {
  printf 'ERROR=nsswitch_account_sources_unresolved\n' >&2
  exit 1
}
for source in $passwd_nss_sources $group_nss_sources; do
  [[ "$source" == files || "$source" == systemd ]] || {
    printf 'ERROR=non_enumerable_nss_source:%s\n' "$source" >&2
    exit 1
  }
done
if ! getent passwd >"$passwd_snapshot"; then
  printf 'ERROR=passwd_nss_enumeration_failed\n' >&2
  exit 1
fi
[[ -s "$passwd_snapshot" ]] || {
  printf 'ERROR=passwd_nss_enumeration_empty\n' >&2
  exit 1
}
if ! getent group >"$group_snapshot"; then
  printf 'ERROR=group_nss_enumeration_failed\n' >&2
  exit 1
fi
[[ -s "$group_snapshot" ]] || {
  printf 'ERROR=group_nss_enumeration_empty\n' >&2
  exit 1
}
docker_gid_entries="$(awk -F: -v gid="$docker_group_gid" '$3 == gid { print $1 }' "$group_snapshot")"
[[ "$docker_gid_entries" == docker ]] || {
  printf 'ERROR=docker_group_gid_must_be_unique:%s\n' "$docker_group_gid" >&2
  exit 1
}
grep -Eq "^${runner_user}:[^:]*:[0-9]+:[0-9]+:" "$passwd_snapshot" || {
  printf 'ERROR=runner_missing_from_passwd_nss_snapshot\n' >&2
  exit 1
}
mapfile -t docker_authorized_accounts < <(
  {
    tr ',' '\n' <<<"$docker_group_members"
    awk -F: -v gid="$docker_group_gid" '$4 == gid { print $1 }' "$passwd_snapshot"
  } | sed '/^$/d' | sort -u
)
for account in "${docker_authorized_accounts[@]}"; do
  [[ "$account" == "$runner_user" ]] || {
    printf 'ERROR=unexpected_docker_authorized_account:%s\n' "$account" >&2
    exit 1
  }
done

active_units="$tmp_dir/active-services.txt"
if ! systemctl list-units --type=service --state=running --no-legend --plain >"$active_units"; then
  printf 'ERROR=active_systemd_service_enumeration_failed\n' >&2
  exit 1
fi
cgroup_root=/sys/fs/cgroup
[[ -f "$cgroup_root/cgroup.controllers" ]] || {
  printf 'ERROR=unified_cgroup_v2_required_for_process_authorization\n' >&2
  exit 1
}
runner_uid_number="$(id -u "$runner_user")"
active_service_index=0
while read -r active_unit _; do
  [[ -n "$active_unit" ]] || continue
  active_service_index=$((active_service_index + 1))
  active_user_property="$(systemctl show "$active_unit" -p User --value)"
  if [[ -n "$active_user_property" ]]; then
    if ! active_passwd_entry="$(getent passwd "$active_user_property")"; then
      printf 'ERROR=active_systemd_user_unresolved:%s:%s\n' "$active_unit" "$active_user_property" >&2
      exit 1
    fi
    IFS=: read -r active_user _ active_uid _ <<<"$active_passwd_entry"
    [[ "$active_uid" =~ ^[0-9]+$ ]] || {
      printf 'ERROR=active_systemd_user_uid_unresolved:%s:%s\n' "$active_unit" "$active_user_property" >&2
      exit 1
    }
  else
    active_user=root
    active_uid=0
  fi

  control_group="$(systemctl show "$active_unit" -p ControlGroup --value)"
  [[ "$control_group" == /* && "$control_group" != *$'\n'* && "$control_group" != *'..'* ]] || {
    printf 'ERROR=active_systemd_control_group_unresolved:%s\n' "$active_unit" >&2
    exit 1
  }
  if ! control_group_path="$(realpath -e -- "$cgroup_root$control_group")"; then
    printf 'ERROR=active_systemd_control_group_missing:%s\n' "$active_unit" >&2
    exit 1
  fi
  [[ "$control_group_path" == "$cgroup_root"/* ]] || {
    printf 'ERROR=active_systemd_control_group_outside_root:%s\n' "$active_unit" >&2
    exit 1
  }
  pid_snapshot="$tmp_dir/active-service-${active_service_index}-pids.txt"
  if ! find "$control_group_path" -type f -name cgroup.procs -exec cat -- {} + >"$pid_snapshot"; then
    printf 'ERROR=active_systemd_process_enumeration_failed:%s\n' "$active_unit" >&2
    exit 1
  fi
  sort -nu -o "$pid_snapshot" "$pid_snapshot"
  [[ -s "$pid_snapshot" ]] || {
    printf 'ERROR=active_systemd_process_enumeration_empty:%s\n' "$active_unit" >&2
    exit 1
  }
  while IFS= read -r active_pid; do
    [[ "$active_pid" =~ ^[0-9]+$ ]] || {
      printf 'ERROR=active_systemd_invalid_pid:%s\n' "$active_unit" >&2
      exit 1
    }
    process_status_file="/proc/${active_pid}/status"
    if ! process_status="$(cat -- "$process_status_file" 2>/dev/null)"; then
      [[ ! -e "$process_status_file" ]] || {
        printf 'ERROR=active_systemd_process_status_unreadable:%s:%s\n' "$active_unit" "$active_pid" >&2
        exit 1
      }
      continue
    fi
    process_uid="$(awk '$1 == "Uid:" { print $2; exit }' <<<"$process_status")"
    process_groups="$(awk '$1 == "Groups:" { $1=""; sub(/^ /, ""); print; exit }' <<<"$process_status")"
    [[ "$process_uid" =~ ^[0-9]+$ && -n "$process_groups" ]] || {
      printf 'ERROR=active_systemd_process_credentials_unresolved:%s:%s\n' "$active_unit" "$active_pid" >&2
      exit 1
    }
    if grep -Eq "(^|[[:space:]])${docker_group_gid}($|[[:space:]])" <<<"$process_groups"; then
      [[ ( "$active_unit" == "$expected_unit" && "$process_uid" == "$runner_uid_number" ) \
        || ( "$active_unit" != "$expected_unit" && "$process_uid" == 0 ) ]] || {
        printf 'ERROR=unexpected_running_process_docker_authorization:%s:%s:%s\n' "$active_unit" "$active_pid" "$process_uid" >&2
        exit 1
      }
    fi
  done <"$pid_snapshot"

  [[ "$active_uid" != 0 ]] || continue
  active_group="$(systemctl show "$active_unit" -p Group --value)"
  active_supplementary="$(systemctl show "$active_unit" -p SupplementaryGroups --value)"
  active_user_has_docker_access=false
  for account in "${docker_authorized_accounts[@]}"; do
    if [[ "$active_user" == "$account" ]]; then
      active_user_has_docker_access=true
      break
    fi
  done
  active_unit_declares_docker_group=false
  for group_property in $active_group $active_supplementary; do
    if ! active_group_entry="$(getent group "$group_property")"; then
      printf 'ERROR=active_systemd_group_unresolved:%s:%s\n' "$active_unit" "$group_property" >&2
      exit 1
    fi
    IFS=: read -r _ _ active_group_gid _ <<<"$active_group_entry"
    [[ "$active_group_gid" =~ ^[0-9]+$ ]] || {
      printf 'ERROR=active_systemd_group_gid_unresolved:%s:%s\n' "$active_unit" "$group_property" >&2
      exit 1
    }
    if [[ "$active_group_gid" == "$docker_group_gid" ]]; then
      active_unit_declares_docker_group=true
    fi
  done
  if [[ "$active_user_has_docker_access" == true ]] \
    || [[ "$active_unit_declares_docker_group" == true ]]; then
    [[ "$active_unit" == "$expected_unit" && "$active_user" == "$runner_user" ]] || {
      printf 'ERROR=unexpected_systemd_docker_authorization:%s:%s\n' "$active_unit" "$active_user" >&2
      exit 1
    }
  fi
done <"$active_units"
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
  printf 'DOCKER_SOCKET_ACL=BASE_ENTRIES_ONLY\n'
  printf 'DOCKER_NSS_ENUMERATION=PASS\n'
  printf 'DOCKER_SYSTEMD_SERVICE_ENUMERATION=PASS\n'
  printf 'DOCKER_EFFECTIVE_PROCESS_GROUP_ENUMERATION=PASS\n'
  printf 'DOCKER_AUTHORIZED_NON_ROOT_ACCOUNTS=%s\n' "${docker_authorized_accounts_csv:-UNIT_BOUND_RUNNER_ONLY}"
  printf 'RUNNER_DOCKER_SECURITY_IMPACT=DOCKER_GROUP_CONFERS_ROOT_EQUIVALENT_HOST_CONTROL\n'
  printf 'RUNNER_DOCKER_AUTHORIZATION=PASS\n'
  printf 'RUNNER_IDENTITY=PASS\n'
} >"$report"
chmod 600 "$report"
cat "$report"
