#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ $# -eq 1 && "$1" == /* ]] || {
  echo 'RUNTIME_SSH_WRAPPER_ERROR=output path must be absolute' >&2
  exit 1
}

wrapper="$1"
cat >"$wrapper" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
unset SSH_AUTH_SOCK
exec ssh \
  -F /dev/null \
  -i "$RUNTIME_GIT_SSH_KEY" \
  -o BatchMode=yes \
  -o IdentitiesOnly=yes \
  -o IdentityAgent=none \
  -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o StrictHostKeyChecking=yes \
  -o UpdateHostKeys=no \
  -o VerifyHostKeyDNS=no \
  -o CheckHostIP=no \
  -o GlobalKnownHostsFile=/dev/null \
  -o "UserKnownHostsFile=$RUNTIME_GIT_KNOWN_HOSTS" \
  -o HostKeyAlgorithms=ssh-ed25519 \
  -o ConnectTimeout=10 \
  -o ServerAliveInterval=5 \
  -o ServerAliveCountMax=1 \
  "$@"
WRAPPER
chmod 700 "$wrapper"
