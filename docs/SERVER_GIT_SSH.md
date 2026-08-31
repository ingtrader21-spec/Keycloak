# Server-to-GitHub SSH bootstrap

## Security model

`65.109.65.169` receives a repository-scoped Ed25519 deploy key for
`appolon1908-hue/Keycloak`. GitHub write access must remain disabled. The server
must not receive a personal GitHub key, broad token, or write-enabled deploy key.

The runtime preflight proves repository **read access**. It cannot prove the
GitHub-side write checkbox is disabled, so reviewers must verify that setting
and match the public-key fingerprint independently.

## Required paths

Use verified canonical paths, not guessed placeholders:

```text
RUNTIME_REPO_DIR
RUNTIME_COMPOSE_FILE
RUNTIME_ENV_FILE
RUNTIME_CADDY_FILE
RUNTIME_GIT_SSH_KEY
RUNTIME_GIT_KNOWN_HOSTS
```

Run the restricted self-hosted runner service under the dedicated
`keycloak-deploy` Unix account. The private key and `known_hosts` file must be
owned by that same runner account, must not grant group or world access, and
must remain outside the Git checkout.

## Exclusive GitHub host trust

The dedicated `known_hosts` file may contain only explicit `github.com`
Ed25519 entries. Runtime SSH uses:

```text
-F /dev/null
StrictHostKeyChecking=yes
UpdateHostKeys=no
GlobalKnownHostsFile=/dev/null
UserKnownHostsFile=<dedicated file>
HostKeyAlgorithms=ssh-ed25519
IdentitiesOnly=yes
IdentityAgent=none
```

No user SSH configuration, SSH agent, global known-hosts file, password, or
keyboard-interactive fallback participates in the connection.

## Release preparation

After the runtime paths are independently verified and the read-only deploy key
is registered in GitHub, synchronize the server checkout to the exact protected
merged SHA. Do not run a floating production `git pull`. Confirm:

```bash
GIT_CONFIG_NOSYSTEM=1 \
GIT_CONFIG_GLOBAL=/dev/null \
GIT_OPTIONAL_LOCKS=0 \
git -C "$RUNTIME_REPO_DIR" rev-parse HEAD
```

The value must equal the exact SHA selected in the manual workflow. The preflight
also checks that GitHub's remote `main` returns the same SHA using `git ls-remote`.
It makes no live Keycloak, Docker, or Caddy change.

## Self-hosted runner and Docker authorization

The reviewed runner service identity is
`actions.runner.appolon1908-hue-Keycloak.kazan555.service`, running as the
dedicated non-root `keycloak-deploy` account. The manual runtime preflight runs
`systemctl list-units`, `systemctl cat`, and `systemctl show` against that exact
unit, confirms the workflow process has the same Unix identity, and then proves
Docker access without changing unit, account, group, or socket state.

Docker access is intentionally limited to the dedicated runner identity through
the `docker` group and a `0660 root:docker` socket. Membership in the Docker
group confers root-equivalent control of this host; it must therefore remain
limited to this protected runner and must never be replaced with a world-writable
socket or a root-runner workaround. Any identity, unit, group, or socket-mode
drift fails the preflight. The probe enumerates explicit Docker-group members
and accounts whose primary group is Docker; any non-root identity other than
`keycloak-deploy` fails authorization. Systemd environment values are inspected
but never retained in the uploaded evidence. The Docker socket must have only
the base owner/group/other ACL entries; any named user/group ACL or mask fails.
The account database must also support a complete successful NSS enumeration
from local enumerable `files`/`systemd` sources before primary-group access is
evaluated. Every active systemd service substate is checked. For populated
service cgroups, the probe recursively reads effective process credentials and
rejects a retained Docker primary, effective, saved, filesystem, or
supplementary GID outside the exact non-root runner unit. This catches stale
credentials after a group or unit change that was not followed by a service
restart. A host-wide process scan also rejects retained Docker credentials in
login/session scopes and any root or otherwise unexpected UID inside the runner
cgroup. No other unit or process may declare, inherit, or retain Docker
authorization.

Every GHCR-authenticated workflow step creates `DOCKER_CONFIG` below
`RUNNER_TEMP` with mode `0700`, registers an `EXIT` cleanup trap, logs out, and
removes the directory on success or failure. Credentials must never be written
to `/var/lib/keycloak-deploy/.docker`, `/root/.docker`, or another persistent
runner home.
