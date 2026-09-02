# Repository-name migration and Keycloak dependency safety

Six Codestra repositories have approved corrected names, but none is considered renamed until GitHub readback proves the same stable repository ID at the approved target full name.

The Keycloak repository does not own those renames. It records their stable IDs so identity and staging workflows do not silently follow a different repository with a matching slug.

## Current migration state

```text
STATUS=PREPARED_NOT_RENAMED
IDENTITY_KEY=repository_id
HISTORICAL_EVIDENCE_IMMUTABLE=YES
```

Machine-readable mappings are in [`../config/policy/repository-name-aliases.v1.json`](../config/policy/repository-name-aliases.v1.json).

The account-wide authority remains `appolon1908-hue/documentaions:repository-name-migration.v1.json` until that repository completes its own controlled rename.

## Runtime-preflight rule

The existing Stage 6 workflow checks out:

```text
appolon1908-hue/Infustruction-repo
```

at an exact `INFRASTRUCTURE_SHA`. That current name remains correct before cutover. The future target `appolon1908-hue/Codestra-Infrastructure` must not be used by Keycloak Actions until all of the following are true:

1. GitHub reports repository ID `1350724865` at the target full name;
2. the default and selected exact SHAs are unchanged;
3. branch protection, rulesets, Environments, deploy keys, GitHub Apps, packages, and workflow permissions are read back successfully;
4. the infrastructure authority publishes an accepted post-rename manifest;
5. this Keycloak repository receives a reviewed PR changing the mutable workflow reference;
6. exact-head and merge-result validation pass;
7. runtime preflight proves the same source and no identity apply occurs merely because of the rename.

## Keycloak-specific inventory before a dependency rename

Record, without secret values:

- every Actions checkout or reusable-workflow repository reference;
- exact cross-repository SHAs and artifact digests;
- GitHub Environment names and protected variable/secret **names**;
- deploy-key fingerprints and GitHub App repository access;
- runtime Git remotes and read-only checkout paths;
- Keycloak desired-state source references, plan hashes, review hashes, and rollback exports;
- current issuer, realm, clients, scopes, audiences, and redirect origins as read-only evidence.

## Safety requirements

A dependency repository rename must not:

- apply Keycloak desired state;
- create, update, disable, or delete a realm/client/user/role/group;
- rotate client secrets or signing keys;
- change issuer, redirect, logout, or web-origin contracts;
- restart Keycloak;
- change DNS or Caddy/Kong routing;
- alter production authentication traffic.

Required metadata-only result:

```text
KEYCLOAK_CONFIG_APPLIES=0
CLIENTS_CHANGED=0
USERS_CHANGED=0
SECRETS_ROTATED=0
WORKLOADS_RESTARTED=0
PRODUCTION_AUTH_TRAFFIC_CHANGED=NO
```

## Validation

```bash
python scripts/validate-repository-name-authority.py
```

The validator requires all six exact stable-ID mappings, keeps the current infrastructure repository in the active runtime-preflight workflow, rejects the target name before cutover, and requires the exact infrastructure SHA plus credential-free checkout behavior.