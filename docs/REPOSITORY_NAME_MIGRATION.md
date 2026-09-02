# Repository-name migration and Keycloak dependency safety

Six Codestra repositories have approved corrected names, but none is considered renamed until GitHub readback proves the same stable repository ID at the approved target full name.

The Keycloak repository does not own those renames. It records their stable IDs so identity and staging workflows do not silently follow a different repository with a matching slug.

## Current migration state

```text
STATUS=PREPARED_NOT_RENAMED
IDENTITY_KEY=repository_id
HISTORICAL_EVIDENCE_IMMUTABLE=YES
LIVE_REPOSITORY_IDENTITY=REQUIRED_BEFORE_CUTOVER
```

Machine-readable mappings are in [`../config/policy/repository-name-aliases.v1.json`](../config/policy/repository-name-aliases.v1.json).

The account-wide authority remains `appolon1908-hue/documentaions:repository-name-migration.v1.json` until that repository completes its own controlled rename.

## Offline pull-request validation

Ordinary pull-request and merge-result validation runs:

```bash
python3 scripts/validate-repository-name-authority.py
```

This validates the exact six-ID mapping, current and target names, duplicate protection, immutable-history policy, and the exact Infrastructure checkout block. It does not pretend that the Keycloak-scoped `GITHUB_TOKEN` can read sibling private repositories.

## Protected live GitHub ID gate

Before any repository-name cutover or mutable workflow-reference change, dispatch `.github/workflows/repository-name-live-authority.yml` from the exact reviewed `main` SHA. The protected `production` environment must supply a narrow read-only `CODESTRA_REPOSITORY_READ_TOKEN` that can read metadata for the six private repositories.

The workflow runs:

```bash
python3 scripts/validate-repository-name-authority.py --live
```

The live mode calls GitHub for every current operational slug and requires its returned `full_name` and numeric repository ID to match the mapping. A missing token, inaccessible repository, recreated slug, redirect to another name, API error, or ID mismatch fails closed. Do not expose this cross-repository token to ordinary pull-request jobs.

Required cutover evidence:

```text
KEYCLOAK_MAIN_SHA=<exact-40-character-sha>
LIVE_REPOSITORY_IDENTITY=PASS
CROSS_REPOSITORY_TOKEN_SCOPE=READ_ONLY_METADATA
REPOSITORIES_VERIFIED=6/6
```

## Runtime-preflight rule

The existing Stage 6 workflow checks out:

```text
appolon1908-hue/Infustruction-repo
```

at an exact `INFRASTRUCTURE_SHA`. That current name remains correct before cutover. The validator identifies the specific checkout step and requires that same step—not an unrelated checkout—to contain `persist-credentials: false` and the exact `INFRASTRUCTURE_SHA` ref.

The future target `appolon1908-hue/Codestra-Infrastructure` must not be used by Keycloak Actions until all of the following are true:

1. the protected live gate reports repository ID `1350724865` at the target full name;
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
