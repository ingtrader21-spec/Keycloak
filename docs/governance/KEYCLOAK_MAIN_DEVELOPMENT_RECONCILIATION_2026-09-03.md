# Keycloak main-to-development authority reconciliation

Date: 2026-09-03

## Exact ancestry

```text
protected_main_sha=3d8cd0483a178100b679b2c3f0f4d4ca36fe161c
previous_development_sha=18c130af174dc791222355fa6178422bd6cb30d2
merge_base_sha=92ca388323db23c1f308ce4e33d9f36b0c77c74e
protected_main_unique_commits=19
development_unique_commits=30
development_delta_paths=49
target_branch=sync/main-development-reconciled-20260903
tree_authority=protected main
history_preserved=true
force_update=false
```

## Resolution

The development-only history is preserved as the merge commit's second parent,
but its tree is intentionally superseded by current protected `main`.

Repository comparison showed that all 30 development-only commits belong to an
older observability managed-identity implementation. That overlay attempted to
place Grafana, Superset, and OpenBao browser clients into live-capable managed and
creatable policies, while current protected `main` intentionally keeps those
identities repository-only, requires MFA for every bound role, uses OpenBao-backed
runtime secret files, and sets `liveApplyAuthorized=false`.

The old development overlay also replaced the hardened plan, review, apply,
rollback-evidence, and plan-gate scripts with small wrappers around a parallel
engine. Keeping both authorities produced contradictory policies and failed the
repository's own validators. The protected-main tree is therefore retained as
the single source of truth; commit ancestry remains auditable and no branch is
force-updated.

## Required follow-up

This merge commit must enter `development` through a reviewed pull request.
Afterward, feature branches must rebase on the reconciled development head and
pass exact-head source and merge-result validation. This source reconciliation
does not authorize a live realm plan or apply.

## Safety

```text
KEYCLOAK_RUNTIME_CONTACTED=false
KEYCLOAK_RUNTIME_APPLY=false
REALMS_CHANGED=0
CLIENTS_CHANGED=0
USERS_CHANGED=0
SECRETS_READ=0
SECRETS_WRITTEN=0
TOKENS_ISSUED=0
SSH_CHANGED=false
DNS_CHANGED=false
PRODUCTION_RUNTIME_CHANGED=false
```
