# Keycloak pull-request reconciliation — 2026-09-03

## Scope

This repository review covers every open and draft pull request at its exact current head. The review surface includes branch direction, changed files, mergeability, required checks, independent approval, active review threads, duplicate work, source/runtime boundaries, identity configuration, supply-chain controls and rollback evidence.

## Protected source path

Repository work enters the integration branch only through a governed temporary branch:

```text
remediation/* | security/* | upgrade/* | hotfix/* | sync/*
  -> development
  -> test
  -> staging
  -> production
  -> main
```

A later protected branch may be promoted only from the immediately preceding protected branch. A source branch must not skip `development`, `test` or `staging` merely because its change is documentation-only or a check is inconvenient.

## Exact-head merge rule

A pull request is not merge-authorized unless all of the following are true at the same immutable head SHA:

1. the pull request is not a draft;
2. the source and target branches follow the protected promotion path;
3. GitHub reports a clean mergeable state;
4. all required checks exist, are bound to the current head and are successful;
5. no required check is absent, pending, stale, cancelled, timed out, action-required or failed;
6. no active non-outdated review thread remains unresolved;
7. no current review requests changes;
8. an independent reviewer approved the current exact head;
9. the expected head has not moved between approval and merge.

The read-only auditor in `scripts/ci/audit_keycloak_pull_requests.py` records these conditions without merging, updating, dismissing or bypassing any pull request.

## Draft rules

A promotion pull request remains draft when its source branch does not yet contain a required remediation, when exact-head checks are incomplete, when active review findings remain, when rollback/recovery evidence is missing or when an upstream repository dependency has not protected-merged.

A draft is not made ready merely to trigger deployment. Readiness means the source itself is reviewable, tests are complete and the remaining work is independent approval rather than implementation.

## Duplicate and stale work

A pull request may be closed as superseded only when another current review surface contains the same exact tree or demonstrably contains every unique change. Similar titles, overlapping files or an older base alone are insufficient evidence.

Valid unique changes from a stale or wrong-base branch must be replayed onto a current governed remediation branch before the old review surface is closed.

## Keycloak safety boundary

Repository merge does not by itself authorize:

- realm import or mutation;
- client, scope, mapper, role, group or user changes;
- credential, key, token or password issuance;
- session revocation in a live realm;
- DNS, TLS, Caddy, Kong, firewall, SSH or server changes;
- staging or production deployment;
- external email, SMS, dialing, advertising, publishing, payment, trading or provider effects.

Runtime application requires a separately protected plan, exact source and image identity, backup and rollback evidence, environment approval and post-apply readback.

```text
KEYCLOAK_RUNTIME_APPLY=false
REALMS_CHANGED=0
CLIENTS_CHANGED=0
USERS_CHANGED=0
SECRETS_WRITTEN=0
TOKENS_ISSUED=0
PRODUCTION_CHANGED=false
SSH_CHANGED=false
```

## Continuous review

The scheduled audit emits bounded JSON and Markdown evidence containing each PR number, draft status, base/head refs and SHAs, exact-head check results, unresolved-thread count, review decision, promotion-path result and merge authorization outcome. Unknown or unavailable evidence fails closed rather than being treated as approval.
