# Keycloak protected-promotion branch topology

Date: 2026-09-03  
Repository: `appolon1908-hue/Keycloak`

## Result

The repository now has the intended protected-promotion branch name `test`.

```text
development -> test -> staging -> production -> main
```

The branch was created only after a guarded namespace migration because Git cannot hold both:

```text
refs/heads/test
refs/heads/test/integration-token-matrix-v2
```

## Exact evidence

```text
development_sha=18c130af174dc791222355fa6178422bd6cb30d2
test_sha=18c130af174dc791222355fa6178422bd6cb30d2
legacy_branch=test/integration-token-matrix-v2
legacy_sha=fb2bda91e52385c0f673f358ab3147f93b42b766
archive_branch=archive/integration-token-matrix-v2-20260903
archive_sha=fb2bda91e52385c0f673f358ab3147f93b42b766
legacy_ref_present=false
legacy_pull_request_references=0
workflow_run=33748330902
workflow_job=100625884766
workflow_conclusion=success
```

## Guard conditions used

Before changing refs, the migration required all of the following:

1. `development` still matched the reviewed exact SHA.
2. The legacy branch still matched its reviewed exact SHA.
3. The archive branch existed at the same exact legacy SHA.
4. No `test` promotion branch already existed.
5. No open or closed pull request referenced the legacy branch.

The workflow included rollback logic to recreate the legacy ref if deletion succeeded but creation of `test` failed. Final read-back verified the new `test` ref, the preserved archive ref, and absence of the conflicting legacy ref.

## Remaining production gates

Creating the branch name does not itself make the repository or Keycloak runtime production-ready. Before protected promotion:

- `development`, `test`, `staging`, and `production` require active branch rulesets equivalent to or stronger than the current `main` ruleset;
- current `main` authority must be reconciled into the promotion chain through reviewed pull requests;
- every source promotion must pass exact-head `validate-source` and `validate-merge-result` checks;
- runtime deployment still requires immutable image, backup/restore, drift, realm-plan, rollback, smoke-test, and post-deployment evidence.

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
