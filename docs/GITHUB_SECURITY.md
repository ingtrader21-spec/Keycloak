# GitHub security baseline

## `main` protection

The repository versions two ruleset documents because GitHub evaluates
`CODEOWNERS` from the pull request's base branch.

### Bootstrap ruleset

`config/github/bootstrap-main-ruleset.json` is used only to merge the pull
request that first places the independent CODEOWNER on `main`. It requires:

- pull requests
- one approval from someone other than the last pusher
- stale approvals dismissed after new commits
- all review conversations resolved
- only squash merge
- `validate-source`
- `validate-merge-result`
- strict up-to-date status checks
- force pushes blocked
- branch deletion blocked

The bootstrap rule intentionally leaves `require_code_owner_review` disabled,
because the base branch does not yet contain `@kazan555` in `CODEOWNERS`.

### Final ruleset

Immediately after the protected squash merge, replace the bootstrap rule with
`config/github/main-ruleset.json`. The final rule keeps every bootstrap control
and additionally requires CODEOWNER review.

The `.github/CODEOWNERS` file assigns `@appolon1908-hue` and `@kazan555` to the
repository and to all identity configuration, workflow, script, deployment, and
security-runbook paths. `require_last_push_approval` prevents the last pusher
from satisfying the approval gate.

No administrator bypass actor is declared in either ruleset.

## Actions policy

- workflow token permissions remain read-only
- pull-request jobs use GitHub-hosted runners only
- privileged jobs are `workflow_dispatch`-only
- no `pull_request_target`
- no pull-request secrets or protected Environments
- no job-level permission overrides
- every external action is allowlisted and pinned to an exact reviewed SHA
- checkout credentials are never persisted
- source-head and merge-result identities are validated separately

Pinned revisions:

```text
actions/checkout          3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
actions/upload-artifact   043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  # v7.0.1
actions/download-artifact 3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c  # v8.0.1
```

## Protected Environments

Create separate `staging` and `production` Environments. Restrict production to
`main`, require an independent reviewer, and prevent self-review when available.

Required variables:

```text
KC_BASE_URL=https://auth.codestra.co
KC_PUBLIC_URL=https://auth.codestra.co
KC_TARGET_REALM=codestra
KC_ADMIN_REALM=master
RUNTIME_REPO_DIR
RUNTIME_COMPOSE_FILE
RUNTIME_ENV_FILE
RUNTIME_CADDY_FILE
RUNTIME_GIT_SSH_KEY
RUNTIME_GIT_KNOWN_HOSTS
RUNTIME_GIT_REMOTE=git@github.com:appolon1908-hue/Keycloak.git
RUNTIME_GIT_BRANCH=main
RUNTIME_PATHS_APPROVED_SHA256
```

`KC_ADMIN_REALM=master` is the administrative authentication realm only. The
protected planner and apply engine must continue to target `KC_TARGET_REALM=codestra`.
The admin credential does not authorize mutation of `master` realm resources.

Required secrets:

```text
KC_ADMIN_CLIENT_ID
KC_ADMIN_CLIENT_SECRET
```

Use different fine-grained Keycloak service-account clients and secrets for
staging and production. Neither identity may receive `realm-admin`,
`manage-realm`, or unrestricted realm-wide `manage-clients`. Any permission
required for reviewed creation of the explicitly creatable MoneyBee clients must
be separately reviewed and limited to the smallest Keycloak administrative scope
supported by the deployed version.
