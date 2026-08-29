# Codestra Keycloak GitOps runbook

## Canonical identity endpoint

```text
Public URL:                    https://auth.codestra.co
Canonical issuer:              https://auth.codestra.co/realms/codestra
Target realm:                  codestra
Administrative auth realm:     master
```

Applications discover authorization, token, logout, user-info, and signing-key
endpoints through the `codestra` realm discovery document. The exact expected
endpoint contract is versioned in `config/endpoints/codestra.json`.

The protected deployment identity authenticates through the `master` realm but
all reviewed client administration continues to target the `codestra` realm.
This split is deliberate: `KC_ADMIN_REALM=master` controls where the deployment
service obtains its administrative token, while `KC_TARGET_REALM=codestra`
controls which realm may be read or mutated by the reviewed plan.

## Active administration scope

The protected normal workflow manages exactly the client IDs listed in
`config/policy/managed-clients.json`:

- `klyrow-portal`
- `moneybee-admin`
- `moneybee-borrower`
- `moneybee-lender`

It treats the `codestra` realm file as a validation invariant and never creates
or mutates a realm.

Client creation is a separate, narrower policy. Only the three MoneyBee IDs in
`config/policy/creatable-clients.json` may receive a reviewed `create` action.
`klyrow-portal` remains update-only: if it is absent, the plan reports
`blocked_missing`.

A missing creatable MoneyBee client does not authorize an immediate write. The
check plan must record the exact absent state, desired-state hash, `create`
action, and disable-first/separate-reviewed-delete rollback metadata. Apply then
rechecks all reviewed create targets are still absent immediately before the
first mutation. Any race invalidates the whole plan before writes begin.

Use a dedicated protected Keycloak administration identity for this workflow.
Do not place its credential in Git, shell history, the runtime checkout, or
operator logs. The `production` GitHub Environment should provide these
non-secret variables:

```text
KC_BASE_URL=https://auth.codestra.co
KC_PUBLIC_URL=https://auth.codestra.co
KC_TARGET_REALM=codestra
KC_ADMIN_REALM=master
```

and these values only as Environment secrets:

```text
KC_ADMIN_CLIENT_ID
KC_ADMIN_CLIENT_SECRET
```

The credential must have only the Keycloak permissions actually required by the
reviewed managed operations. If the deployed Keycloak version cannot grant
client-create capability without a broader realm-level permission, do not
silently broaden the identity: keep create operations blocked until that
administrative permission change is separately reviewed and approved.

The twelve machine identities in `config/contracts/machine-clients.json` are
active protected desired state. Each is a distinct confidential service-account
client. Generated overlays and rollback allowlists are checked against the
caller-to-audience matrix; shared credentials are neither declared nor accepted.

## Pull-request validation

CI runs the full validation, Compose render, plan-gate tests, and image build for:

1. the exact pull-request source-head SHA
2. GitHub's synthetic merge result against current `main`

Both check contexts must be required on protected `main`. A dismissed or stale
review is not approval of a later head. Any push changes the SHA that must be
covered by CI and fresh approval.

## Runtime preflight

The manual preflight requires the exact selected `${{ github.sha }}` and verifies:

- canonical non-symlink runtime paths
- private runtime environment and SSH material
- clean runtime repository on `main`
- runtime repository HEAD equals the selected SHA
- remote `main` equals the selected SHA
- exact repository SSH origin
- dedicated Ed25519 deploy-key fingerprint
- a dedicated `known_hosts` file containing only explicit `github.com` entries
- SSH read access with global and user SSH trust disabled

It reports a stable path fingerprint and a release-identity hash. It does not
fetch, pull, restart, reload, or call a mutating Keycloak endpoint.

## Merge before production check

The protected `Deploy Keycloak configuration` workflow is intentionally guarded
so deployment must run from `refs/heads/main`. Its `confirm_sha` must exactly
equal the selected `GITHUB_SHA`.

Therefore, never dispatch a production check against a PR-branch SHA. The order
is:

1. freeze an exact PR head;
2. obtain successful source-head and merge-result CI for that unchanged head;
3. obtain fresh independent approval applying to that exact head;
4. merge through protected `main`;
5. record the resulting exact 40-character `main` SHA;
6. dispatch production `check` mode with `confirm_sha` equal to that `main` SHA.

## Check, independent drift review, and protected apply

Run **Deploy Keycloak configuration** in `check` mode first. It creates:

```text
plan.json
plan.canonical.json
plan.sha256
evidence.json
```

The plan is deterministic: it contains no timestamp and includes the exact Git
SHA, target environment, canonical API URLs, managed current values, desired
values, pre-change hashes, create/update/noop actions, and rollback metadata.

Review every action through **Review Keycloak drift**. `blockedCount` must be
zero before review is eligible. For a
`create`, verify the plan recorded `before: {}` and the exact intended client ID.
Record the successful check run ID and `PLAN_SHA256`. The reviewer must differ
from the change author and records a change ticket. The review artifact binds
every action and before/desired hash to the plan, repository SHA, and environment.

Apply must use:

- the same merged `main` SHA;
- the same protected environment;
- the successful check-run ID;
- the exact reviewed plan SHA-256.
- the exact independent drift-review run and artifact SHA-256.

Apply verifies the source run and artifact, confirms the human-approved hash,
rechecks every existing pre-change hash, then rechecks every reviewed create is
still absent immediately before the first write. Mutating Keycloak calls are not
automatically retried.

After apply, the planner is regenerated and apply requires all of:

```text
driftCount=0
blockedCount=0
createCount=0
updateCount=0
```

Only then may the read-only OIDC smoke tests be treated as post-apply evidence.

## Rollback

Before apply, `export-client.sh` creates rollback evidence using the reviewed
client-specific allowlists under `config/export-allowlists/`.

For clients that already exist, the artifact contains an allowlisted before-state
overlay. Restore that state only through another reviewed check/plan/apply cycle.

For a reviewed create whose pre-apply state is absent, the rollback artifact
records:

- `preApplyState=absent`;
- disable first (`enabled=false`);
- deletion only after disable;
- deletion requires a separate reviewed rollback authorization.

Do not bypass the plan/hash/environment boundary to delete a newly created
client. A PostgreSQL restore is reserved for database-level failure and is not
the normal rollback method for a client redirect, mapper, or scope change.
