# Codestra Keycloak GitOps runbook

## Canonical identity endpoint

```text
Public URL:       https://auth.codestra.co
Canonical issuer: https://auth.codestra.co/realms/codestra
```

Applications discover authorization, token, logout, user-info, and signing-key
endpoints through the realm discovery document. The exact expected endpoint
contract is versioned in `config/endpoints/codestra.json`.

## Active administration scope

The protected normal workflow manages only `klyrow-portal`. It treats the
`codestra` realm file as a validation invariant and never creates or mutates a
realm. Missing clients are blocked rather than created.

Create a confidential service-account client dedicated to this workflow. Disable
browser and password flows. Do not grant `manage-realm` or realm-wide
`manage-clients`. Use Keycloak fine-grained administrative permissions on the
`klyrow-portal` client for only the read/configure operations needed to inspect
and update that client. Grant only the smallest discovery permission needed to
resolve the client by ID.

The twelve machine identities in `config/contracts/machine-clients.json` are a
reviewed naming and flow contract, not active provisioning. Each client must be
promoted in its own pull request after its caller-to-audience map, scopes,
secret destination, token lifetime, fine-grained administrative scope, and
rollback policy are approved.

## Pull-request validation

CI runs the full validation, Compose render, and image build twice:

1. exact pull-request source-head SHA
2. GitHub's synthetic merge result against current `main`

Both check contexts must be required on protected `main`.

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

## Check and reviewed-plan apply

Run **Deploy Keycloak configuration** in `check` mode first. It creates:

```text
plan.json
plan.canonical.json
plan.sha256
evidence.json
```

The plan is deterministic: it contains no timestamp and includes the exact Git
SHA, target environment, canonical API URLs, managed current values, desired
values, and pre-change hashes.

Review the plan artifact, record the workflow run ID and the SHA-256 value, then
run `apply` with both. Apply verifies the source run, downloads that exact
artifact, confirms the human-approved hash, and rechecks every live pre-change
hash before the first write. Any intervening drift invalidates the complete
plan.

Mutating Keycloak calls are not automatically retried. After apply, the workflow
regenerates the plan and requires zero drift, then runs the OIDC smoke test.

## Rollback

Before apply, `export-client.sh` creates a rollback overlay using the reviewed
client-specific allowlist under `config/export-allowlists/`. A generic denylist
is not used. Restore the artifact through a new check, review, and apply cycle;
do not bypass the plan gate.

A PostgreSQL restore is reserved for database-level failure and is not the
normal rollback method for a client redirect or scope change.
