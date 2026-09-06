# Codestra Keycloak

GitOps repository for the Codestra identity service.

> **Repository authority:** this is the independent Git authority for Codestra Keycloak desired state and protected identity changes. Other repositories consume its versioned identity contracts; they do not control or directly mutate Keycloak. See [`docs/KEYCLOAK_REPOSITORY_AUTHORITY.md`](docs/KEYCLOAK_REPOSITORY_AUTHORITY.md). The cross-repository rollout sequence starts in [`docs/CODESTRA_MISSION_PLAN.md`](docs/CODESTRA_MISSION_PLAN.md).

```text
Public URL:       https://auth.codestra.co
Canonical issuer: https://auth.codestra.co/realms/codestra
Discovery:        https://auth.codestra.co/realms/codestra/.well-known/openid-configuration
```

The repository manages reviewable desired state, exact-source and merge-result
CI, runtime identity verification, deterministic drift plans, protected apply,
and read-only OIDC acceptance checks. It never stores client secrets, user
credentials, access tokens, private keys, OTP seeds, signing material, database
data, or live server environment files.

## Authentication policy

Human browser clients use Authorization Code Flow with PKCE `S256`. Implicit
flow and password/direct grants are prohibited.

Machine clients use confidential service accounts with short-lived Client
Credentials tokens. Every service receives its own client ID, scope namespace,
and audience. The twelve required machine identities are active protected
desired state. Their generated overlays are confidential service-account
clients with five-minute tokens, disabled browser/password flows, no redirect
origins, `fullScopeAllowed=false`, and only reviewed audiences and scopes.
Keycloak generates a distinct credential for every client; none enters Git.

The community-edition n8n editor uses the confidential `n8n-editor-gateway`
client through oauth2-proxy. It permits Authorization Code with PKCE S256 only,
has exact production/staging callback origins, and receives no service account
or password grant. Runtime calls continue to use the separately governed
`n8n-automation` Client Credentials identity.

The protected managed-client boundary is explicit in
`config/policy/managed-clients.json`. It contains the twelve machine clients,
`klyrow-portal`, and the three MoneyBee browser clients. Creation is separately
allowlisted in `config/policy/creatable-clients.json`; `klyrow-portal` is
creatable only through the reviewed plan/apply gate with disable-first and
separate-reviewed-delete rollback metadata.

MoneyBee uses three public PKCE clients:

- `moneybee-borrower` -> `https://app.moneybeeloan.com`
- `moneybee-lender` -> `https://lenders.moneybeeloan.com`
- `moneybee-admin` -> `https://admin.moneybeeloan.com`

Each MoneyBee client includes the reviewed `moneybee-api-audience` mapper so
access tokens contain the `moneybee-api` audience required by the backend.

## Secure change flow

1. Create a feature branch and edit reviewed desired state.
2. Open a pull request.
3. Run CI for the exact source-head SHA and GitHub's synthetic merge-result SHA.
4. Obtain fresh independent review for that unchanged exact head.
5. Merge through protected `main`.
6. Record the resulting exact merged `main` SHA.
7. Synchronize the server's read-only checkout to that exact merged SHA.
8. Run **Verify Keycloak runtime paths** for that exact SHA.
9. Independently approve the stable runtime-path fingerprint.
10. Run **Deploy Keycloak configuration** in `check` mode from `main`, with
    `confirm_sha` exactly equal to the selected `GITHUB_SHA`.
11. Review every plan action through **Review Keycloak drift**. The reviewer
    must differ from the change author; record its run ID and review hash.
12. Run `apply` with that main SHA, check run/hash, review run/hash, and the
    protected production approval.
13. Apply rechecks both artifacts, all existing pre-change hashes, and every reviewed create's
    absence before the first write, applies only the reviewed plan, regenerates
    the plan, requires zero drift/blocked/create/update actions, and runs the
    read-only OIDC smoke test.

A merge never changes the live Keycloak instance. A PR-branch SHA is never a
valid production-check SHA. `apply` cannot run without successful prior check
and independent drift-review artifacts for the same environment and exact
merged `main` commit.

## Repository layout

```text
config/
  clients/                    Active Git-managed client overlays
  contracts/                  Declared identity contracts not yet provisioned
  endpoints/                  Canonical issuer and API endpoint contract
  export-allowlists/          Per-client rollback export allowlists
  github/                     Desired main-branch ruleset
  identity/                   Canonical application/domain and portal contracts
  policy/                     Managed and separately creatable client boundaries
  realms/                     Read-only realm invariant
scripts/
  validate-workflows.py       Parsed YAML Actions policy validator
  validate.sh                 Desired-state, endpoint, secret, and syntax policy
  runtime-preflight.sh        Read-only paths, SHA, host-key, and SSH read access
  plan.sh                     Deterministic, non-mutating drift/create plan
  apply-plan.sh               Reviewed plan-hash and optimistic-state apply
  export-client.sh            Existing/absent rollback evidence export
  reconcile-moneybee-oidc.sh  Read-only MoneyBee view of protected plan engine
  smoke-test.sh               Read-only discovery and redirect acceptance test
.github/workflows/
  validate.yml                Exact source-head and merge-result CI
  runtime-preflight.yml       Manual read-only server verification
  deploy.yml                  Manual plan/check and reviewed-plan apply
```

## Local validation

```bash
make validate
```

CI additionally validates Docker Compose, exercises the protected plan gate,
and builds the pinned Keycloak image without publishing it.

## PostgreSQL recovery evidence

`scripts/backup-postgres.sh` publishes an encrypted custom-format dump and its
checksum under a non-blocking publication lock. It refuses timestamp
collisions and syncs the artifact, checksum, and destination directory before
reporting success. Database credentials are supplied only through a protected
PostgreSQL passfile.

`scripts/verify-backup.sh` requires an explicitly isolated restore database,
validates the encrypted artifact checksum and archive inventory, performs the
restore, verifies the required Keycloak `realm` and `client` tables, and then
atomically publishes checksum-bound restore evidence. It refuses the source
database identity. `scripts/check-recovery-freshness.sh` accepts only complete,
checksum-valid, successful restore evidence inside the configured age limit.
These commands are operational authorities; source validation does not prove
that a live backup or restore test has occurred.

Production Compose requires `KEYCLOAK_IMAGE` to be an approved GHCR release reference in `repository:source-SHA@sha256:digest` form. The protected manual image-release workflow builds once, publishes SBOM and provenance attestations, scans the exact digest, and emits checksummed release evidence; it never deploys Keycloak.

## Governance that remains external to Git

Repository rules, protected GitHub Environments, reviewer identities,
service-account secrets, and the server deploy key are configured outside the
repository. `config/github/main-ruleset.json` records the required `main`
policy, but an administrator must apply it after both CI check contexts exist.

The protected Keycloak administration credential must not be broadened merely
because Git now supports reviewed MoneyBee client creation. If the deployed
Keycloak version requires additional administrative permission to create a
client, that credential change requires a separate security review and approval.

See `docs/GITOPS.md`, `docs/GITHUB_SECURITY.md`,
`docs/MONEYBEE_OIDC_CLIENTS.md`, and `docs/SERVER_GIT_SSH.md` for operating
procedures.
