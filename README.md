# Codestra Keycloak

GitOps repository for the Codestra identity service.

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

The protected managed-client boundary is explicit in
`config/policy/managed-clients.json`. It contains the twelve machine clients,
`klyrow-portal`, and the three MoneyBee browser clients. Creation is separately
allowlisted in `config/policy/creatable-clients.json`; Klyrow remains update-only.

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
  apply-plan.sh               Race-safe apply with durable recovery evidence
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
