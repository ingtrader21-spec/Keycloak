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
and audience. The twelve recommended machine identities are declared in
`config/contracts/machine-clients.json`; they are deliberately marked
`declared-not-created` until caller-to-audience access contracts and client-
specific fine-grained administration are independently reviewed.

The normal protected apply remains scoped to the existing `klyrow-portal`
client. It cannot create realms or clients and does not require `manage-realm`
or realm-wide `manage-clients`.

## Secure change flow

1. Create a feature branch and edit reviewed desired state.
2. Open a pull request.
3. Run CI for the exact source-head SHA and GitHub's synthetic merge-result SHA.
4. Obtain independent review and merge through protected `main`.
5. Synchronize the server's read-only checkout to the exact merged SHA.
6. Run **Verify Keycloak runtime paths** for that exact SHA.
7. Independently approve the stable runtime-path fingerprint.
8. Run **Deploy Keycloak configuration** in `check` mode.
9. Review `plan.json`, the run ID, and `PLAN_SHA256`.
10. Run the same workflow in `apply` mode with the prior run ID and reviewed hash.
11. The workflow downloads that exact artifact, verifies the hash, rechecks every
    live pre-change hash, exports an allowlisted rollback overlay, applies only
    the reviewed plan, verifies convergence, and runs the OIDC smoke test.

A merge never changes the live Keycloak instance. `apply` cannot run without a
successful prior check artifact for the same environment and exact commit SHA.

## Repository layout

```text
config/
  clients/                    Active Git-managed client overlays
  contracts/                  Declared identity contracts not yet provisioned
  endpoints/                  Canonical issuer and API endpoint contract
  export-allowlists/          Per-client rollback export allowlists
  github/                     Desired main-branch ruleset
  policy/                     Explicit active managed-client boundary
  realms/                     Read-only realm invariant
scripts/
  validate-workflows.py       Parsed YAML Actions policy validator
  validate.sh                 Desired-state, endpoint, secret, and syntax policy
  runtime-preflight.sh        Read-only paths, SHA, host-key, and SSH read access
  plan.sh                     Deterministic, non-mutating drift plan generator
  apply-plan.sh               Reviewed plan-hash and optimistic-state apply
  export-client.sh            Client-specific allowlisted rollback export
  reconcile.sh                Check wrapper; direct unplanned apply is disabled
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

CI additionally validates Docker Compose and builds the pinned Keycloak image
without publishing it.

## Governance that remains external to Git

Repository rules, protected GitHub Environments, reviewer identities,
service-account secrets, and the server deploy key are configured outside the
public repository. `config/github/main-ruleset.json` records the required `main`
policy, but an administrator must apply it after both CI check contexts exist.

See `docs/GITOPS.md`, `docs/GITHUB_SECURITY.md`, and
`docs/SERVER_GIT_SSH.md` for the operating procedure.
