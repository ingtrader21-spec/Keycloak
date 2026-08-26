# Codestra Keycloak

GitOps repository for the Codestra identity service at `https://auth.codestra.co`.

This repository manages **reviewable Keycloak desired state**, deployment packaging, validation, drift checks, and controlled application of configuration. It intentionally does not store the Keycloak database, users, passwords, client secrets, private keys, access tokens, or recovery codes.

## Current managed fix

The `klyrow-portal` OIDC client is declared with the exact production callback currently sent by Klyrow:

```text
https://klyrow.com/
```

The client is configured as a browser/public client using Authorization Code Flow with PKCE `S256`. Implicit flow, password/direct grants, service accounts, wildcard redirects, and wildcard web origins are disabled.

## Repository layout

```text
config/
  realms/                 Safe realm-level desired-state overlays
  clients/                One declarative JSON file per OIDC/SAML client
deploy/caddy/              Reverse-proxy snippet for auth.codestra.co
scripts/
  lib/keycloak-admin.sh    Authentication and Admin REST helpers
  validate.sh              Offline policy and syntax validation
  reconcile.sh             Idempotent check/apply reconciler
  export-client.sh         Sanitized pre-change export for rollback/adoption
  smoke-test.sh            Read-only OIDC and redirect validation
.github/workflows/
  validate.yml             Pull-request and main-branch validation
  deploy.yml               Manual, environment-gated check/apply workflow
```

## Change flow

1. Create a branch.
2. Edit the appropriate JSON under `config/`.
3. Open a pull request.
4. Let `validate.yml` verify JSON, shell scripts, Docker Compose, the container build, redirect safety, PKCE, and secret policy.
5. Merge the reviewed commit.
6. Run **Deploy Keycloak configuration** in `check` mode.
7. Review the reported drift.
8. Run the same workflow in `apply` mode through the protected GitHub Environment.
9. Confirm the read-only smoke test passes.

The deploy workflow is manual by design. A merge does not silently alter production identity configuration.

## Local validation

```bash
make validate
```

## Local container test environment

```bash
cp .env.example .env
# Replace every CHANGE_ME value in .env.
docker compose up -d --build
```

Caddy should proxy only to Keycloak's loopback HTTP listener. The management port stays on loopback and must not be exposed publicly.

## Check live drift

Use a least-privilege Keycloak service-account client and export its secret into the current shell:

```bash
export KC_BASE_URL="https://auth.codestra.co"
export KC_TARGET_REALM="codestra"
export KC_ADMIN_REALM="codestra"
export KC_ADMIN_CLIENT_ID="keycloak-gitops"
export KC_ADMIN_CLIENT_SECRET="<secret>"

./scripts/reconcile.sh --check
```

Apply only after review:

```bash
./scripts/export-client.sh --output ./artifacts/before klyrow-portal
./scripts/reconcile.sh --apply
./scripts/smoke-test.sh
```

## Required GitHub Environment configuration

Create `staging` and `production` environments. Require approval for `production`, then configure:

Variables:

- `KC_BASE_URL`
- `KC_PUBLIC_URL`
- `KC_TARGET_REALM`
- `KC_ADMIN_REALM`

Secrets:

- `KC_ADMIN_CLIENT_ID`
- `KC_ADMIN_CLIENT_SECRET`

The workflow expects a self-hosted runner labeled:

```text
self-hosted, linux, x64, codestra-keycloak
```

See [docs/GITOPS.md](docs/GITOPS.md) for bootstrap, rollback, and operating rules.
