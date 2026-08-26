# Codestra Keycloak GitOps Runbook

## Scope

This repository controls reviewed configuration overlays for the `codestra` realm and its managed clients. It does not replace PostgreSQL backups and it must never contain user exports, credentials, OTP seeds, client secrets, private keys, SMTP passwords, or signing keys.

Keycloak startup realm import is useful for a new environment, but it does not provide reliable ongoing updates to an already-existing realm. Ongoing production changes are therefore applied by the idempotent Admin REST reconciler.

## One-time deployment identity

Create a confidential client named `keycloak-gitops` in the `codestra` realm:

- Client authentication: enabled
- Service accounts: enabled
- Standard flow: disabled
- Direct access grants: disabled

Assign only these service-account roles from the `realm-management` client:

- `view-realm`
- `manage-realm`
- `view-clients`
- `manage-clients`

Store the client ID and secret in the protected GitHub Environment. Do not put them in repository files, workflow source, shell history, screenshots, issue comments, or pull-request comments.

For stricter separation, use different clients and secrets for staging and production.

## Required self-hosted runner

The deploy workflow intentionally uses a runner labeled:

```text
self-hosted
linux
x64
codestra-keycloak
```

Install the runner on a hardened management host that can reach the Keycloak Admin REST API. The runner account should not be root and should not have unrestricted Docker, sudo, or SSH privileges unless an approved deployment step specifically requires them.

## Pull-request rules

Every client change should be isolated to its own branch when practical. A redirect-URI change must show:

- exact requested URI
- exact client ID
- whether the client is public or confidential
- PKCE policy
- web origin
- post-logout redirect
- staging test evidence
- rollback snapshot

Do not merge changes containing `*`, `+`, or broad `/*` redirect patterns without an explicit security exception.

## Check and apply

Check mode is read-only:

```bash
./scripts/reconcile.sh --check
```

Exit codes:

- `0`: desired state and live state are synchronized
- `2`: drift exists
- any other nonzero code: authentication, authorization, transport, policy, or API failure

Apply mode updates only the declared overlays, then automatically runs another check:

```bash
./scripts/reconcile.sh --apply
```

## Adoption of an existing client

Export the live client before replacing hand-managed configuration:

```bash
./scripts/export-client.sh --output ./artifacts/adoption klyrow-portal
```

The export removes internal IDs and common secret-bearing fields. Review it again before committing because custom providers can add additional sensitive attributes.

## Rollback

Every `apply` workflow stores a sanitized pre-change artifact for 30 days.

1. Download the matching `keycloak-before-...` artifact.
2. Inspect the JSON.
3. Point the reconciler at the downloaded configuration root.
4. Apply through the same protected environment.
5. Run the smoke test.

Example:

```bash
CONFIG_ROOT="$PWD/keycloak-before/config" ./scripts/reconcile.sh --apply
./scripts/smoke-test.sh
```

A PostgreSQL restore is reserved for database-level failure and must follow the separate backup/restore procedure. Do not use a database rollback merely to reverse one client redirect.

## Klyrow acceptance check

The managed Klyrow authorization request must use:

```text
client_id=klyrow-portal
redirect_uri=https://klyrow.com/
response_type=code
code_challenge_method=S256
```

A fresh browser transaction should show the Codestra login page instead of `Invalid parameter: redirect_uri`.
