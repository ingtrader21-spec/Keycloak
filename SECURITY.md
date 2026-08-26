# Security policy

## Never commit

- passwords, password hashes, or client secrets
- Keycloak access or refresh tokens
- private keys, keystores, signing material, or private certificates
- OTP seeds, recovery codes, or WebAuthn private material
- production users, sessions, PostgreSQL data, or database backups
- live environment files or SSH configuration containing private material
- SMTP, SMS, Odoo, n8n, Kong, Caddy, or cloud-provider credentials

Use protected GitHub Environment secrets or the approved external secret store.

## Identity boundaries

The canonical issuer is:

```text
https://auth.codestra.co/realms/codestra
```

Browser clients use Authorization Code Flow with PKCE `S256`. Machine services
use separate confidential clients and short-lived Client Credentials tokens.
Secrets are generated and rotated outside Git.

The normal GitOps service account must not receive `manage-realm` or realm-wide
`manage-clients`. It is scoped to `klyrow-portal` using Keycloak fine-grained
administrative permissions plus only the minimum client-discovery permission
required by the deployed Keycloak version.

## Git and deployment identities

The server uses a repository-scoped deploy key with GitHub write access disabled.
The preflight proves SSH **read access** only; the write-disabled setting must be
verified independently in GitHub. The SSH command ignores user and global SSH
configuration and trusts only the dedicated pinned `github.com` host-key file.

## Change control

Production apply requires all of the following:

1. exact protected `main` SHA confirmation
2. runtime checkout and remote `main` equal to that exact SHA
3. approved runtime-path fingerprint
4. a successful prior `check` run for the same SHA and environment
5. reviewed deterministic plan SHA-256
6. unchanged live pre-change hashes for every managed client
7. client-specific allowlisted rollback artifact
8. convergence verification and read-only OIDC smoke test

Direct, unplanned mutation and automatic retries of ambiguous mutating requests
are prohibited.

## Incident handling

Rotate exposed credentials immediately, invalidate sessions when appropriate,
review GitHub Actions and Keycloak admin events, rerun runtime preflight after
SSH material changes, and record the exact incident and rotation times.
