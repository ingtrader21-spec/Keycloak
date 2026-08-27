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

The protected managed-client set is versioned in
`config/policy/managed-clients.json`. Client creation is separately constrained
by `config/policy/creatable-clients.json`; only the three reviewed MoneyBee
portal clients are creatable. `klyrow-portal` remains update-only.

MoneyBee access tokens must contain the `moneybee-api` audience. Each MoneyBee
client overlay therefore manages an explicit `oidc-audience-mapper`, and CI
cross-validates that mapper against both the MoneyBee contract and backend
audience expectation.

The protected Keycloak administration identity must have only the permissions
required by the reviewed managed operations. Do not grant `manage-realm` as a
shortcut. If the deployed Keycloak version cannot grant client-create authority
without a broader permission such as realm-wide client management, creation
must remain blocked until that credential-scope change is separately reviewed
and approved.

## Git and deployment identities

The server uses a repository-scoped deploy key with GitHub write access disabled.
The preflight proves SSH **read access** only; the write-disabled setting must be
verified independently in GitHub. The SSH command ignores user and global SSH
configuration and trusts only the dedicated pinned `github.com` host-key file.

## Change control

Production apply requires all of the following:

1. exact protected merged `main` SHA confirmation
2. runtime checkout and remote `main` equal to that exact SHA
3. approved runtime-path fingerprint
4. successful source-head and merge-result CI on the unchanged PR head before merge
5. fresh independent approval applying to that unchanged PR head
6. a successful prior protected `check` run for the resulting merged `main` SHA and environment
7. reviewed deterministic plan SHA-256
8. `blockedCount=0`
9. unchanged live pre-change hashes for every existing managed client
10. reviewed create action only for an allowlisted creatable client whose plan recorded absence
11. a second absence recheck for every reviewed create immediately before the first write
12. client-specific rollback evidence for existing clients and disable/delete metadata for reviewed creates
13. post-apply plan convergence with `driftCount=0`, `blockedCount=0`, `createCount=0`, and `updateCount=0`
14. read-only OIDC smoke tests after convergence

A PR-branch commit is never a valid production-check SHA. The protected deploy
workflow runs from `refs/heads/main`, and `confirm_sha` must equal the selected
`GITHUB_SHA`.

Direct, unplanned mutation and automatic retries of ambiguous mutating requests
are prohibited. `reconcile-moneybee-oidc.sh` is diagnostic-only and cannot
perform production writes.

## Rollback

Existing managed clients are exported through reviewed per-client allowlists.
For a newly created client whose pre-apply state was absent, rollback metadata
requires disabling the client first and permits deletion only through a separate
reviewed rollback authorization. Do not bypass the plan/hash/environment
boundary to delete a newly created client.

## Incident handling

Rotate exposed credentials immediately, invalidate sessions when appropriate,
review GitHub Actions and Keycloak admin events, rerun runtime preflight after
SSH material changes, and record the exact incident and rotation times.
