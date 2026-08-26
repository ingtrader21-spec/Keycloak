# Security policy

## Never commit

- passwords or password hashes
- Keycloak access or refresh tokens
- client secrets
- private keys, keystores, or certificates containing private material
- OTP seeds, recovery codes, or WebAuthn private material
- production user exports
- PostgreSQL data or backups
- SMTP, SMS, Odoo, n8n, Kong, Caddy, or cloud-provider credentials

Use GitHub Environment secrets or the approved external secret store.

## Change control

Production configuration is applied only from a reviewed commit through the manual, protected deployment workflow. The workflow first stores a sanitized client snapshot, applies the desired state, verifies convergence, and performs a read-only OIDC smoke test.

## Incident handling

For a suspected credential leak:

1. Revoke or rotate the exposed credential immediately.
2. Invalidate active sessions when appropriate.
3. Remove the secret from the repository and rewrite Git history if required.
4. Review GitHub Actions logs and Keycloak admin events.
5. Record the incident and the exact rotation time.
