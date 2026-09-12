# Production email operator identity

`production-operator` is the privileged, tenant-bound confidential workload
identity for the Middleware production-email control surface. Its access token
has audience `middleware-api` and only these scopes:

- `email.production.read`
- `email.production.write`

It has no connector-command target, provider access, n8n authority, browser
flow, password grant, token exchange, refresh token, wildcard tenant, or realm
administration capability. The separately provisioned
`KC_CLIENT_SECRET_PRODUCTION_OPERATOR` secret is required by protected apply
and is never stored in Git.

Provisioning this client does not itself authorize or activate email. The
Middleware API still requires an immutable policy record, exact release and
change identity, bounded tenant/sender/domain/recipient/category scope, active
validity window, quotas, DKIM evidence, explicit activation, and an open kill
switch. Access to the protected secret must be limited to the production
operators executing the approved change.
