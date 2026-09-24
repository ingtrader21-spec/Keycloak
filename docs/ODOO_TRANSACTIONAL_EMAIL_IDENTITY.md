# Odoo transactional email service identity

`odoo-email` is the dedicated confidential workload identity used by the
optional Odoo 19 transactional-email bridge. It can call only Middleware with
audience `middleware-api` and these exact scopes:

- `odoo.email.command.write`
- `odoo.email.status.read`

The service-account user must have one exact `tenant_id` attribute. Wildcard
tenant values, token exchange, browser flows, password grants, refresh tokens,
direct Klyrow/Postal access, and production-policy mutation scopes are not
permitted.

The client secret is not stored in Git. Protected apply expects the separately
provisioned `KC_CLIENT_SECRET_ODOO_EMAIL` environment secret, and Odoo receives
that value through its existing mounted-secret mechanism. Creating this client
does not enable the Odoo bridge or authorize production email; both Odoo send
switches and the Middleware production policy remain independent fail-closed
controls.
