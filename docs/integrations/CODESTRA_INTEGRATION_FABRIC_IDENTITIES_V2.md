# Codestra Integration Fabric — Keycloak identities v2

## Authority

Keycloak is the sole normal authority for human authentication, machine identities, token issuance, sessions, MFA, linked identity providers, and verified login email. It does not own application tenants, CRM records, workflow state, email/SMS/social delivery, telephony state, crawler jobs, or financial records.

Canonical issuer:

```text
https://auth.codestra.co/realms/codestra
```

## Machine identity rules

- Client Credentials only.
- Confidential service-account clients.
- Maximum access-token lifetime: 300 seconds.
- Explicit audience: `middleware-api`.
- No implicit flow, browser flow, direct grants, device flow, refresh token, human login, realm-management role, provider credential access, or platform-admin role.
- Secrets are created and rotated outside Git.
- Each client is restricted by workflow family, command prefix, Kong cell, and granular scopes.
- Generic `automation.execute` and generic `automation.command` scopes are prohibited.

## Cell clients

### Core automation

`n8n-core-automation` may claim only core platform, identity, CRM, email, SMS, social, crawler, forms, and provisioning workflow families. It cannot claim telephony or Beyvra work.

### Beyvra automation

`n8n-beyvra-automation` may claim only `product.beyvra-nonfinancial` and request only `beyvra.operations.*`. No trade, order, wallet, ledger, hold, payment, deposit, withdrawal, transfer, custody, chain, broker, or provider prefix is authorized.

### Contact-center automation

`n8n-contact-center-automation` may claim only telephony and contact-center CRM workflow families. Live call commands remain separately capability-gated in Middleware.

## Adapter clients

Each domain adapter has a separate identity:

```text
odoo-integration
klyrow-adapter
telnexa-adapter
postly-adapter
kyqra-adapter
vicidial-adapter
provisioning-service
```

An adapter client can call only its own Middleware callback/status contract or receive only its own command family. It cannot impersonate n8n or another adapter.

## Human applications

Human portals continue to use Authorization Code with PKCE through an approved BFF/browser boundary. Browser access tokens must not be reused as service tokens. A caller-provided tenant ID is never proof of membership.

## Apply process

This repository contains desired state only. Any apply requires:

1. protected merged SHA;
2. deterministic plan and diff;
3. protected environment approval;
4. secret creation outside Git;
5. no-bypass exact-head review;
6. OIDC token acceptance and negative tests;
7. post-apply read-back and zero-drift verification;
8. rollback plan.

No client declared here is created by the source commit.