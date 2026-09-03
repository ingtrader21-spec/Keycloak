# Codestra Platform API Scopes V2

This branch completes the remaining service identities, audiences and least-privilege scopes required by the Infrastructure platform API authority.

## Required identities and scopes

```text
sdk-intake
  leads.write
  surveys.write

alertmanager
  alerts.write

operations-console
  alerts.read
  alerts.acknowledge
  alerts.resolve
  operations.read
  operations.cancel
  provider.health.read

codestra-marketing
  marketing.read
  marketing.write
  marketing.approve
  marketing.campaign.request

codestra-ai
  ai.read
  ai.request
  ai.cancel
  ai.inference.request

codestra-communication
  communication.read
  communication.write
  communication.cancel
  communication.email.request
  communication.sms.request

codestra-social
  social.read
  social.write
  social.approve
  social.publish.request

odoo-integration
  odoo.events.publish

middleware-worker
  marketing.provider.dispatch
  ai.provider.dispatch
  email.send
  sms.send
  social.publish
```

Provider/readback identities receive only their provider-specific `*.provider.status.read` scope. n8n family clients receive only the exact automation-v2 operations used by their owned workflow family.

## Invariants

- machine identities use client credentials;
- human applications use Authorization Code + PKCE;
- exact audience, short token lifetime and no full/wildcard scopes;
- no password grant or implicit flow;
- applications and n8n have no provider dispatch permission;
- `middleware-worker` is the only dispatch identity;
- provider credentials are never stored in the committed realm plan;
- dedicated Alertmanager identity has write-only alert ingestion authority;
- operations-console does not receive provider dispatch authority;
- plan/export/drift validation is source-only and performs no realm mutation.

## Safety

```text
KEYCLOAK_RUNTIME_APPLY=false
SECRETS_CREATED=false
PROVIDER_WRITES=false
PRODUCTION_CHANGED=false
```
