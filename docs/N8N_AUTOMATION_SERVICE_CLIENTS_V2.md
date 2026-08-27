# Keycloak n8n Automation Service Clients v2

## Exact lineage

```text
Keycloak base SHA: d3ed59800c53b82b03323960fe006fc15a08091e
Keycloak branch: feature/n8n-automation-service-clients-v2
N8N contract SHA: e3a3e97ab0da0d7df78bba52b18904e5f83e6dbe
Middleware contract SHA: bd6c7c0a470a74ef648fe2a21e2d9dcd4c2328a4
Production activation: NOT AUTHORIZED
```

The machine-readable desired-state contract is:

```text
config/contracts/n8n-automation-clients-v2.json
```

## Design

Eight confidential service clients separate platform, CRM, telephony, messaging, crawler, product, privacy, and operations automation. Every client uses Client Credentials, short-lived access tokens, no refresh token, no human login, and the exact Middleware API audience.

n8n receives no Keycloak administration scope, provider scope, platform-administrator role, or direct application audience.

## Required validation before creation

- exact Middleware audience and resource-server mapping;
- per-scope permission contract;
- client-specific administrative boundary;
- secret generation and delivery outside Git;
- token lifetime and rotation policy;
- revocation and incident procedure;
- staging-only client creation first;
- negative tests for wrong issuer, audience, client, tenant, workflow, and scope;
- proof that one automation class cannot call another class's commands;
- proof that privacy and operations credentials require their additional approvals;
- rollback export of every affected managed object;
- deterministic Keycloak plan with zero unreviewed actions.

## Secure change flow

```text
feature branch
 -> exact-head and merge-result CI
 -> independent approval
 -> protected main merge
 -> runtime-path verification
 -> deterministic check plan
 -> protected staging apply
 -> Middleware token acceptance tests
 -> no-effect n8n staging tests
 -> production plan and separate approval
```

A merge never creates a live Keycloak client. The current state remains `declared-not-created`; no secret, credential, client, role, token, service restart, n8n activation, or production change is included.
