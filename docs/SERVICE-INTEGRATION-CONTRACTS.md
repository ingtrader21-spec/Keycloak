# Codestra service identity, API, and webhook contracts

## Scope

This contract layer binds the Keycloak machine-client registry to the logical
API and webhook relationships used by Kong, middleware, workers, Odoo, n8n,
VICIdial, Telnexa, Klyrow, Kyqra, Postly, provisioning, and monitoring.

It is desired state and CI policy. It does **not** claim that a live endpoint is
installed, reachable, authenticated, or production-ready. Runtime readiness
still requires protected merge, environment configuration, exact-SHA staging
checks, token tests, webhook replay tests, and explicit activation approval.

## Canonical identity

```text
issuer=https://auth.codestra.co/realms/codestra
token_endpoint=https://auth.codestra.co/realms/codestra/protocol/openid-connect/token
jwks_uri=https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs
human_flow=authorization_code+PKCE_S256
machine_flow=client_credentials
maximum_machine_token_lifetime_seconds=300
```

Machine tokens must carry `iss`, `sub`, `aud`, `azp`, `iat`, `exp`, `jti`, and
`scope`. Refresh tokens and full-scope mode are prohibited for machine clients.
Secrets remain in protected environment secrets or the approved external secret
store and never enter Git.

## Contract files

```text
config/contracts/machine-clients.json
config/contracts/service-access-matrix.json
config/contracts/webhook-contracts.json
scripts/validate-service-integrations.py
```

`machine-clients.json` declares one confidential Keycloak client per workload.
`service-access-matrix.json` declares every allowed caller-to-resource edge,
required audience, and least-privilege scope set. `webhook-contracts.json`
declares the signed provider callbacks accepted by the middleware boundary.

## API URL policy

Only the canonical Keycloak URLs are committed as absolute URLs. Application and
provider locations are supplied through protected runtime variables:

```text
KONG_GATEWAY_BASE_URL
MIDDLEWARE_API_BASE_URL
ODOO_INTEGRATION_BASE_URL
N8N_AUTOMATION_BASE_URL
VICIDIAL_ADAPTER_BASE_URL
TELNEXA_GATEWAY_BASE_URL
KLYROW_GATEWAY_BASE_URL
KYQRA_GATEWAY_BASE_URL
POSTLY_ADAPTER_BASE_URL
```

This prevents the identity repository from inventing or silently changing
runtime hosts. Relative API paths remain versioned under `/api/v1/`.

## Call graph rules

- Kong forwards authorized requests to `middleware-api`.
- n8n calls only `middleware-api`; it receives no direct Odoo or provider grant.
- Middleware is the only normal command boundary to Odoo, VICIdial, Telnexa,
  Klyrow, Kyqra, and Postly.
- Provider and adapter events return to `middleware-api` with the target audience
  and a producer-specific publish scope.
- `monitoring-readonly` receives only `health.read` and `metrics.read`.
- `provisioning-service` can request business provisioning through middleware,
  but receives no Keycloak Admin API permission or realm-management role.

## Webhook security

Every webhook requires both a short-lived OIDC bearer token and an HMAC-SHA256
signature. The canonical signature input is:

```text
v1
POST
<relative-path>
<unix-timestamp>
<event-id>
<source-client-id>
<sha256-body>
```

Required headers:

```text
Authorization
Content-Type
Idempotency-Key
X-Codestra-Event-Id
X-Codestra-Event-Type
X-Codestra-Source
X-Codestra-Tenant-Id
X-Codestra-Timestamp
X-Codestra-Signature
X-Correlation-Id
```

The receiver permits at most 300 seconds of clock skew, persists replay keys for
at least 24 hours, stores inbound data in a durable inbox before acknowledging,
and deduplicates by authoritative event ID. Delivery is at least once; handlers
must therefore be idempotent.

## Required staging evidence

For each caller-target grant, obtain a token and verify:

```text
iss=canonical Codestra issuer
azp=exact caller client
required target audience is present
exp-iat<=300 seconds
only reviewed scopes are present
jti is present
unrelated audiences and realm-management roles are absent
```

For each webhook, verify valid delivery plus rejection of wrong issuer, wrong
audience, missing scope, expired token, stale timestamp, invalid signature,
duplicate event ID, tenant mismatch, and an unknown event type.
