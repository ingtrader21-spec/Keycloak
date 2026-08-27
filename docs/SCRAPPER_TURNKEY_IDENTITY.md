# Scrapper Turnkey Identity

Status: identity contract only. This branch does not change the live realm, rotate a secret, create a user, or deploy Keycloak.

## Canonical authority

The canonical issuer is:

```text
https://auth.codestra.co/realms/codestra
```

Human users enter the scraper through a same-origin backend-for-frontend. The browser uses no machine credential and does not persist access or refresh tokens in local storage.

## Human flow

```text
Browser
  -> scraper BFF /auth/login
  -> Keycloak Authorization Code + PKCE S256
  -> BFF validates issuer, audience, signature, state and nonce
  -> BFF creates an opaque HttpOnly session
  -> browser calls only same-origin /bff routes
```

Required human roles:

- `scraper-viewer`: read jobs, results, sources and diagnostics.
- `scraper-operator`: create/cancel/retry jobs and validate sources within an assigned tenant.
- `scraper-admin`: manage schedules, integrations, reviews, exports and tenant API clients.
- `platform-admin`: manage tenant onboarding and suspension across tenants.

`platform-admin` must be assigned only through a dedicated administrative group and reviewed separately from normal tenant access.

## Tenant membership

Tenant membership is represented by Keycloak groups:

```text
/codestra/tenants/<tenant-uuid>
```

A protocol mapper emits a multivalued `tenant_ids` claim. The scraper rejects tenant API or BFF requests when the authoritative tenant is not present in that claim. A caller-supplied `X-Tenant-ID` is never sufficient authorization.

## Service clients

### Scraper to Middleware

Client: `codestra-scrapper-middleware-events`

- Audience: `codestra-middleware`.
- Scope: `scrapper.events.write`.
- Preferred authentication: mTLS or private-key JWT.
- Short-lived Client Credentials token.

### Middleware to Scraper

Client: `codestra-middleware-scrapper-commands`

- Audience: `codestra-scrapper`.
- Scopes: `scraper.inbox.write`, `scraper.inbox.read`.
- mTLS and signed canonical messages remain required at the transport layer.

### Internal control worker

Client: `codestra-scrapper-control-worker`

- Audience: `codestra-scrapper`.
- Narrow job and source command scopes.
- `tenant.impersonate` may be granted only to this isolated worker identity and never to a browser client.

## Token and session policy

- Access tokens: five minutes.
- Service access tokens: five minutes.
- Refresh-token rotation enabled.
- Refresh-token reuse disabled.
- BFF session cookie: `Secure`, `HttpOnly`, `SameSite=Lax`.
- CSRF token required for every browser mutation.
- Login state and nonce are single-use and expire after ten minutes.
- Realm/client secrets are mounted through the approved secret mechanism and never stored in Git.

## Provisioning contract

Tenant creation in the scraper emits a durable onboarding event to Codestra Middleware. Middleware requests Keycloak provisioning through its approved identity adapter. The adapter must be idempotent and return a receipt containing:

- tenant ID;
- group path;
- client IDs created or reconciled;
- protocol-mapper version;
- role-mapping version;
- Keycloak resource IDs;
- non-secret configuration digest;
- reconciliation status.

The scraper onboarding step becomes `passed` only after the receipt is verified. It must never infer success merely because an HTTP request returned without a durable receipt.

## Revocation and suspension

Tenant suspension must:

1. disable new scraper commands immediately in the scraper database;
2. revoke or disable tenant service clients through the identity adapter;
3. invalidate active BFF sessions for the tenant;
4. retain read-only audit access for platform administrators;
5. record all actions with a correlation ID.

## Acceptance tests

Before applying this contract to the live realm:

- exact issuer and audience validation;
- PKCE, state and nonce rejection tests;
- browser session and CSRF tests;
- cross-tenant membership denial;
- platform-admin role denial for ordinary admins;
- service-client audience and scope denial;
- client-secret rotation and previous-secret revocation;
- tenant suspension and session invalidation;
- realm export diff review and rollback evidence.
