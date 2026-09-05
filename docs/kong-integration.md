# Keycloak → Kong OIDC trust boundary

## Canonical identity authority

Codestra Keycloak is the sole JWT/OIDC issuer accepted by the Kong API gateway for protected platform traffic.

```text
issuer=https://auth.codestra.co/realms/codestra
discovery=https://auth.codestra.co/realms/codestra/.well-known/openid-configuration
jwks=https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs
token=https://auth.codestra.co/realms/codestra/protocol/openid-connect/token
```

Kong must validate the token signature against the realm JWKS, require the exact issuer, require a non-expired access token, enforce the expected audience and route scope, and reject requests before forwarding when any identity check fails.

## Existing protected clients

This repository already manages the confidential `kong-gateway`, `middleware-api`, `n8n-automation`, and provider/service clients through protected GitOps. Do not create a second realm export or duplicate client IDs for this integration.

The `kong-gateway` client is a confidential service-account client with browser/password flows disabled, five-minute access tokens, `fullScopeAllowed=false`, and an access-token audience mapper for `middleware-api`. Its reviewed service scopes are:

- `middleware.request.forward`
- `middleware.status.read`

The service-access matrix is authoritative for cross-service grants. Kong may forward to Middleware only under that reviewed grant. Middleware remains responsible for independently validating the original caller identity/tenant claims where the downstream contract requires it.

## Machine-to-machine flow

1. A backend or automation service obtains an access token from Keycloak with its own confidential client identity and client-credentials grant.
2. The caller sends `Authorization: Bearer <access-token>` to the canonical Kong ingress.
3. Kong validates Keycloak issuer, signature, expiry, audience, client identity and required route scope.
4. Kong rejects invalid/unauthorized requests at the edge.
5. Only validated traffic is routed to Middleware.
6. Middleware applies its own authorization, tenant, command, idempotency and capability checks before any cross-system effect.

Kong must not mint substitute user/service identity for the originating caller and must not disable Middleware's own authorization boundary.

## Secrets

No client secret is stored in this repository. Keycloak generates or receives credentials through the protected deployment/secret-management path. Kong's own confidential credential, if required by its selected validation mode, is installed in the runtime secret manager and referenced by environment/secret binding only.

Never commit access tokens, refresh tokens, client secrets, realm signing keys, database passwords, private keys, or live environment files.

## Kong contract

The Kong repository must bind protected routes to this issuer and preserve a fail-closed configuration. Health/liveness endpoints may be explicitly unauthenticated; business and Middleware routes may not bypass identity validation.

The expected source contract is:

```text
KEYCLOAK_ISSUER_URL=https://auth.codestra.co/realms/codestra
KEYCLOAK_DISCOVERY_URL=${KEYCLOAK_ISSUER_URL}/.well-known/openid-configuration
KEYCLOAK_JWKS_URL=https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs
KONG_RESOURCE_CLIENT=kong-gateway
MIDDLEWARE_AUDIENCE=middleware-api
```

## Promotion gates

Source alignment does not prove runtime wiring. Before staging or production promotion, capture evidence for:

- discovery/JWKS reachability from Kong;
- valid token accepted;
- wrong issuer rejected;
- invalid signature rejected;
- expired token rejected;
- wrong audience rejected;
- insufficient scope rejected;
- missing token rejected;
- health route behavior matches the approved exception list;
- Middleware receives the expected identity context and still rejects unauthorized commands.

No merge or source validation by itself authorizes live deployment.