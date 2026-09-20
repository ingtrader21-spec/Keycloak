# Codestra Platform API Identities V3

## PAS-156 — final Middleware V3 API identity authority

PAS-156 pins Keycloak source authority to the canonical Middleware V3 route contract:

- repository: `ingtrader21-spec/Middleware-`
- source: `deploy/public-api-route-contract.json`
- schema: `codestra.middleware.public-api-route-contract.v2`
- canonical digest: `9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b`
- routes: **117 total = 105 shared_edge + 2 private_only + 10 denied**
- issuer: `https://auth.codestra.co/realms/codestra`
- Middleware audience: `middleware-api`

The generated authority is `config/contracts/middleware-api-access.v3.json`. It represents every Middleware route exactly once for identity review while remaining fail-closed: `runtimeApplyAuthorized=false`, `providerEffectsEnabled=false`, and no caller client, secret, live realm mutation, or production activation is created here.

Generate and verify it against the exact Middleware source with:

```text
python scripts/generate_middleware_api_access_v3.py --source <Middleware>/deploy/public-api-route-contract.json
python scripts/generate_middleware_api_access_v3.py --source <Middleware>/deploy/public-api-route-contract.json --check
python scripts/validate_middleware_api_access_v3.py
```

The required success markers are:

```text
MIDDLEWARE_API_ACCESS_V3_GENERATOR=PASS
MIDDLEWARE_API_ACCESS_V3=PASS
MIDDLEWARE_ROUTE_COUNT=117
MISSING_REQUIRED_SCOPES=0
```

### Platform-kernel scopes and role

PAS-156 owns exactly three new optional Keycloak client scopes:

- `platform.command` — submit/cancel platform commands;
- `platform.command.read` — operation, timeline, and kernel-description reads;
- `platform.command.replay` — replay requests.

They are never realm defaults and are not attached as default client scopes. Caller assignment remains dark until PAS-157 completes caller/token certification.

Replay additionally requires the `platform-operator` realm role. The role is prepared with MFA required, independent approval required, cross-family grants disabled, and activation `PREPARED_DISABLED`. The `platform-operator` string used by other Middleware routes as a `calling_client` selector is a separate caller-classification concern; PAS-156 does not infer realm-role authority from that selector.

### Route-scope completeness

For every non-denied route, the generated matrix preserves a required scope value. The one value `resolved_from_command_prefix` is explicitly modeled as a Middleware runtime selector rather than a literal Keycloak scope. Denied routes remain explicit deny decisions with no required scope. This is the basis for `MISSING_REQUIRED_SCOPES=0`; it does **not** create new client-scope files outside PAS-156's three owned platform scopes or widen any existing grant.

### Parallel-wave boundary

PAS-156 does not modify `config/contracts/service-access-matrix.json`, release trust-root/bootstrap files, or PAS-157 caller/token certification files. PAS-157 owns resolution of symbolic/concrete callers, positive/negative token matrices, and final caller assignments.

## Existing platform identity backlog

## Exact source work still required

### `sdk-intake`

A confidential client-credentials workload identity calling `middleware-api` with only:

```text
leads.write
surveys.write
```

Required token properties:

```text
audience=middleware-api
access-token lifetime <= 300 seconds
refresh tokens disabled
full scope disabled
password grant disabled
implicit flow disabled
service account enabled
secret stored outside Git
```

The caller must provide the tenant required for each request through a reviewed tenant-bound workload configuration. Do not hard-code one tenant into a shared SDK or gateway identity.

### `alertmanager`

A confidential client-credentials workload identity calling `middleware-api` with only:

```text
alerts.write
```

Alertmanager receives no incident-read, acknowledgement, resolution, provider-dispatch, customer-communication or administration authority. Its secret remains outside Git and the token lifetime is at most 300 seconds.

### Operations console

Do not model the operations console as an unrestricted machine client. Before implementation, define the actual human access path and choose either:

1. a same-origin server-side BFF using Authorization Code + PKCE for human operators; or
2. a confidential browser gateway with approved redirect URIs, PKCE, role mapping and server-side session storage.

Only after that authority is reviewed may it receive:

```text
alerts.read
alerts.acknowledge
alerts.resolve
operations.read
operations.cancel
provider.health.read
```

It must never receive provider dispatch, secret administration, realm administration or wildcard scopes.

## Existing authority to preserve

- `codestra-ai`, `codestra-communication`, `codestra-marketing` and `codestra-social` request only their reviewed Middleware operations;
- `middleware-worker` remains the sole provider-dispatch identity;
- provider adapters expose only exact status/read or event-publication scopes;
- `monitoring-readonly` remains limited to optional `health.read` and `metrics.read` scopes;
- n8n family identities do not receive provider credentials or direct provider dispatch;
- Keycloak plans, exports and drift checks remain source-controlled and fail closed.

## Prohibited static tenant claims

Do not add a fixed `tenant_id` mapper to the shared `kong-gateway` or shared `n8n-automation` service accounts. Those identities serve multiple governed tenants and must not mint every token as one tenant. Tenant binding must use a reviewed per-tenant client, token-exchange/authorization mechanism, or cryptographically authenticated request context whose lifecycle and revocation are explicit.

A tenant mapper may be added only to a dedicated single-tenant identity whose client ownership and tenant assignment are immutable, reviewed and tested.

## Required implementation files

Update the existing authority rather than creating a competing model:

```text
config/contracts/service-access-matrix.json
config/contracts/machine-clients.json
config/policy/managed-clients.json
config/policy/creatable-clients.json
config/clients/sdk-intake.json
config/clients/alertmanager.json
config/export-allowlists/sdk-intake.json
config/export-allowlists/alertmanager.json
scripts/render-machine-client-overlays.py
scripts/validate-service-integrations.py
scripts/validate.sh
tests/test_platform_api_identities.py
```

Generated overlays and export allowlists must be deterministic.

## Negative tests

Reject:

- wildcard or full scopes;
- refresh tokens for machine clients;
- password or implicit grants;
- token lifetime above 300 seconds;
- sdk-intake scopes other than `leads.write` and `surveys.write`;
- Alertmanager scopes other than `alerts.write`;
- Alertmanager read/acknowledge/resolve or provider authority;
- applications or n8n receiving provider dispatch;
- operations-console provider dispatch;
- static tenant claims on shared Kong or shared n8n identities;
- any committed secret or client credential;
- any client absent from managed/creatable/export authority;
- any generated-overlay drift.

## Safety

```text
KEYCLOAK_RUNTIME_APPLY=false
SERVICE_SECRETS_CREATED=false
PROVIDER_WRITES=false
PRODUCTION_CHANGED=false
```

This branch modifies source authority only. It does not apply a realm plan, create a service secret, change a live client, deploy Keycloak, activate an external effect or authorize production.