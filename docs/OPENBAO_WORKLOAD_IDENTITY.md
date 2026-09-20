# Keycloak → OpenBao workload identity

Keycloak is the issuer of every machine identity; OpenBao is the secrets
authority. A workload obtains a short-lived Keycloak service-account token,
presents it to OpenBao's `jwt-codestra` mount, and receives an OpenBao token
bound to one least-privilege policy. This document records the Keycloak side of
that flow. It is repository desired state: nothing here applies to a live realm
by itself, and production activation is not authorized.

```text
Service (azp = clientId)
   |  client_credentials + scope=openbao.workload
   v
Keycloak (per-environment issuer)
   |  access token: aud ⊇ [openbao], azp, jti, codestra_environment, exp-iat ≤ 300
   v
OpenBao jwt-codestra (CEL role <clientId>-<environment>)
   |  validates iss/aud/azp/codestra_environment/jti/lifetime
   v
workload-<clientId>-<environment> policy → short-lived OpenBao token
```

## Desired state

`config/desired-state/openbao-workload-identity/`

| Path | Purpose |
| --- | --- |
| `contract.json` | issuers per environment, audience `openbao`, scope `openbao.workload`, claim `codestra_environment`, the new clients, the existing managed-client bindings, the OpenBao identities that do not resolve, the clients that must never be bound, token policy and boundary flags |
| `client-scopes/openbao.workload.json` | optional client scope with exactly two mappers: `audience-openbao` (access token only) and `claim-codestra-environment` whose value is the placeholder `${CODESTRA_ENVIRONMENT}` rendered by the reconciler to its own environment |
| `clients/*.json` | nine confidential service-account clients for the monitoring plane: `prometheus-openbao`, `grafana-runtime`, `alloy-collector`, `otel-gateway`, `loki-runtime`, `tempo-runtime`, `redis-exporter`, `postgres-exporter`, `superset-analytics` — no flows, `fullScopeAllowed=false`, 300 s tokens, default scope `basic`, optional scope `openbao.workload` only |
| `openbao-workload-secret-authority.v1.json` + `.sha256` | byte-for-byte copy of `Codestra-OpenBao/config/workload-secret-authority.v1.json` pinned by canonical sha256 |

Existing protected managed clients that OpenBao already admits —
`alertmanager`, `kong-gateway`, `middleware-api`, `middleware-worker`,
`n8n-automation`, `odoo-integration`, `vicidial-adapter` — are bound by linking
the optional scope; their managed JSON is untouched so the protected plan does
not drift.

`grafana-runtime` is the only new client that also carries the `middleware-api`
audience, with read-only Middleware scopes, because Grafana's control-plane
client reads operational views from Middleware.

## Why an optional scope

- The `openbao` audience and the environment claim are added only when a token
  is requested with `scope=openbao.workload`; ordinary tokens toward Middleware
  or Kong do not carry them.
- One realm export is deployed to both Keycloak instances. The scope stores the
  placeholder; the staging reconciler renders `staging`, so the staging
  instance can never mint `codestra_environment=production`. Production
  rendering is part of the protected production process and is not automated
  here.
- The scope is never a realm default (validated against
  `config/realms/codestra.json` and live during reconciliation), never linked to
  a public/browser client, and never linked to `monitoring-readonly`, which keeps
  exactly `health.read` and `metrics.read`.

## Validation

```bash
make openbao-workload-identity-check   # --check --require-cross-check
python3 scripts/openbao_workload_identity_desired_state.py --check [--openbao-repo PATH]
python3 -m unittest tests/test_openbao_workload_identity.py
```

The validator proves, offline: exact client shape; the scope mappers; every
OpenBao role resolves to one client of the same `clientId` or is listed under
`unresolvedOpenBaoIdentities` (currently the business-application identities
whose Keycloak client ids differ — `beyvra-*`, `breero-api`, `larimia-api`,
`moneybee-api`, `crawler-adapter`, `klyrow-email-adapter`,
`telnexa-sms-adapter` — which the owning repositories must reconcile before
any OpenBao binding); the monitoring-plane identities all resolve; no browser
client, `monitoring-readonly` or realm default carries the scope; the vendored
authority matches its pin; and, with `--openbao-repo`, that the OpenBao
checkout's authority is byte-identical, that its staging/production mounts bind
the Keycloak staging/production issuers, and that every role binds the
`openbao` audience and requires `codestra_environment`.

## Staging reconciliation

```bash
CERTIFY_ENVIRONMENT=staging KC_BASE_URL=https://auth-staging.codestra.co \
KC_PUBLIC_URL=https://auth-staging.codestra.co KC_TARGET_REALM=codestra \
KC_ADMIN_REALM=master KC_ADMIN_CLIENT_ID=... KC_ADMIN_CLIENT_SECRET_FILE=/abs/0600/file \
make reconcile-openbao-workload-identity MODE=plan OUTPUT_DIR=/abs/0700/dir
```

`plan` reads only. `apply` creates or updates the scope (claim rendered to
`staging`), the nine clients and the optional links, reads everything back,
verifies the boundary (no realm default, no never-bound client) and writes new
client secrets to 0600 files outside the checkout for the OpenBao agent
bootstrap. `disable` disables the nine clients and unlinks the scope from every
bound client. Secrets and tokens are never printed or written into evidence.

## Negative expectations OpenBao enforces with these tokens

| Token | OpenBao result |
| --- | --- |
| production issuer presented to the staging mount (or vice versa) | rejected: foreign issuer |
| token without `scope=openbao.workload` (no `openbao` audience) | rejected: wrong audience |
| `azp` of another client | rejected: wrong client |
| staging token against `codestra/production/*` | denied by policy; `codestra_environment` mismatch rejects the role first |
| expired, tampered or replayed `jti` | rejected |
| `monitoring-readonly` token | no role exists; rejected |
