# CIP tenant identity authority (Foundation 3 / I1)

Keycloak's identity contract for the Codestra Integration Platform (CIP) tenant
API path. It defines who the caller is, which tenant and projects the caller acts
for, which product scopes it may obtain, and exactly what Kong and Middleware
must reject. Status: `PREPARED_DISABLED`. Nothing here applies a realm, creates a
secret or activates production.

| Artifact | Purpose |
| --- | --- |
| `config/desired-state/cip-tenant-identity/contract.json` | Single source of truth |
| `config/desired-state/cip-tenant-identity/{client-scopes,user-profile,realm-roles,scope-role-mappings,clients}/` | Keycloak desired state rendered from the contract |
| `config/certification/cip-f3-cross-repo-parity-recertification.v1.json` | Step 1 parity evidence (frozen `middleware-api`) |
| `config/certification/cip-tenant-token-matrix.v1.json` | Positive/negative token matrix (88 cases) |
| `release/cip-tenant-identity/keycloak-cip-tenant-identity-desired-state-plan.json` (+ `.sha256`) | Staging-only reconcile plan |
| `release/cip-tenant-identity/keycloak-cip-gateway-identity-contract.v1.json` (+ `.sha256`) | **What Kong consumes** |

```text
python3 scripts/cip_tenant_identity.py --check     # contract, desired state, release artifacts
python3 scripts/cip_tenant_identity.py --write     # re-render after a reviewed contract change
python3 scripts/cip_tenant_token_matrix.py         # token matrix
python3 -m pytest -q tests/test_cip_*certification*.py
```

`scripts/validate.sh` runs every `tests/test_*certification*.py`, so all four
CIP test files run on every validation without changing the closure-pinned
`validate.sh`.

## Audience and route contract (frozen)

Audience `middleware-api`, issuer `https://auth.codestra.co/realms/codestra`
(staging `https://auth-staging.codestra.co/realms/codestra`), Middleware route
contract `9c32daec…3512b` (117 routes). On 2026-09-25 the parity certifier gave
PASS with 0 mismatches against current mains (Middleware `0606b0d`, Kong
`3e68cb2`, Caddy `64b2992`). It also passed against the mission heads (Kong #120
`12b25dc`, Caddy #186 `1c28b8f`). The unmerged Middleware kernel draft `0bc8d07`
(128 routes) is not adopted and fails closed until a reviewed repin.

## Who the caller is

| Actor | Grant | Client shape | Evidence |
| --- | --- | --- | --- |
| `user` (human) | Authorization Code + PKCE S256 | browser client, no service account | `amr` contains `mfa` |
| `service` | `client_credentials` only | confidential, dedicated to one tenant, no browser flow, no refresh token | no `amr` |

Every CIP client serves exactly one actor kind. A hardcoded mapper emits
`codestra_actor_kind` (`user` or `service`), and the gateway checks it against
the `azp` registry. Token exchange, password, implicit, device and CIBA grants
are disabled.

## Tenant and project claims: no self-assertion

| Claim | Rule | Human source | Service source |
| --- | --- | --- | --- |
| `tenant_id` | exactly one string, required, the **only** tenant authority | admin-only user-profile attribute `codestra_tenant_id` via `cip.user.context` | hardcoded mapper on the dedicated client |
| `project_ids` | optional list, narrowing only; absent ≠ all projects | admin-only attribute `codestra_project_ids` | hardcoded mapper on the dedicated client |

- The user-profile attributes are view/edit `admin` only and are not collected
  at registration. `unmanagedAttributePolicy` is `ADMIN_VIEW`. A user cannot
  set their own tenant, and a self-registered user has no `tenant_id`, so they
  fail closed.
- `tenant_ids`, `tenant`, `org_id`, `tid` and `organization` are **prohibited**
  on CIP tokens. Middleware still accepts `tenant_ids`, and Kong's control-plane
  Lua reads `tenant`, so any second tenant-shaped claim is rejected instead of
  merged.
- A tenant value in the request is a **selector only**. This covers
  `X-Tenant-ID`, body `tenant_id` / `command.tenant_id`, query `tenant_id` and
  path `{tenant_id}`. It must equal `tenant_id` exactly (case-sensitive),
  otherwise the request gets `403 cross_tenant_denied`. It never replaces or
  widens the token tenant. Project selectors (`X-Project-ID`, `project_id`) must
  be in `project_ids`, otherwise the request gets `403 cross_project_denied`.
- Shared identities (`kong-gateway`, `middleware-api`, `middleware-worker`,
  `n8n-automation`) never carry a tenant and cannot satisfy a CIP route.

## Product scopes (least privilege)

| Capability | Scope | Actors | Route binding |
| --- | --- | --- | --- |
| tenant admin | `cip.tenant.admin` | user | UNBOUND (no Middleware route yet) |
| connector admin | `cip.connector.admin` | user | UNBOUND |
| command submit | `platform.command` (frozen kernel scope) | user, service | `POST /platform/v1/commands`, `POST /platform/v1/operations/{operation_id}/cancel` |
| command read | `platform.command.read` (frozen kernel scope) | user, service | `GET /platform/v1/operations/{operation_id}`, `…/timeline`, `GET /platform/v1/kernel/describe` |
| usage read | `cip.usage.read` | user, service | UNBOUND |
| audit read | `cip.audit.read` | user, service | UNBOUND |

Keycloak issues a product scope only when all three of these hold:

1. The client lists it as an **optional** scope.
2. The token request names it.
3. The principal holds one of the scope's **role scope-mappings**.

The ten roles are `cip-tenant-admin`, `cip-connector-admin`,
`cip-command-operator`, `cip-command-viewer`, `cip-usage-viewer`,
`cip-audit-viewer`, and four `cip-svc-*` service roles. All are non-composite
and none is a default role. No CIP client carries the `roles` scope, so roles
never appear in the token; the scope claim is the authority.

Separation of duties holds throughout. Tenant admin, connector admin and audit
read never share a role, and no service client combines command submit with
audit read. `platform.command.replay`, `platform-operator`, the cross-tenant
`platform.*` scopes, `identity.*` and the gateway scopes are prohibited on CIP
principals.

Command scopes reuse the frozen Middleware kernel scopes, so Kong's literal
per-route scope checks do not change. The `platform.command*` role mappings are
overlays; the frozen scope files are byte-identical. The staging CIP clients are
only *proposed* `platform-command-client` members. Middleware rejects their
`azp` on command routes until it registers them.

## What Kong consumes

`release/cip-tenant-identity/keycloak-cip-gateway-identity-contract.v1.json`
(schema `codestra.keycloak.cip-gateway-identity-contract.v1`) contains:

- issuers, discovery and JWKS URIs per environment;
- the `azp` registry per environment (actor kind, allowed scopes, tenant and
  projects for service accounts). The production registry is **empty**, so every
  production CIP token is rejected;
- claim names (`azp`, `sub`, `tenant_id`, `project_ids`, `codestra_actor_kind`,
  `amr`) and the prohibited claims, scopes and roles;
- the selector rules, product-scope route bindings, enforcement order, failure
  codes (reusing Kong's `invalid_token`, `insufficient_scope`,
  `cross_tenant_denied`, `authorized_party_denied`, `algorithm_or_kid_denied`,
  `scope_denied`), and rate-limit keys (`tenant_id`, then the validated project
  selector);
- a conformance pointer: Kong must reproduce the verdict and status of every
  token-matrix case.

Kong pins the file by sha256 and never edits Keycloak desired state. Unbound
scopes satisfy **no** route until Middleware publishes one and Keycloak repins.

## Activation preconditions (not met; production stays NO_GO)

1. Protected merge, plan regenerated from the merged SHA, independent plan
   review, then a staging-only reconcile.
2. The realm OTP execution is configured so the AMR mapper emits `mfa`. Until
   then, every human CIP token fails closed on MFA.
3. Middleware registers the proposed `platform-command-client` members.
4. Kong imports the gateway contract by digest and passes the token matrix.
5. The production `cip-portal` origin is reviewed; it is
   `BLOCKED_ORIGIN_UNRESOLVED` today.
6. Middleware publishes tenant, connector, usage and audit routes before those
   scopes are bound.
