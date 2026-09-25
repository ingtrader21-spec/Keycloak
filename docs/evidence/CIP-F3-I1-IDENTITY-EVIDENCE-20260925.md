# CIP Foundation 3 / Agent I1: Keycloak identity authority evidence (2026-09-25)

Mission: [CIP Foundation 3: Identity, Gateway & Edge Authority](https://linear.app/passion-fruit/document/cip-foundation-3-identity-gateway-and-edge-authority-dual-agent-ba6f3b4b15f5).
Branch `product/cip-identity-tenant-auth-20260924` started from Keycloak #127's exact
head `521403d518b78e625eba5c2394131548819cd5ab`. The branch is committed locally
and has not been pushed or merged. `PRODUCTION_GO=NO`.

## Step 1: parity re-certified; audience `middleware-api` frozen: PASS

`scripts/certify_cross_repo_identity_parity.py` compared read-only snapshots.
Mission heads were read with `git show <sha>:<path>` from the CIP worktrees, and
current mains with `gh api …/contents?ref=<sha>`. No sibling repository was modified.

| Snapshot | Middleware | Kong | Caddy | Verdict |
| --- | --- | --- | --- | --- |
| Current mains | `0606b0d` | `3e68cb2` | `64b2992` | PASS, 0/0/0/0 mismatches |
| Mission heads | `0606b0d` | #120 `12b25dc` | #186 `1c28b8f` | PASS, 0/0/0/0 mismatches |
| Middleware kernel draft | `0bc8d07` (128 routes, `e5e71fe…`) | `3e68cb2` | `64b2992` | FAIL (expected); not adopted |

The frozen values are:

- route contract `9c32daec…3512b`, 117 routes (105 shared_edge);
- audience `middleware-api` on 113 routes, plus the 4 reviewed exceptions;
- Kong upstream `middleware-integration-api:8095`.

The draft's 11 new routes keep `middleware-api`, and the caller model covers
them (0 unknown callers), but adopting them needs a reviewed repin.

Record: `config/certification/cip-f3-cross-repo-parity-recertification.v1.json`.
Test: `tests/test_cip_parity_recertification_certification.py`.

## Step 2: human, service-account and tenant/project claim authority: PASS (repository)

Contract `config/desired-state/cip-tenant-identity/contract.json`. The claim
names match what the consumers already read: Middleware `app/security.py` and
`app/platform/principal.py` read `tenant_id`, and so does Kong's `tenantClaim`.

- `tenant_id` is exactly one value and the only authority. Humans get it from
  the admin-only `codestra_tenant_id` user-profile attribute. Service accounts
  get it from a hardcoded mapper on a dedicated single-tenant client.
- `project_ids` narrows only.
- `codestra_actor_kind` is hardcoded per client.
- Human tokens need `amr` containing `mfa`; service tokens carry no `amr`.
- `tenant_ids`, `tenant`, `org_id`, `tid` and `organization` are prohibited.
- Tenant/project values in the body, header, query or path are selectors only.

Rendered staging-only clients: `test-syn-cip-portal` (human) and three service
accounts across tenants A and B. Production `cip-portal` is
`BLOCKED_ORIGIN_UNRESOLVED`; there is no reviewed portal hostname in Caddy or
the portal repo.

## Step 3: product scopes: PASS (repository)

| Capability | Scope | Binding |
| --- | --- | --- |
| tenant admin | `cip.tenant.admin` (human only) | unbound |
| connector admin | `cip.connector.admin` (human only) | unbound |
| command submit | `platform.command` (frozen) | 2 routes |
| command read | `platform.command.read` (frozen) | 3 routes |
| usage read | `cip.usage.read` | unbound |
| audit read | `cip.audit.read` | unbound |

Issuance is gated by ten non-composite roles through client-scope role mappings.
Separation of duties is enforced. Replay, `platform-operator`, cross-tenant
platform scopes, `identity.*` and gateway scopes are prohibited. The frozen
caller authority and scope files are unchanged.

## Step 4: negative token matrix: PASS

`config/certification/cip-tenant-token-matrix.v1.json`: **88 cases, 12 positive
and 76 negative**. Every negative pins its failure category and HTTP status.

| Dimension | + / − |
| --- | --- |
| issuer | 1 / 5 |
| audience | 1 / 4 |
| azp | 1 / 6 |
| scope | 1 / 7 |
| tenant | 2 / 15 |
| expiry | 1 / 7 |
| service-account misuse | 1 / 11 |
| privilege escalation | 1 / 12 |
| project | 1 / 5 |
| mfa | 1 / 2 |
| algorithm | 1 / 2 |

Escalation cases run through the Keycloak issuance model. They cover:

- a viewer requesting submit;
- a tenant admin requesting connector admin or audit read;
- an operator requesting replay;
- a user who set their own tenant or project attribute;
- a self-registered user;
- a body tenant that differs from the issued token.

Every base fixture is accepted unmutated, so each rejection is caused by its own
mutation.

## Step 5: desired-state and contract evidence for Kong: PASS

| Artifact | sha256 |
| --- | --- |
| `release/cip-tenant-identity/keycloak-cip-gateway-identity-contract.v1.json` (file) | `10067954133a8c1023376d142b1bd75ab862a9cc44d4e8a4b100a5e3b3c0de34` |
| `release/cip-tenant-identity/keycloak-cip-tenant-identity-desired-state-plan.json` (file) | `5b75a7ef69456e8e429addb846814068caaff94c9288463c617a6376067e993f` |
| plan `configurationChecksum` | `cb3993ffdd5e691931ef842b8057f574b96994c049d3fdb5f31e5ae946506d2c` |
| contract (canonical) | `af7dc452969859370f82ac9a3479cd8cd01ed2bcb7b83bf2498f41fca19e978b` |
| token matrix (canonical) | `f5f98b3eb5658f1c180a15389ecc63cc5619c7df730140825b7d3fc549db1551` |

The plan has 40 operations. Every write is `RECONCILE_IN_STAGING_ONLY_AUTHORIZED_MISSION`.
`platform.command*` is `REFERENCE_FROZEN_DEFINITION_UNCHANGED`, and `cip-portal`
is `BLOCKED_ORIGIN_UNRESOLVED`. The production `azpRegistry` is empty.
Consumer guide: `docs/CIP_TENANT_IDENTITY.md`.

## Verification run in this worktree (2026-09-25)

| Command | Result |
| --- | --- |
| `bash scripts/validate.sh </dev/null` | exit 0, `VALIDATION=PASS`, 171 JSON files; all 63 CIP certification tests discovered and passed |
| `python3 -B -m pytest -q -p no:cacheprovider tests` | 329 passed, 503 subtests (baseline at `521403d`: 295 passed) |
| `python3 scripts/cip_tenant_identity.py --check` | `CIP_TENANT_IDENTITY=PASS` |
| `python3 scripts/cip_tenant_token_matrix.py` | `CIP_TENANT_TOKEN_MATRIX=PASS` (12+/76−) |
| `validate_middleware_caller_classification.py --check --require-target-contract` | PASS, target match PASS, 0 unknown callers |
| `validate_middleware_api_access_v3.py` / `validate_v3_token_matrix.py --check` | PASS (117 routes) / PASS (8/8/8, unchanged) |

## Hand-offs (not edited here)

- **Kong (I2):**
  - Import the gateway contract by digest.
  - `deploy/kong/scope-policy.lua` and `control-plane.yml` read `claims.tenant`,
    and the `codestra-authz` plugin schema allows `tenant`/`org_id`; CIP routes
    must read `tenant_id` only.
  - Unbound scopes satisfy no route.
  - Reproduce the matrix verdicts and statuses.
- **Middleware (K1):**
  - Register the proposed `platform-command-client` members.
  - Publish tenant-admin, connector-admin, usage and audit routes before Keycloak
    binds those scopes.
  - Middleware accepts `tenant_ids`, but CIP tokens never carry it.
  - Middleware has no project dimension or MFA check yet; the gateway enforces
    both until it does.
- **Keycloak realm (separately reviewed):** configure the OTP execution so the AMR
  mapper emits `mfa`. Until then, human CIP tokens fail closed.
- **Portal (P1):** a reviewed production origin is needed before `cip-portal` can
  be rendered.

## Safety

No Kong, Caddy, realm, live-client, managed-policy, closure-pinned or frozen
artifact was modified. No secrets, no tokens, no push, no merge, no live apply.
