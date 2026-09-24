# Edge integration certification: Keycloak identities for TEST_SYN

## Scope and authority

This is the Keycloak half of the staging certification that proves the real
deployed path **Keycloak token → Caddy → Kong → Middleware `integration_api`
handler** for campaign `TEST_SYN`. Middleware owns the certification runner
(`scripts/certify_edge_integration.py` in `appolon1908-hue/Middleware-`) and
the edge-route contract; Caddy and Kong own their route sources. This
repository owns the identities, the ingress scopes, and the claim contract
those tokens must carry, and it pins the same edge-contract SHA-256 the other
three components pin.

Everything under `config/desired-state/edge-integration-certification/` is
repository-only, validate-only desired state. It is deliberately outside
`config/clients/` and the managed/creatable client policies, exactly like the
observability desired state, so a normal protected client reconciliation can
never create or modify a certification identity. CI fails if a certification
identity or an ingress scope leaks into those live-capable sets, if any client
anywhere in the repository is granted `odoo.campaign.control.write`, or if an
ingress scope becomes a realm default client scope.

State: `SOURCE_PREPARED_NOT_DEPLOYED`. Nothing here reads runtime state,
mints tokens, or applies to any Keycloak instance. Production activation is
not authorized by this source.

## Files

```text
config/desired-state/edge-integration-certification/
  contract.json                       certification contract and edge-contract SHA-256 pin
  client-scopes/n8n.results.submit.json
  client-scopes/n8n.results.read.json
  client-scopes/odoo.campaigns.read.json
  clients/test-syn-n8n-submit.json
  clients/test-syn-n8n-read.json
  clients/test-syn-odoo-reader.json
  clients/test-syn-wrong-audience.json
  clients/test-syn-wrong-tenant.json
release/edge-integration-certification/
  keycloak-edge-certification-desired-state-plan.json   deterministic plan (also pins the hash)
  keycloak-edge-certification-desired-state-plan.sha256
scripts/edge_certification_desired_state.py   validator and plan renderer (--write / --check)
scripts/reconcile_edge_certification_staging.py   staging-only plan / apply / disable
scripts/certify_edge_identity_staging.py      staging token minting and redacted claim matrix
tests/test_edge_integration_certification.py  discovered by validate.sh (test_*certification*.py)
```

## Identity contract

| Client ID | Scope claim | Audience | tenant_id | business_units | campaigns | Purpose |
| --- | --- | --- | --- | --- | --- | --- |
| `test-syn-n8n-submit` | `n8n.results.submit` | `middleware-api` | `TEST_SYN_TENANT` | `["TEST_SYN"]` | `["TEST_SYN"]` | submit one safe result, expected `202` |
| `test-syn-n8n-read` | `n8n.results.read` | `middleware-api` | `TEST_SYN_TENANT` | `["TEST_SYN"]` | `["TEST_SYN"]` | read the seeded result, `200` / `404`; `403` on submit |
| `test-syn-odoo-reader` | `odoo.campaigns.read` | `middleware-api` | `TEST_SYN_TENANT` | `["TEST_SYN"]` | `["TEST_SYN"]` | campaign and desired-state reads, `200` |
| `test-syn-wrong-audience` | *(none)* | `test-syn-wrong-audience` | `TEST_SYN_TENANT` | `["TEST_SYN"]` | `["TEST_SYN"]` | valid token, wrong audience, `401` everywhere |
| `test-syn-wrong-tenant` | `n8n.results.read odoo.campaigns.read` | `middleware-api` | `TEST_SYN_OTHER_TENANT` | `["TEST_SYN_OTHER"]` | `["TEST_SYN_OTHER"]` | cross-tenant rows: same `404` as missing, indistinguishable denial |

Every client is a confidential service-account client with five-minute access
tokens, `fullScopeAllowed=false`, browser/password/device/CIBA flows disabled,
no redirect URIs or origins, and no optional client scopes. Scopes are real
realm client scopes attached as explicit per-client default scopes with
`include.in.token.scope=true`, so a plain Client Credentials request without
a `scope` parameter yields exactly the assigned scope in the `scope` claim.
The `basic` scope supplies `sub`. The tenant claims are hardcoded-claim
mappers (`business_units` and `campaigns` are JSON arrays) and every token
carries `environment=staging`.

No identity holds `odoo.campaign.control.write`, and none holds the separate
Middleware → Odoo outbound scope `odoo.campaign.control.read`.

Audience note: the certification identities emit the canonical
`middleware-api` audience declared by
`config/contracts/service-access-matrix.json`. The `codestra-middleware`
compatibility audience the deployed staging edge used to expect is retired:
Middleware branch `codex/cross-repo-authority-20260916` defaults
`N8N_SERVICE_AUDIENCE` to `middleware-api` and its
`deploy/keycloak/campaign-control-service-clients.v1.json` declares the five
identities above with `middleware-api` and no compatibility audience; the Kong
branch of the same name sets the staging campaign-automation routes to
`middleware-api`. Until staging Kong and Middleware are deployed from those
aligned sources, these tokens are rejected with `401` and the certification
stays `NO_GO`.

## Edge-contract pin

`contract.json` pins the Middleware edge contract
(`deploy/public-api-route-contract.json`, schema
`codestra.middleware.public-api-route-contract.v2`, 117 routes, hash rule
`sha256(json.dumps(contract, sort_keys=True, separators=(',', ':')))`):

```text
9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b
```

The pin was taken from Middleware `main` at `0606b0d` (2026-09-24, PAS-8), the
same digest pinned by Kong `main` (`3e68cb2`), Caddy `main` (`0feae8a`) and
`config/contracts/middleware-api-access.v3.json`. The four TEST_SYN route/scope
rows and five retired denied paths are unchanged from the earlier 92-route v2
pin `7580123dead97ea342c704a57a3c8eed9f5dce69aab247d4b693db96bc7334d5`
(branch `codex/cross-repo-authority-20260916`, contract commit `4c353df`).
That 92-route pin superseded the v1 pin
`af984cbaa41d1e3602ceb40be6fe383c0030a3c10cbea772efab7ff95d602d36`; the four
TEST_SYN route/scope rows are unchanged between v1 and v2, and v2 adds the
denied `GET /api/v1/integrations/odoo/campaign-commands/{command_id}` surface
to the retired list.

`scripts/edge_certification_desired_state.py --check` recomputes the hash and
compares the four route/scope rows whenever a Middleware checkout is available
(`--middleware-repo`, `CERTIFY_MIDDLEWARE_REPO`, or the sibling `../Middleware-`);
`--require-cross-check` turns an absent checkout into a failure. Until the v2
contract is merged, the sibling checkout must be on that branch or
`CERTIFY_MIDDLEWARE_REPO` must point at a worktree of it, or the cross-check
fails closed on the v1 digest. When the Middleware contract changes, its new
digest must be pinned here, in Kong, and in Caddy in the same change window,
or the certification stays `NO_GO`.

## Validation

```bash
python3 scripts/edge_certification_desired_state.py --check --require-cross-check
python3 -m unittest discover -s tests -p 'test_edge_integration_certification.py' -v
make edge-certification-check
```

`scripts/validate.sh` runs the tests through its `test_*certification*.py`
discovery; the tests build and check the committed plan, so CI proves the
plan is fresh without touching the trust-root closure.

## Staging reconciliation (operator, protected credential)

Only the staging instance is ever a valid target. The reconciler refuses any
`KC_PUBLIC_URL` other than `https://auth-staging.codestra.co`, refuses a
production issuer in the contract, verifies before and after apply that no
ingress scope is a realm default client scope, and never touches a client
outside the five certification identities.

```bash
export CERTIFY_ENVIRONMENT=staging CERTIFY_CAMPAIGN_ID=TEST_SYN
export KC_BASE_URL=https://auth-staging.codestra.co KC_PUBLIC_URL=https://auth-staging.codestra.co
export KC_TARGET_REALM=codestra KC_ADMIN_REALM=master
export KC_ADMIN_CLIENT_ID=<protected staging admin client>
export KC_ADMIN_CLIENT_SECRET_FILE=/run/secrets/keycloak-staging-admin   # 0600, outside Git
EDGE_CERTIFICATION_MODE=plan  EDGE_CERTIFICATION_DIR=/var/lib/codestra/edge-certification make reconcile-edge-certification
EDGE_CERTIFICATION_MODE=apply EDGE_CERTIFICATION_DIR=/var/lib/codestra/edge-certification make reconcile-edge-certification
```

`apply` creates or updates the three scopes and five clients, reads every
resource back against the desired source, links exactly `basic` plus the
assigned ingress scopes as default scopes, and writes each generated client
secret to `<dir>/<clientId>.secret` (0600) with the matching runner variable
printed next to it, for example
`CERTIFY_CLIENT_SECRET_FILE_N8N_SUBMIT=/var/lib/codestra/edge-certification/test-syn-n8n-submit.secret`.
Secret and token values are never printed and never enter evidence files.
`disable` is rollback step one (disable, prove unused, separately approve
deletion).

## Token certification and the redacted claim matrix

```bash
export CERTIFY_ENVIRONMENT=staging CERTIFY_CAMPAIGN_ID=TEST_SYN
export CERTIFY_CLIENT_SECRET_FILE_N8N_SUBMIT=/var/lib/codestra/edge-certification/test-syn-n8n-submit.secret
export CERTIFY_CLIENT_SECRET_FILE_N8N_READ=...  CERTIFY_CLIENT_SECRET_FILE_ODOO_READER=...
export CERTIFY_CLIENT_SECRET_FILE_WRONG_AUDIENCE=...  CERTIFY_CLIENT_SECRET_FILE_WRONG_TENANT=...
EDGE_IDENTITY_REPORT=/var/lib/codestra/evidence/keycloak-edge-identity.json make certify-edge-identity
```

The tool refuses to run outside `staging`/`TEST_SYN`, refuses raw secrets in
the environment, checks live discovery against the contract, mints one token
per identity, verifies the RS256 signature against the staging JWKS with the
standard library, and asserts per token: `iss`, exact `aud`, `azp`, `typ`,
`sub`/`jti` present, `60 ≤ exp-iat ≤ 300`, `nbf`, exact `scope`, no forbidden
or outbound scope, no `realm_access`/`resource_access`, `environment=staging`,
and the tenant, business-unit, and campaign bindings. Distinct tokens and
distinct `jti` values across identities are also required. Any failure exits
non-zero (`NO_GO`). The report contains claim values and SHA-256 fingerprints
only; no token or secret is ever written or printed. These variable names are
identical to the Middleware runner's, so one environment serves both tools.

## Cross-component prerequisites this repository cannot satisfy

* Kong must declare all four routes with exact methods and scopes, accept the
  five `azp` values, `environment=staging`, and the staging issuer/JWKS, and
  pin the same edge-contract hash.
* Caddy must forward all four routes (with method matchers) to Kong ahead of
  the legacy fallback on a staging API hostname.
* Middleware must run with `N8N_CAMPAIGN_SERVICE_CLIENT_IDS` and
  `ODOO_CAMPAIGN_READER_CLIENT_IDS` covering the identities above, environment
  `staging`, and the staging issuer.
* Staging Odoo must hold campaign `TEST_SYN` and its desired-state record with
  provider writes disabled.

Until all four components pin the identical hash and the live matrix and
routing proof pass, the certification verdict is `NO_GO`.
