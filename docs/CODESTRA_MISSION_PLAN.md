# Codestra Mission Plan to Completion

## Scope

This mission covers the CRM/telephony/messaging control plane across Middleware, Odoo, Keycloak, n8n, Kong, Telnexa, Klyrow, Kyqra, VICIdial/Asterisk, and provisioning.

Other products remain independent missions with their own launch criteria.

## Operating model

There is no central release-authority repository. Every repository ships independently and couples to other systems only through reviewed, versioned contracts.

For identity, this repository is authoritative. Cross-repository plans may depend on Keycloak, but they do not grant another repository authority to mutate Keycloak.

Each stage below has an entry condition, concrete tasks, and an exit condition. A stage is not complete because code exists; it is complete only when the stated verification proves the result.

---

## Stage 0 — Establish ground truth

### Why first

Several repositories in the control-plane mission have historically had incomplete or unaudited runtime claims. Later integration stages must not be scheduled around assumptions.

### Entry condition

None.

### Tasks

1. Produce a one-page audit for each relevant repository covering README claims versus actual code, test coverage, CI presence, TODO/stub count, and last substantive commit versus scaffold-only commits.
2. Resolve duplicate/ambiguous repository pairs and document the authoritative source for each system.
3. Confirm backend/frontend splits explicitly where separate repositories represent one product.
4. Verify deployment status from each authoritative repository rather than inheriting claims from another project's README.
5. Determine whether the standalone SDK repository duplicates connector SDK code embedded in Middleware; consolidate ownership if needed.
6. Confirm which repository owns edge/Caddy configuration.
7. Record the findings in the architecture documentation and replace every remaining `unknown`, `needs audit`, or inferred runtime status with verified evidence.

### Exit condition

A Stage 0 findings document exists and every dependency needed by the identity/integration stages has a verified repository, CI status, runtime status, and ownership boundary.

---

## Stage 1 — Identity foundation

### Why here

Kong, Middleware, Odoo, n8n, and provider adapters depend on Keycloak-issued identity. End-to-end integration cannot be considered valid until the identity layer works and its protected change process is proven.

### Entry condition

Stage 0 audit of the Keycloak repository is complete.

### Tasks — owner: `appolon1908-hue/Keycloak`

1. Verify the canonical Keycloak public endpoint and discovery document are healthy before downstream integration testing.
2. Maintain one machine client per service boundary. The baseline identity set is:
   - `kong-gateway`
   - `middleware-api`
   - `middleware-worker`
   - `odoo-integration`
   - `n8n-automation`
   - `vicidial-adapter`
   - `telnexa-gateway`
   - `klyrow-gateway`
   - `kyqra-gateway`
   - `postly-adapter`
   - `provisioning-service`
   - `monitoring-readonly`
3. Do not share credentials between services.
4. Keep check-mode, drift review, and protected apply as separate gates.
5. Require exact merged-main SHA and reviewed plan hash for apply.
6. Re-fetch every existing client immediately before its `PUT` and reject the apply if the live pre-change hash no longer matches the reviewed state.
7. Produce a durable partial-apply/recovery manifest for every mutation attempt.
8. Pin runtime images by immutable digest before production certification.
9. Promote one reviewed test caller from `declared-not-created` into the active desired state in `config/contracts/machine-clients.json`, `config/policy/managed-clients.json`, and `config/policy/creatable-clients.json`; validate its unique protected credential before mutation and retain rollback evidence.
10. Prove Client Credentials flow from at least one service client through the canonical issuer and verify Kong accepts the resulting token under the intended audience/scope contract.

### Exit condition

A service successfully completes Client Credentials against the canonical issuer and receives a token accepted by Kong, verified against the live runtime; the protected Keycloak check/apply path has also passed its concurrency, recovery, immutable-image, convergence, and rollback-rehearsal gates.

---

## Stage 2 — Edge authorization

Owner: `appolon1908-hue/Kong`. Consume the exact Stage 1 issuer, audience, scope, and tenant claims; pass positive and negative route tests. Exit only when unauthorized, wrong-audience, wrong-tenant, and excessive-scope requests are denied.

## Stage 3 — Middleware integration

Owner: `appolon1908-hue/Middleware-`. Bind browser and machine callers to the reviewed Keycloak/Kong contract, durable inbox/outbox processing, tenancy, idempotency, and audit. Exit only after exact-SHA integration and rollback gates pass with external delivery disabled.

## Stage 4 — Odoo and n8n application flows

Owners: `appolon1908-hue/Odoo` and `appolon1908-hue/N8N`. Consume narrow Middleware identities; do not receive Keycloak password, reset, OTP, or client-secret material. Exit after tenant isolation, duplicate-event, retry, and no-effect failure tests pass.

## Stage 5 — Provider adapters and communications

Owners: Telnexa, Klyrow, Kyqra, Postal, social, and communications repositories. Use dedicated machine identities and reviewed provider contracts. Exit after controlled staging evidence proves correlation, consent, suppression, delivery reconciliation, and kill switches; live external effects remain disabled.

## Stage 6 — Telephony and provisioning

Owners: VICIdial/Asterisk and provisioning repositories. Require campaign-scoped identities and deny predictive dialing, customer-list activation, and broad administrative writes by default. Exit only after the separately approved one-call authorization package and complete rollback rehearsal.

## Stage 7 — Protected production promotion

Each owning repository publishes an immutable, signed, attested release and records its exact source/image tuple. The production platform verifies all component attestations, compatibility locks, approvals, backup/restore evidence, and unchanged kill switches before any narrow operator is installed. Merge alone never authorizes deployment.

## Stage ownership rule

Future stages for Middleware, Kong, Odoo, n8n, telephony, messaging, provider adapters, and provisioning must live in their owning repositories or in a cross-repository planning document. They may reference Keycloak contracts but must not move application-specific logic, provider credentials, or non-identity release authority into this repository.
