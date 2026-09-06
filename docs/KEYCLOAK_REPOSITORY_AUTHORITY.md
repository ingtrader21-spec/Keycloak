# Keycloak Repository Authority

## Status

This repository is the independent Git authority for the Codestra Keycloak identity platform.

It is intentionally standalone. No central release-authority repository may directly mutate Keycloak production state. Other repositories integrate with Keycloak through reviewed identity contracts, issuer/audience requirements, and documented client/scoping conventions.

## Canonical identity boundary

The repository owns:

- Keycloak realm desired state and invariants.
- OIDC/OAuth client definitions and reviewed client creation policy.
- Service-account client contracts.
- Browser-client PKCE contracts.
- Client scopes, protocol mappers, audiences, roles, and identity policy that belong in Keycloak.
- Canonical issuer/endpoints contract.
- Managed-client and creatable-client boundaries.
- Drift planning and read-only runtime verification.
- Protected configuration apply tooling.
- Rollback/recovery evidence for managed Keycloak changes.
- Keycloak runtime container definitions used by this repository.
- CI policy and repository-side release evidence for Keycloak changes.

The repository does not own:

- Application business logic.
- Kong route definitions or gateway business policy.
- Middleware cross-system orchestration.
- Odoo business workflows.
- n8n automation logic.
- VICIdial/Asterisk campaign logic.
- Provider application internals.
- Production secrets, client secrets, private keys, user credentials, access tokens, or server environment files.

## Canonical public contract

```text
Public URL:       https://auth.codestra.co
Canonical issuer: https://auth.codestra.co/realms/codestra
Discovery:        https://auth.codestra.co/realms/codestra/.well-known/openid-configuration
```

All downstream systems must treat the issuer and identity contracts published by this repository as authoritative. Downstream repositories may validate compatibility, but may not silently redefine the issuer, client ownership, audience, grant type, or authentication boundary.

## Authentication policy

### Human/browser clients

- Authorization Code Flow only.
- PKCE `S256` required.
- No Implicit Flow.
- No password/direct grant.
- No long-lived browser token storage policy may be introduced here as a workaround for application design.

### Machine/service clients

- Client Credentials flow.
- One confidential service client per service boundary.
- No shared service credentials between unrelated services.
- Short-lived access tokens.
- Explicit scope and audience contracts.
- Client creation must remain separately allowlisted and reviewed.

## Independent change flow

1. Create a feature branch from protected `main`.
2. Change reviewed desired state or repository automation.
3. Run exact-source-head CI.
4. Run merge-result CI.
5. Obtain independent review against the unchanged exact head.
6. Merge to protected `main`.
7. Record the exact merged `main` SHA.
8. Run read-only runtime preflight for that exact SHA.
9. Run protected deployment workflow in `check` mode.
10. Review the deterministic plan and record its SHA-256.
11. Require protected-environment approval.
12. Run `apply` only for the same merged SHA and reviewed plan hash.
13. Verify convergence and OIDC behavior after apply.
14. Persist recovery/partial-apply evidence for every mutation attempt.

A Git merge is never permission to mutate live Keycloak automatically.

## Mandatory production safety rules

### 1. Optimistic concurrency immediately before every update

Existing clients must be re-fetched immediately before the corresponding `PUT`. The live state must still match the reviewed expected pre-change hash. A stale representation prepared earlier in the apply process must never be allowed to overwrite a concurrent administrator or deployment change.

### 2. Durable partial-apply recovery

A multi-resource apply can fail after earlier writes have already succeeded. Every protected apply must therefore produce durable mutation/recovery evidence that records at minimum:

- exact repository SHA;
- exact reviewed plan SHA-256;
- environment and realm;
- operation order;
- pre-apply state hashes;
- completed creates/updates;
- failed operation;
- rollback material or approved recovery instructions;
- final convergence result;
- explicit `COMPLETE`, `PARTIAL_APPLY`, or `FAILED_BEFORE_WRITE` status.

Production apply must never report a generic failure that hides already-committed mutations.

### 3. Immutable runtime artifacts

Keycloak and database runtime images used for protected environments must be pinned by digest (`name:tag@sha256:...`). Mutable tags alone are not acceptable release evidence.

Digest updates must arrive as reviewed dependency changes through the normal branch/PR/CI path.

## Cross-repository integration model

Other repositories may depend on Keycloak only through versioned contracts such as:

- issuer/discovery URL;
- client ID;
- client type and grant policy;
- redirect URI contract;
- audience;
- required scopes/roles;
- token validation requirements;
- service-to-service identity contract.

They must not copy production Keycloak administration credentials or run independent admin mutations against the realm.

## Repository governance

Protected `main` should require:

- pull request review;
- required CI checks;
- exact-head freshness before merge;
- no force pushes;
- no branch deletion bypass for protected release refs;
- protected deployment environments for staging and production;
- independent approval for production configuration apply.

Repository rules, GitHub Environment reviewers, deployment credentials, deploy keys, and production secrets remain external control-plane configuration and must not be committed.

## Current hardening gates

The repository is not considered fully production-certified until all of the following are demonstrated:

- per-update pre-write re-fetch/hash validation;
- durable partial-apply recovery manifest;
- immutable Keycloak and PostgreSQL image digests;
- full `make validate` in CI with all required tooling;
- successful read-only runtime preflight;
- successful protected `check` with zero blocked resources;
- reviewed-plan `apply` in a non-production rehearsal;
- rollback/recovery rehearsal;
- post-apply convergence and OIDC smoke test.

## Authority statement

`appolon1908-hue/Keycloak` is the authoritative independent repository for Codestra Keycloak identity configuration and its protected change process. Cross-system mission documents may reference this repository, but they do not supersede this repository's identity authority or permit another repository to mutate Keycloak directly.
