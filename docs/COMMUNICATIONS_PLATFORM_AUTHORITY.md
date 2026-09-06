# Communications Platform Authority — Keycloak / Identity

## Purpose

This document defines `appolon1908-hue/Keycloak` as the principal identity authority for the unified communications platform.

## Permanent ownership

This repository owns:

- Codestra realm desired state;
- human OIDC clients and PKCE policy;
- machine/service clients;
- scopes, audiences and token policy;
- identity drift detection and reviewed apply controls;
- read-only OIDC acceptance/smoke verification.

This repository does not own:

- API routing/policy — `Kong`;
- cross-system authorization, durable commands or provider execution — `Middleware-`;
- channel runtimes — `klyrow.com`, `telnexa`, `Vicidialer-Codestra`;
- SDK contracts — `SDK-repository`;
- CRM state — `Odoo`;
- workflow orchestration — `N8N`;
- shared TLS edge — `Caddy`.

## Required identity path

```text
Human/service client
      -> Keycloak token issuance
      -> Caddy
      -> Kong validation and route/scope policy
      -> Middleware authorization revalidation
      -> channel/provider adapter
```

Keycloak proves identity and issues claims. It does not by itself authorize a cross-system business effect. Middleware remains the final privileged authorization boundary.

## Communications client model

Every service or product integrating with communications must have a separately reviewed identity. Shared broad service credentials are prohibited.

Required identity properties include:

- unique client ID;
- narrowly scoped service account or PKCE browser client;
- explicit intended audience(s);
- explicit communication scopes;
- short token lifetime;
- `fullScopeAllowed=false` for managed machine clients;
- no password/direct grant or implicit flow;
- no unnecessary redirect URIs/origins;
- no client secrets stored in Git.

Suggested scope families are provider-neutral and should be granted only where required, for example:

- `communications.email.send`;
- `communications.email.read`;
- `communications.sms.send`;
- `communications.sms.read`;
- `communications.voice.command`;
- `communications.voice.read`;
- `communications.templates.manage`;
- `communications.domains.read`;
- `communications.reputation.read`;
- `communications.webhooks.manage`;
- `communications.analytics.read`.

Final scope names must be versioned and kept consistent across Keycloak, Kong, Middleware and SDK contracts.

## Caller-token contract

The production caller-token model must be identical across Keycloak, Kong and Middleware. Before cutover, prove end to end that:

1. Keycloak issues the intended token to the intended client;
2. Kong validates issuer, signature, expiry, audience and required scopes;
3. Kong preserves the caller identity needed by Middleware;
4. Middleware independently revalidates the token/claims required for privileged commands;
5. invalid issuer, audience, scope, tenant or client is rejected;
6. one product/service cannot use another product/service's scopes or tenant context.

A mismatch between Kong token forwarding and Middleware `azp`/audience expectations is a production blocker, not a documentation warning.

## Human and machine authentication rules

Human/browser applications use Authorization Code + PKCE S256. Machine-to-machine callers use Client Credentials with distinct confidential clients. Do not place machine credentials in browsers, SDK source, n8n workflow exports or application repositories.

## Tenant and role principles

Identity claims may carry stable subject/client identity and reviewed scopes/roles. Tenant membership/authorization must still be enforced by the owning application/Middleware using authoritative tenant mappings. Never trust an arbitrary caller-supplied tenant header without binding it to authenticated authorization.

## Safety rules

1. Never commit client secrets, user credentials, signing keys, tokens, OTP seeds or live realm exports containing secrets.
2. A merge never applies Keycloak changes to production automatically.
3. Every new communication client or scope requires least-privilege review.
4. Token lifetime must remain short for machine clients.
5. Browser clients must not receive service-account privileges.
6. Service clients must not receive administrator roles unless separately justified and approved.
7. Kong and Middleware acceptance tests must accompany identity contract changes.
8. Removed scopes/clients require consumer impact review and staged revocation.
9. Identity drift plans must be reviewed before apply.
10. Emergency revocation/disable procedures must exist for compromised clients.

## Cross-repository contract requirements

Identity-affecting communications changes require coordinated evidence from:

- `Keycloak` — desired identity state;
- `Kong` — issuer/audience/scope enforcement;
- `Middleware-` — caller authorization and tenant binding;
- `SDK-repository` — documented auth requirements and generated client behavior;
- the relevant provider/channel repository;
- `N8N` and `Odoo` when their service identities/scopes are affected;
- `Caddy` only when public identity routing changes.

## Release gates

Before a communications client/scope becomes production-authoritative:

1. desired-state validation passes at exact head;
2. merge-result validation passes;
3. runtime preflight verifies the target instance;
4. deterministic drift plan is independently reviewed;
5. apply is bound to the exact accepted main SHA and reviewed plan;
6. read-only OIDC smoke tests pass;
7. Kong acceptance/rejection tests pass;
8. Middleware acceptance/rejection and tenant-binding tests pass;
9. no secret material is present in Git/evidence;
10. activation approval is separate from source merge approval.

## Branching

Use short-lived `feature/*`, `fix/*`, `docs/*` and `test/*` branches. Identity changes are promoted through protected review and GitOps check/apply; documentation changes never authorize a live identity apply.
