# Repository Profile — `Keycloak`

## Identity

- **Repository:** `appolon1908-hue/Keycloak`
- **Category:** Platform security — identity
- **Visibility:** `private`
- **Default branch:** `main`
- **Authority:** Primary Codestra identity, OIDC, realm, client, role, and authentication-policy authority
- **Status:** Active GitOps repository with protected desired-state, plan, review, apply, export, and rollback work.

## Purpose

Manages human and machine identities, OIDC clients, roles, scopes, audiences, authentication flows, MFA, session/token policy, recovery, and authoritative identity deployment source.

## Owns

- Keycloak realm desired state and runtime packaging
- OIDC clients, roles, groups, scopes, audiences, mappers, authentication flows, and identity policy
- Protected identity planning, independent review, apply, read-back, export, and rollback controls

## Does not own

- Application business-state authorization beyond approved identity claims
- Client secrets, passwords, recovery material, or private keys in Git
- Live apply from unmerged feature branches or without protected approval

## Key integrations

- Kong and Middleware
- Product frontends, APIs, and machine clients
- Grafana, Superset, and OpenBao
- Klyrow SMTP for approved identity email paths

## Current priorities

1. Promote managed observability clients and realm roles through protected branches
2. Consolidate stacked identity/security work into an auditable merge sequence
3. Keep generated and existing client secrets external and redacted
4. Prove staging login, denial, role isolation, read-back, recovery, and rollback before production apply

## Governance and safety

- Promotion model: `feature/docs/fix/security/upgrade -> development -> test -> staging -> production -> main`.
- Every apply must bind an independently approved plan hash to the exact accepted source SHA.
- Never commit credentials, tokens, passwords, OTP/reset material, realm exports containing secrets, or recovery keys.
- Merge is desired-state acceptance only; live identity mutation remains separately authorized.
- This document does not create clients/roles/users, generate secrets, send identity email, restart Keycloak, or apply production state.

## Account-wide catalog

See `appolon1908-hue/documentaions/REPOSITORY_CATALOG.md`.
