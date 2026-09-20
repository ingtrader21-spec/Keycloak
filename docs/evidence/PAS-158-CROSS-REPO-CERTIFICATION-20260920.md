# PAS-158 — Cross-Repository Identity Certification

## Verdict

PAS158_VERDICT=BLOCKED_CROSS_REPO_PARITY

Production effects remain disabled. The prior PR #118 `missing-independent-approval` trust-root result is tracked as a separate release-governance blocker and is not conflated with implementation parity.

## Exact pins

- Keycloak: `45a487d71a516ae3039b00c250752897469ffe7a`
- Kong: `5ac254c6fb04579615e4d60d25efcc911d42a2e3`
- Caddy: `84c2b7b3bce6d90764eac5eab362aed973f56056`
- Middleware: `2862af0aa97367b18cb360af69212abe4243a1ac`
- Middleware route digest: `9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b`

## Keycloak ↔ Middleware

- status: **PASS**
- Middleware routes: 117
- Keycloak routes: 117
- exact route-set parity: PASS
- audience: `middleware-api`
- exact-target caller certification: PASS
- `UNKNOWN_CALLER_IDENTITIES=0`
- `SERVICE_OR_USER_ROUTES=84`
- token matrix: 8 positive / 8 negative
- privileged default-scope leaks: 0

## Kong ↔ Middleware

- status: **BLOCKED**
- Middleware shared-edge routes: 105
- Kong routes: 80
- matching routes: 80
- field mismatches on matching routes: 0
- missing shared-edge routes: **25**
- Middleware `/platform/v1` shared routes: 84
- Kong `/platform/v1` routes: 59

### Missing Kong routes

| Method | Path | Caller | Scope | Auth |
| --- | --- | --- | --- | --- |
| `GET` | `/platform/v1/contacts` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `GET` | `/platform/v1/contacts/{contact_id}` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `GET` | `/platform/v1/contacts/{contact_id}/notes` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `GET` | `/platform/v1/contacts/{contact_id}/tasks` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `GET` | `/platform/v1/kernel/describe` | `platform-command-client` | `platform.command.read` | `service-or-user-jwt` |
| `GET` | `/platform/v1/operations/{operation_id}` | `platform-command-client` | `platform.command.read` | `service-or-user-jwt` |
| `GET` | `/platform/v1/operations/{operation_id}/timeline` | `platform-command-client` | `platform.command.read` | `service-or-user-jwt` |
| `GET` | `/platform/v1/opportunities` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `GET` | `/platform/v1/opportunities/{opportunity_id}` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `GET` | `/platform/v1/tickets` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `GET` | `/platform/v1/tickets/{ticket_id}` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `PATCH` | `/platform/v1/contacts/{contact_id}` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `PATCH` | `/platform/v1/contacts/{contact_id}/notes/{note_id}` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `PATCH` | `/platform/v1/opportunities/{opportunity_id}` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `PATCH` | `/platform/v1/tasks/{task_id}` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `PATCH` | `/platform/v1/tickets/{ticket_id}` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `POST` | `/platform/v1/commands` | `platform-command-client` | `platform.command` | `service-or-user-jwt` |
| `POST` | `/platform/v1/contacts` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `POST` | `/platform/v1/contacts/{contact_id}/notes` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `POST` | `/platform/v1/contacts/{contact_id}/tasks` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `POST` | `/platform/v1/operations/{operation_id}/cancel` | `platform-command-client` | `platform.command` | `service-or-user-jwt` |
| `POST` | `/platform/v1/operations/{operation_id}/replay` | `platform-command-client` | `platform.command.replay` | `service-or-user-jwt` |
| `POST` | `/platform/v1/opportunities` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `POST` | `/platform/v1/tasks/{task_id}/complete` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |
| `POST` | `/platform/v1/tickets` | `authorized-provisioning-client` | `identity.request` | `service-or-user-jwt` |

## Caddy ↔ Kong

- status: **BLOCKED**
- `/platform/v1` prefix declared for Kong: `false`
- `/platform/v1` matcher present in `sites/api.codestra.co.caddy`: `false`
- Caddy correctly leaves OIDC/JWT/scope enforcement to Kong and privileged re-authorization to Middleware.
- Current source does not authorize production cutover.

## Required repair before PAS-158 can pass

1. Kong must extend its canonical Middleware authority from 80 to all 105 shared-edge routes, adding the 25 missing routes without changing the 80 already-matching route semantics.
2. Caddy must route the accepted `/platform/v1/*` surface to Kong instead of the legacy fallback, while preserving bearer authorization and host forwarding.
3. Re-run PAS-158 at new exact Kong/Caddy SHAs and require zero missing routes, zero field mismatches, and a passing Caddy platform boundary.

## Release governance

`BOOTSTRAP_REJECTED=missing-independent-approval` remains a separate governance item from the pre-merge PR #118 trust-root run. The merged implementation must not be described as production-certified until the release-governance and later staging/recovery gates are complete.
