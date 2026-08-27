# Keycloak identities for governed n8n automation

## Authority

Keycloak is the machine-identity authority. n8n workflow clients authenticate to Middleware only. They do not receive direct access to Odoo, VICIdial, Asterisk, Telnexa, Jasmin, Klyrow, Postal, Mautic, Kyqra, Postly, product databases or provider APIs.

Canonical issuer:

```text
https://auth.codestra.co/realms/codestra
```

Machine clients use Client Credentials with short-lived tokens. Human users do not use these clients, and workflow clients do not use browser flows, direct grants or implicit flow.

## Proposed clients

```text
n8n-platform-runtime
n8n-crm-automation
n8n-telephony-automation
n8n-messaging-automation
n8n-crawler-automation
n8n-product-automation
n8n-privacy-automation
n8n-operations-automation
```

Every client is confidential, has service accounts enabled, has a maximum access-token lifetime of 300 seconds, and targets the `middleware-api` audience.

## Scope families

```text
automation.job.claim
automation.job.heartbeat
automation.job.complete
automation.command.crm
automation.command.telephony
automation.command.messaging
automation.command.crawler
automation.command.product
automation.approval.read
automation.operations.reconcile
automation.operations.replay
```

No client receives all scope families by default.

## Separation

| Client | Intended scopes |
|---|---|
| `n8n-platform-runtime` | Job claim, heartbeat and completion |
| `n8n-crm-automation` | Runtime scopes plus CRM commands |
| `n8n-telephony-automation` | Runtime scopes plus telephony commands |
| `n8n-messaging-automation` | Runtime scopes plus SMS/email commands |
| `n8n-crawler-automation` | Runtime scopes plus crawler commands |
| `n8n-product-automation` | Runtime scopes plus allowlisted product commands |
| `n8n-privacy-automation` | Runtime scopes plus approved privacy commands |
| `n8n-operations-automation` | Runtime scopes plus reconciliation and protected replay |

`automation.operations.replay` must be ineffective unless Middleware also has a valid protected approval and `DEAD_LETTER_REPLAY=true`.

## Token and claim requirements

```text
iss = canonical issuer
aud includes middleware-api
azp = exact client ID
exp, iat and nbf validated
service-account subject mapped locally
scope checked per route
tenant authority resolved by Middleware
```

n8n cannot choose an arbitrary tenant by sending a header. Middleware validates every tenant value against the event/job and local service authorization.

## GitOps safety

The accompanying client contract is declaration only:

```text
PROVISIONING_STATE=declared-not-created
CLIENT_SECRETS_IN_GIT=NO
LIVE_KEYCLOAK_CHANGED=NO
```

Creation or update requires the existing protected Keycloak check/apply process, exact merged `main` SHA, a reviewed deterministic plan, protected environment approval, post-apply zero drift and OIDC acceptance checks.

## Branch dependencies

```text
Keycloak/main
Middleware-/integration/keycloak
Middleware-/integration/n8n
N8N/contract/automation-control-plane-v2-20260827
N8N/shared/automation-runtime
```

## Acceptance

```text
CLIENT_CREDENTIALS_ONLY=PASS
DIRECT_ACCESS_GRANTS=DISABLED
IMPLICIT_FLOW=DISABLED
SERVICE_ACCOUNTS=ENABLED
SHORT_LIVED_TOKENS=PASS
AUDIENCE_MIDDLEWARE_ONLY=PASS
LEAST_PRIVILEGE_SCOPES=PASS
CUSTOMER_PLATFORM_ADMIN_MAPPING=DENIED
SECRETS_IN_GIT=NO
LIVE_APPLY=NO
```
