# Keycloak identities for governed n8n automation

## Authority

Keycloak is the machine-identity authority. n8n workflow clients authenticate to Middleware only. They do not receive direct access to Odoo, VICIdial, Asterisk, Telnexa/Jasmin, Klyrow/Postal/Mautic, Postly/Postiz or social providers, Kyqra/Crawlee, Beyvra, product databases or provider APIs.

Canonical issuer:

```text
https://auth.codestra.co/realms/codestra
```

Machine clients use Client Credentials with short-lived tokens. Human users do not use these clients, and workflow clients do not use browser flows, direct grants or implicit flow.

## Canonical authorization source

The client declarations mirror:

```text
appolon1908-hue/Middleware-
integration/n8n-control-plane-v2-20260827
contracts/automation/operation-policy.v2.json
```

Generic `automation.execute` and `automation.command` scopes are prohibited. Middleware enforces both the OAuth scope and the client/workflow-family/command-prefix mapping.

## Proposed clients

```text
n8n-platform-runtime
n8n-identity-automation
n8n-crm-automation
n8n-telephony-automation
n8n-messaging-automation
n8n-social-automation
n8n-crawler-automation
n8n-product-automation
n8n-privacy-automation
n8n-operations-automation
```

Every client is confidential, has service accounts enabled, has a maximum access-token lifetime of 300 seconds, targets the `middleware-api` audience, and has no browser or direct-grant flow.

## Beyvra boundary

Beyvra uses the existing `n8n-product-automation` identity only for:

```text
workflow_family = product.beyvra-nonfinancial
command_prefix  = beyvra.operations.
```

The Beyvra frontend is not a machine client. No browser receives an n8n or Middleware service token. Financial and demo-order effects remain prohibited:

```text
trade.*
order.*
wallet.*
ledger.*
hold.*
payment.*
withdrawal.*
deposit.*
transfer.*
custody.*
chain.*
broker.*
provider.*
```

## Token and claim requirements

```text
iss = canonical issuer
aud includes middleware-api
azp = exact client ID
exp, iat and nbf validated
maximum token age <= 300 seconds
service-account subject mapped locally
scope checked per route
workflow family checked per job
command prefix checked per command
tenant and actor derived from the durable job
```

n8n cannot choose an arbitrary tenant or actor by sending a header or payload field.

## GitOps safety

The accompanying client contract is declaration only:

```text
PROVISIONING_STATE=declared-not-created
CLIENT_SECRETS_IN_GIT=NO
LIVE_KEYCLOAK_CHANGED=NO
```

Creation or update requires the existing protected Keycloak check/plan/apply process, exact merged `main` SHA, a reviewed deterministic plan, protected environment approval, post-apply zero drift and OIDC acceptance checks.

## Branch dependencies

```text
Middleware PR #15
N8N PR #9
social.codestra.co PR #1
beyvra-backend PR #52
beyvra-frontend PR #24
N8N/shared/automation-runtime-v2-20260827
```

## Acceptance state

```text
CLIENT_CONTRACT=PRESENT
INDEPENDENT_APPROVAL=PENDING
LIVE_CLIENTS_CREATED=NO
SECRETS_IN_GIT=NO
LIVE_APPLY=NO
```
