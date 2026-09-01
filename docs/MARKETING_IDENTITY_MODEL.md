# Marketing Identity Model

## Canonical service clients
Use the repository's canonical managed client identifiers for existing platform services:
- codestra-marketing
- codestra-ai
- codestra-communication
- codestra-social
- middleware-api
- n8n-automation
- odoo-integration

New aliases such as `codestra-middleware`, `codestra-n8n`, or `codestra-odoo` must not be introduced unless the authoritative managed-client contracts are changed in the same reviewed change.

## User roles
- marketing_viewer
- marketing_operator
- marketing_approver
- marketing_admin
- sales_closer

## Service scopes
- marketing.read
- marketing.write
- marketing.approve
- ai.invoke
- communication.read
- communication.send
- social.read
- social.write
- social.approve
- crm.lead.read
- crm.lead.write

## Default deny
Any role, client, audience, or scope grant not explicitly listed below is denied. Machine identities never inherit human roles. No automation or machine identity may receive `marketing.approve`, provider-spend authority, or any equivalent permission to activate paid media, increase budgets, or approve provider writes.

## User-role grants
| Role | Audience | Allowed scopes |
|---|---|---|
| marketing_viewer | codestra-marketing | marketing.read |
| marketing_operator | codestra-marketing | marketing.read, marketing.write |
| marketing_approver | codestra-marketing | marketing.read, marketing.write, marketing.approve |
| marketing_admin | codestra-marketing | marketing.read, marketing.write, marketing.approve |
| sales_closer | odoo-integration | crm.lead.read, crm.lead.write |

## Machine-client grants
| Client | Audience | Allowed scopes | Explicit denials |
|---|---|---|---|
| codestra-marketing | codestra-ai | ai.invoke | marketing.approve; provider spend/write authority |
| codestra-marketing | codestra-communication | communication.read, communication.send | provider credential ownership |
| codestra-marketing | codestra-social | social.read, social.write | social.approve unless a human-approved command is represented by the owning Social service |
| middleware-api | codestra-marketing | marketing.read, marketing.write | marketing.approve; provider spend/write authority |
| middleware-api | odoo-integration | crm.lead.read, crm.lead.write | human roles |
| n8n-automation | middleware-api | only scopes already authorized by the canonical service-access matrix | marketing.approve; provider spend/write authority; direct downstream/provider credentials |
| odoo-integration | middleware-api | only scopes already authorized by the canonical service-access matrix | marketing.approve; provider spend/write authority |

## Security invariants
- Least privilege is mandatory.
- Service credentials are separate per environment and never committed to Git.
- Every machine/automation identity is denied `marketing.approve` and provider-spend authority.
- Human approval roles must never be assigned to automation clients or service accounts.
- The authoritative `machine-clients.json` and `service-access-matrix.json` contracts remain the implementation source of truth; this marketing model must stay aligned with them.
