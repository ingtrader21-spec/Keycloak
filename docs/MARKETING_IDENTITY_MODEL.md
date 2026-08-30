# Marketing Identity Model

## Service clients
- codestra-marketing
- codestra-ai
- codestra-communication
- codestra-social
- codestra-middleware
- codestra-n8n
- codestra-odoo

## User roles
- marketing_viewer
- marketing_operator
- marketing_approver
- marketing_admin
- sales_closer

## Service scopes
- marketing.read / marketing.write / marketing.approve
- ai.invoke
- communication.read / communication.send
- social.read / social.write / social.approve
- crm.lead.read / crm.lead.write

Least privilege is mandatory. Service credentials must be separate per environment. AI service identity never receives marketing.approve or direct provider-spend authority. Human approval roles must not be silently granted to automation clients.
