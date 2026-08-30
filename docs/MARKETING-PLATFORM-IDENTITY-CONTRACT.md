# Keycloak — Marketing Platform Identity Contract

## Mission
Keycloak is the identity and access-management authority for Codestra users and service identities used by the marketing platform.

## Owns
- User authentication
- Service identities
- Roles, groups and scoped claims
- Client registrations
- Session and token policy
- Identity federation where approved

## Does Not Own
- Marketing, CRM, communication, social or AI business state
- API routing
- Workflow orchestration
- Provider integrations

## Required Access Model
The platform must distinguish human users, operators, approvers, service identities and machine workflows. Roles and scopes should be least-privilege and mapped to business-service authorization checks.

## Required Principles
- Authorization Code with PKCE for interactive browser/mobile clients where applicable
- Service credentials only for approved machine-to-machine integrations
- Short-lived access tokens and controlled refresh/session policy
- No provider secrets stored in user clients
- Tenant/business/campaign context must be enforced by the owning service, not trusted solely from the client
- Administrative roles must be separate from normal operator roles

## Integration Expectations
Kong validates identity at the edge where appropriate. Business services still enforce resource-level authorization. Odoo, Marketing, Communication, Social and AI consume only the claims they need.

## Implementation Order
1. Client/service inventory
2. Role and scope matrix
3. Token/claim contract
4. Service-account mapping
5. Staging validation
6. Negative authorization tests
7. Production promotion with audit evidence