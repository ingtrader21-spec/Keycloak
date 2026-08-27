# MoneyBee OIDC client contract

This document is the operator-facing companion to `config/identity/moneybee-oidc-clients.json`.

## Canonical runtime identity

- Realm: `codestra`
- Issuer: `https://auth.codestra.co/realms/codestra`
- API audience: `moneybee-api`
- Canonical MoneyBee domain: `moneybeeloan.com`
- Do not use `moneybeeloans.com`.
- Do not use `moneybee.loan` as a MoneyBee runtime or redirect domain.
- Do not create `auth.moneybeeloan.com`; MoneyBee authenticates through `auth.codestra.co`.

## Public PKCE clients

MoneyBee uses three separate human clients. They are public clients using Authorization Code flow with PKCE S256. Client secrets, implicit flow, direct access grants, and service accounts must remain disabled.

### Borrower portal

- Client ID: `moneybee-borrower`
- Origin: `https://app.moneybeeloan.com`
- Valid redirect URIs:
  - `https://app.moneybeeloan.com/auth/callback`
  - `https://app.moneybeeloan.com/auth/silent-callback`
- Valid post-logout redirect URI:
  - `https://app.moneybeeloan.com/auth/login`
- Web origin:
  - `https://app.moneybeeloan.com`

### Lender portal

- Client ID: `moneybee-lender`
- Origin: `https://lenders.moneybeeloan.com`
- Valid redirect URIs:
  - `https://lenders.moneybeeloan.com/auth/callback`
  - `https://lenders.moneybeeloan.com/auth/silent-callback`
- Valid post-logout redirect URI:
  - `https://lenders.moneybeeloan.com/auth/login`
- Web origin:
  - `https://lenders.moneybeeloan.com`

### Admin portal

- Client ID: `moneybee-admin`
- Origin: `https://admin.moneybeeloan.com`
- Valid redirect URIs:
  - `https://admin.moneybeeloan.com/auth/callback`
  - `https://admin.moneybeeloan.com/auth/silent-callback`
- Valid post-logout redirect URI:
  - `https://admin.moneybeeloan.com/auth/login`
- Web origin:
  - `https://admin.moneybeeloan.com`

## Keycloak client settings

For all three clients:

- Client type: OpenID Connect
- Client authentication: Off / public client
- Standard flow: On
- PKCE method: S256
- Implicit flow: Off
- Direct access grants: Off
- Service accounts: Off
- Wildcard redirect URIs: prohibited
- Web origins: exact values only

## Runtime verification

Before enabling production login, verify all of the following against the live `codestra` realm:

1. Each exact client ID exists and is enabled.
2. Each client is public and has no client secret dependency.
3. Standard Authorization Code flow is enabled.
4. PKCE S256 is required.
5. Redirect URIs and web origins exactly match this document.
6. `https://auth.codestra.co/realms/codestra/.well-known/openid-configuration` is reachable.
7. `https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs` is reachable.
8. Browser authorization to each portal no longer returns `Client not found`.
9. The authorization request uses the portal-specific client ID and the matching origin callback.
10. After callback, the MoneyBee API resolves `/api/v2/me` and the selected `X-Organization-ID` without cross-tenant access.

The older `moneybee-portal` entry in the general application-domain inventory is not the MoneyBee production portal-client contract. Do not use it to provision borrower, lender, or admin login. The dedicated JSON contract is authoritative for MoneyBee portal clients.
