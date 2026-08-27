# Beyvra OIDC client

Beyvra uses the canonical Codestra realm at
`https://auth.codestra.co/realms/codestra`. The browser client ID is
`beyvra-web-production`, with Authorization Code Flow and PKCE S256 only.

The reviewed contract is intentionally disabled and is not in the protected
managed-client apply set. Runtime verification and a reviewed plan hash are
required before creating or enabling it.

## Exact browser contract

- Redirect: `https://beyvra.com/api/v1/auth/oidc/callback/`
- Post logout: `https://beyvra.com/signIn?logged_out=1`
- Origin: `https://beyvra.com`
- No wildcard redirects or origins
- No implicit, password, device, CIBA, or client-credentials grant
- Roles: `beyvra-user`, `beyvra-admin`, `beyvra-super-admin`

The callback belongs to Beyvra's backend-for-frontend boundary. Keycloak
tokens must not be returned to, logged by, or stored in browser JavaScript.
Local accounts bind on the exact issuer and immutable Keycloak subject.

## Registration and recovery

Keycloak owns registration, verified email, passwords, administrator MFA, and
password recovery. Terms acceptance must be part of the reviewed registration
flow before activation. Beyvra's local password and email-OTP registration
routes must be disabled at cutover.

Password-reset messages use the realm's private Klyrow SECURITY SMTP contract.
Reset lookup, token creation, and password consumption stay inside Keycloak;
they do not pass through Middleware, Odoo, n8n, or the Beyvra API.

## Activation evidence

Before enablement, attach runtime evidence for the exact client export,
redirect and origin probes, same-origin `/api` proxy, Klyrow STARTTLS plus
authentication, a real reset-send/consume smoke test, rollback steps, and the
reviewed apply-plan hash. Source configuration alone is not proof that the
runtime client or mail route exists.
