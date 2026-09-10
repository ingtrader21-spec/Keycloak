# n8n editor gateway login

The `n8n-editor-gateway` client now uses the editor hostnames already declared by N8N and running on the core server:

| Environment | Editor | Exact callback |
| --- | --- | --- |
| Production | `https://n8n.codestra.agency` | `https://n8n.codestra.agency/oauth2/callback` |
| Staging | `https://n8n-staging.codestra.agency` | `https://n8n-staging.codestra.agency/oauth2/callback` |

Root/base URLs, browser origins and post-logout redirects follow those hosts. No wildcard callback is added. The identity issuer remains `https://auth.codestra.co/realms/codestra`.

The client-scoped `login_theme=codestra` attribute selects the existing `themes/codestra/login` theme. Its export allowlist and exact client validation permit that attribute only for this client. The realm default remains `codestra-identity`, which inherits the same shared `codestra` visual base after the black/gold theme change. The normal Keycloak image build includes both themes.

Before a self-hosted deployment plan or apply can proceed, `scripts/validate-runtime-security.py` now inspects the exact running Keycloak container selected through the canonical runtime Compose/service variables and requires both `/opt/keycloak/themes/codestra/login/theme.properties` and `/opt/keycloak/themes/codestra-identity/login/theme.properties`. A stale image that predates either required theme fails closed before configuration is applied.

The client remains confidential with authorization-code flow and PKCE S256. Password, implicit and service-account grants remain disabled; full scope remains disabled. The companion Caddy gateway requires `n8n_operator` or `n8n_admin`, then forwards authorized requests to n8n's native login. The companion N8N assets provide the initial Continue with Codestra page without collecting credentials.

Run `make validate` to check the exact client contract, export allowlist, theme and existing repository policy. That source result does not certify a live token exchange.

Read-only inspection on 2026-09-10 found the client absent from the live realm and the realm login-theme field unset. Production mutation remains disabled in `config/certification/service-identity-matrix.json`. Complete the normal independently reviewed certification and release process before runtime apply. Gateway client/cookie credentials belong in the prescribed root-owned secret files, never in these client JSON files.
