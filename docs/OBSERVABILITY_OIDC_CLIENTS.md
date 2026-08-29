# Observability OIDC clients and roles

This source defines three separate Keycloak browser clients:

- `grafana` for `https://graf.codestra.media`;
- `superset` for `https://supe.codestra.media`;
- `openbao` for the restricted `https://bao.codestra.media` ingress.

Every client uses Authorization Code Flow with PKCE S256. Implicit, direct
password, device, service-account and CIBA grants are disabled. Each client is
confidential because the application backend exchanges the authorization code;
Keycloak generates a distinct credential at reviewed apply time and the value
must be injected from the approved external secret store. No credential is
stored in this repository.

## Role boundary

Grafana and Superset accept only `observability-viewer`,
`observability-operator`, or `observability-admin`. OpenBao accepts only
`secrets-operator` or `secrets-admin`. Observability roles are explicitly not
OpenBao access. There are no default assignments or automatic cross-client
role grants.

Administrative Grafana/Superset access requires MFA. All OpenBao operator and
administrator access requires MFA in addition to OpenBao's own policy checks
and the Caddy operator/VPN allowlist. A Keycloak login does not replace
OpenBao authorization.

The exact redirect URI allowlists and session limits are machine-checked by
`scripts/validate-observability-oidc-contract.py`.

## Activation gate

This branch is desired state only. It does not apply clients or roles to the
live realm. Before activation:

1. review and merge the client/role contract through protected `main`;
2. ensure the realm MFA policy and role-aware provisioning path are separately
   reviewed and active;
3. generate and independently review the deterministic drift plan;
4. apply the exact reviewed SHA through the protected Keycloak environment;
5. inject three distinct credentials into their owning applications;
6. verify exact redirects, role denial, MFA, logout and session expiry;
7. record rollback exports without credential values.

Until those gates pass, the Caddy observability routes must not be installed.
