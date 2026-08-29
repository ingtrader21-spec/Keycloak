# Observability and Secrets OIDC Contract

## Purpose

This branch defines the reviewed identity contract for Grafana, Superset, and OpenBao under `codestra.media`. It does not create live clients or generate secrets.

Canonical issuer:

```text
https://auth.codestra.co/realms/codestra
```

## Clients

| Client ID | Application | Redirect URI |
|---|---|---|
| `grafana-observability` | `https://graf.codestra.media` | `https://graf.codestra.media/login/generic_oauth` |
| `superset-analytics` | `https://supe.codestra.media` | `https://supe.codestra.media/oauth-authorized/keycloak` |
| `openbao-secrets` | `https://bao.codestra.media` | `https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback` plus the approved local CLI callback |

All three use:

- Authorization Code Flow;
- PKCE `S256`;
- confidential clients with externally injected secrets;
- no implicit flow;
- no password/direct grant;
- no service account;
- exact HTTPS redirect and origin allowlists.

## Roles

Observability applications use:

```text
observability-viewer
observability-operator
observability-admin
```

OpenBao uses separate roles:

```text
secrets-operator
secrets-admin
```

The role families are intentionally independent. Observability access must never imply secrets access. Administrative role assignment requires MFA and separate approval.

## Application mappings

### Grafana

Configure Generic OAuth against the canonical issuer. Enable PKCE, require a valid role claim, and deny login when no approved Grafana role can be mapped. Store the client secret outside Git.

### Superset

Configure the Keycloak OAuth provider with the exact callback path in the contract. Map approved Keycloak roles into least-privilege Superset roles. Superset data-source credentials stay external and read-only where practical.

### OpenBao

Configure the OpenBao OIDC auth method with the exact UI and local CLI callbacks. Keycloak authentication does not replace OpenBao policies: users must still receive explicit OpenBao policy mappings. Caddy also enforces the approved source-network boundary.

## Protected apply limitation

The current Keycloak GitOps plan validates and applies the existing managed client set exactly. These three new browser clients are therefore held in `config/contracts/observability-browser-clients.json` until a separately reviewed change extends:

- managed/creatable-client policy;
- export allowlists;
- deterministic plan/apply support;
- rollback export coverage;
- exact-source validation.

Do not create the clients manually merely to bypass that control. The next identity change must promote this accepted contract into the protected managed-client engine.

## Validation

Run:

```bash
python3 scripts/validate-observability-oidc-contract.py
```

The validation confirms exact hostnames, redirect URIs, PKCE, disabled unsafe grants, external secret ownership, role separation, and no live activation flags.

## Activation gate

Before enabling access:

1. extend the protected apply engine for these clients;
2. pass exact-head and merge-result CI;
3. independently review the drift/create plan;
4. create secrets through the approved secret path;
5. configure each application without committing secrets;
6. verify login, logout, role denial, MFA, session revocation, and cross-role isolation;
7. record exact Keycloak, Caddy, and application repository SHAs;
8. obtain explicit production approval.
