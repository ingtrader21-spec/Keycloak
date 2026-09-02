# Observability Keycloak desired state

## Scope and authority

This repository contains repository-only, validate-only desired state for:

- `grafana-observability` at `https://graf.codestra.media`;
- `superset-analytics` at `https://supe.codestra.media`;
- `openbao-secrets` at the restricted `https://bao.codestra.media` boundary;
- `observability-viewer`, `observability-operator`, and `observability-admin`;
- `secrets-operator` and `secrets-admin`.

The desired resources live under `config/desired-state/observability/`. They are deliberately outside `config/clients/` and the managed/creatable policies used by the live-capable reconciliation scripts. Repository CI fails if an observability client is added to those policies. This separation prevents a normal client reconciliation from applying a partially approved observability identity change.

## Security contract

All browser clients are confidential Authorization Code clients with PKCE S256. Implicit flow, Resource Owner Password Credentials, service accounts, full scope, wildcard redirects, and wildcard origins are disabled. Access tokens are limited to five minutes; client sessions are bounded per application.

Client secret values are never represented in Git. The source contract identifies OpenBao as the authority and an application-specific runtime secret-file destination. Generating and transferring those values belongs to a later authorized server mission.

Realm roles are non-composite and split into observability and secrets families. Cross-family grants are prohibited. Operator and administrator roles require MFA; role assignment requires independent approval and must not be derived from an email address.

## Deterministic plan

Generate and verify the source-only plan with:

```bash
python3 scripts/observability_desired_state.py --write
python3 scripts/observability_desired_state.py --check
python3 -m unittest discover -s tests -p 'test_observability_desired_state.py' -v
```

The committed plan and checksum are:

- `release/observability/keycloak-observability-desired-state-plan.json`
- `release/observability/keycloak-observability-desired-state-plan.sha256`

The plan records desired-resource hashes and repository activation preconditions. It does not contain live state, credentials, or an authorization to apply.

## Later apply gate

The later live mission must create a fresh plan from exact protected source and live before-state, obtain independent approval, capture a rollback bundle, authorize the secret handoff, and only then apply. This repository mission does not call the Keycloak Admin API.

## Rollback

Existing resources require a separately reviewed restoration plan built from validated before-state. A newly created client must be disabled, proven unused, and separately approved before deletion. A newly created realm role must have every user, group, and client mapping removed and verified before separately approved deletion.

Rollback evidence must include the protected merge SHA, desired-state checksum, live before-state hash, reviewed plan hash, post-apply read-back hash, and approver identity. Until those values exist, the repository state is `SOURCE_PREPARED_NOT_DEPLOYED` and must not be described as production-ready.
