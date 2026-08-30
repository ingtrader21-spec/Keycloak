# Observability managed identities and realm roles

## Authority

This repository is the Git authority for the reviewed Keycloak desired state used by:

- `grafana-observability` at `https://graf.codestra.media`
- `superset-analytics` at `https://supe.codestra.media`
- `openbao-secrets` at `https://bao.codestra.media`

The source in this branch implements issue #30. It does **not** apply anything to a live Keycloak realm.

## Protected resources

### Confidential browser clients

All three clients use Authorization Code Flow with PKCE S256. Implicit flow, password/direct grants, and service accounts are disabled. Redirect URIs and origins are exact; wildcards are prohibited. Client secrets are generated or retrieved only through a protected external handoff and never appear in Git, plans, reviews, rollback artifacts, CI output, or pull-request evidence.

### Realm roles

The protected role set is:

```text
observability-viewer
observability-operator
observability-admin
secrets-operator
secrets-admin
```

Observability roles and secrets roles are separate families. No composite or cross-family grant is created. Role assignment is outside the repository apply operation and requires independent approval. Operator/admin roles carry an MFA-required policy attribute; production access remains blocked until the live authentication policy proves that requirement.

## Single plan/review/apply boundary

`scripts/protected_identity_engine.py` governs both clients and realm roles.

```text
desired files + managed/creatable policies
              ↓
exact live read-back
              ↓
canonical before/desired hashes
              ↓
plan.json + plan SHA-256
              ↓
independent review.json + review SHA-256
              ↓
pre-write drift and create-race recheck
              ↓
role mutations first, then client mutations
              ↓
read-back convergence plan
```

A missing resource can be created only when it appears in the matching creatable policy. A missing non-creatable resource becomes `blocked_missing`. No direct unplanned mutation mode exists.

## Rollback model

Existing clients and roles use an allowlisted before-state overlay and require a separately reviewed restore plan.

New clients use:

```text
disable → verify no active use → separately reviewed delete
```

New realm roles use:

```text
remove all user/group/client assignments → verify zero mappings → separately reviewed delete
```

Keycloak has no native disabled realm-role state, so role rollback must remove mappings before deletion rather than pretending an attribute disables authorization.

## Client-secret handoff

`scripts/export-generated-client-secrets.sh` supports the protected post-create handoff. It:

- accepts only client IDs in `config/policy/secret-export-clients.json`;
- refuses destinations inside the repository;
- writes one root-only `0600` file per client;
- writes a manifest containing filenames but no secret values;
- never prints a secret value.

The handoff destination must be an approved external secret store or protected runtime path. It must never be uploaded as a GitHub Actions artifact.

## Validation

The exact-source and merge-result gates validate:

- exact client IDs, callbacks, origins, PKCE, and grant restrictions;
- exact managed/creatable policies;
- five realm roles and role-family isolation;
- realm-role token mapper behavior;
- plan create/update/no-op/blocked states;
- exact plan and independent review hashes;
- optimistic before-state and pre-write create-race checks;
- rollback evidence for clients and roles;
- secret redaction and protected handoff file permissions;
- convergence after a mock apply;
- no live apply.

## Activation state

```text
CONTRACT_REVIEWED=YES
MANAGED_CLIENT_SUPPORT=YES
MANAGED_REALM_ROLE_SUPPORT=YES
PLAN_REVIEW_APPLY_SUPPORT=YES
ROLLBACK_SUPPORT=YES
LIVE_KEYCLOAK_APPLY=NO
LIVE_CLIENTS_CREATED=NO
LIVE_ROLES_CREATED=NO
LIVE_SECRETS_EXPORTED=NO
PRODUCTION_ACCESS_ENABLED=NO
```
