# MCR-H identity contract and readback

MCR-H adds an offline, prepared-disabled profile of the existing Middleware V3
`platform-command-client` family. It creates no realm, client, mapper, grant,
credential or deployed authorization. The contract is
`contracts/mcr-identity-v1.json`; its `liveBindings` is deliberately empty.
Concrete MCR client IDs and tenant assignments have not been provided or
certified. Unresolved clients remain denied. `test-syn-mcr-*` identities appear
only in synthetic certification fixtures and must never become live grants.

## V3 authority and decisions

The profile pins the existing caller classification and API access V3 source
files by SHA-256. It reuses realm `codestra`, audience `middleware-api`,
`platform-command-client` and its `platform-command-family` alias. A family name
is not an AZP. Each AZP must resolve to exactly one enabled, reviewed binding for
the selected environment and tenant. Protected desktop clients stay denied.
There is no new MCR realm, audience or scope vocabulary.

| Operation | Scope | Actor | Additional boundary |
| --- | --- | --- | --- |
| read | `platform.command.read` | human or service | reviewed member and tenant |
| command | `platform.command` | human or service | reviewed member and tenant |
| replay | `platform.command.replay` | human only | `platform-operator` realm role, MFA, independent approval, atomic replay reservation, target tenant match |

This is a command-kernel profile, not permission for every Middleware route.
Consumers must resolve routes/command prefixes against V3 before choosing the
operation. Unknown operations deny. Request input cannot select or weaken the
route's required operation, actor, role or scope.

Staging accepts only `https://auth-staging.codestra.co/realms/codestra`;
production accepts only `https://auth.codestra.co/realms/codestra`. Environment
selection is deployment configuration, never inferred from an untrusted token.
The MCR profile requires exactly the Middleware audience (string or singleton
array), a verified RS256 signature, access-token `typ=Bearer`, nonempty subject,
AZP, JTI and tenant, integer `iat`/`nbf`/`exp`, a maximum 300-second lifetime,
no future issue/not-before time, and no expired tokens. It allows zero clock skew.
Scopes must be explicitly permitted by both the profile and the member binding;
realm roles cannot exceed the reviewed binding. Neither wildcard authority nor
privileged default scopes are allowed.

All human command-kernel actions in this profile use Authorization Code with
PKCE S256 and MFA (`amr` contains `mfa`) authenticated within 300 seconds. Grant
and PKCE proof come from reviewed client/session evidence, not invented JWT
claims. Service accounts use confidential `client_credentials`, no refresh
tokens, browser flow, implicit flow, password grant or full scope. Their `sub`
must match the exported Keycloak service-account user UUID, not a username
prefix. Services cannot receive human roles or replay permission.

Tenant binding uses a dedicated reviewed per-tenant member. Trusted resource
lookup must supply the expected tenant; headers alone never authorize. This
version deliberately denies static tenant binding for shared `kong-gateway` and
`n8n-automation`. A future token-exchange or authenticated tenant-context design
requires separate review; this profile does not implement it.

Business-operation replay is distinct from ordinary bearer-token reuse. Read
and command access tokens are not globally single-use. For a replay request the
consumer must first validate all identity and target-tenant boundaries, then
atomically reserve `(issuer, tenant, subject, jti, operation_id)` in a shared
store until token expiry. A duplicate reservation or unavailable store denies.
Independent approval must be bound to the same operation, tenant and requester.
The offline evaluator tests the outcomes of those external checks; it does not
implement a replay store, approval system, JWT cryptography or middleware.

## Local verification

```sh
make mcr-identity-check
python3 -O scripts/validate_mcr_identity.py
python3 -m pytest -q
make validate
```

The focused command reports `MCR_IDENTITY_CONTRACT=PASS`, three synthetic positive
cases, 50 negative cases and `KEYCLOAK_LIVE_APPLY=PROHIBITED`. `make validate`
runs the validator and focused tests before the existing repository validation.
The protected CI entrypoint and release trust-root closure are unchanged. The negative matrix covers
issuer/audience/AZP, family and tenant mismatch, scope and role leakage,
time/type/signature boundaries, grant confusion, PKCE/MFA freshness, service
subject binding, protected clients, replay/approval failures and client policy.
Unit tests also remove every required claim, corrupt input types and policy
values, and check optimized Python and duplicate-key JSON rejection.

Policy and matrix canonical JSON digests are pinned in the validator. Changes
require reviewing both the authority and its certification matrix before
updating these pins; do not automatically regenerate pins during validation.
V3 source drift fails certification until explicitly reviewed. The existing V3
caller check currently reports `TARGET_ROUTE_CONTRACT_MATCH=PENDING_BASE_INTEGRATION`
for its local 92-route source; final integration still requires the pinned
117-route source and `--require-target-contract` as described in
[V3 caller certification](V3_CALLER_IDENTITY_CERTIFICATION.md). MCR source
certification does not resolve or override that outstanding parity gate.

## Readback procedure for a separately authorized activation

No live readback has been performed by this implementation. Before activation,
the integration owner must provide a reviewed concrete client/tenant registry.
Readback is evidence gathering, not permission to apply this contract.

1. Record the exact Git SHA, contract digest, V3 source digests, environment,
   timestamp and reviewer. Run the local checks above against that checkout.
2. Through an already approved read-only Keycloak export process, capture each
   candidate client's ID, enabled status, public/confidential setting, flows,
   service-account setting, full-scope flag, default/optional scopes, audience
   mapper and token lifetime. For humans, include exact redirects, PKCE S256
   and the MFA authentication-flow mapping. Export only allowlisted fields.
3. For each service, resolve its service-account user UUID and effective realm
   and client roles, including composites. Confirm no human/administrative
   roles, refresh grant, secret in Git or privileged default scope. Confirm the
   authoritative tenant/client assignment and revocation owner. Do not attach a
   fixed tenant mapper to a shared client.
4. Check discovery/JWKS against the selected environment's pinned issuer using
   the approved verifier. Verify signatures before trusting claims. Exercise
   valid tokens and the negative matrix against the actual consumer, including
   tampering, wrong key/algorithm, ID tokens, issuer substitution, family
   substitution, cross-tenant targets and stale MFA. Synthetic Boolean
   `signatureVerified` or `reviewed` fields are never runtime proof.
5. Exercise replay twice with the same reservation key; the second must deny.
   Exercise concurrent replay, unavailable replay storage, missing independent
   approval and approval for a different target. Confirm no business/provider
   effect occurs on rejection. A valid synthetic matrix cannot prove this.
6. Record only redacted claim summaries and verdicts, client policy differences,
   and evidence references. Never store bearer tokens, client secrets, private
   keys or personal subject data in this repository. Any missing evidence,
   mismatch, unresolved membership or unavailable dependency blocks activation.

A passing source check does not assert live readback parity or authorize deploy,
merge, provisioning, token minting or changes to the live realm.
