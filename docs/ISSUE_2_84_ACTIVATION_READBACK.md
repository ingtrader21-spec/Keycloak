# Issues #2 and #84: protected activation read-back

This runbook closes the repository-side gap between the existing desired-state and certification contracts and the live/operator evidence still required by issues #2 and #84.

It does **not** authorize production mutation. `config/certification/service-identity-matrix.json` must keep `productionMutationAllowed=false`, and `config/certification/activation-readback.json` must keep `mutationAllowed=false`.

## What the read-back certifies

The manual `Keycloak activation read-back` workflow runs only from protected `main`, on the restricted `keycloak-deploy` self-hosted runner, inside the selected protected GitHub Environment (`staging` or `production`). The operator must provide the exact reviewed protected-main SHA.

The collector then performs only:

1. OIDC discovery `GET` and exact issuer/JWKS URI comparison against the selected canonical endpoint contract.
2. JWKS `GET` and a canonical SHA-256 fingerprint.
3. One OAuth2 client-credentials `POST` for the dedicated read-back identity.
4. Authenticated Keycloak Admin API `GET` calls to resolve `klyrow-portal` and fetch its current representation.
5. Managed-field projection using `config/export-allowlists/klyrow-portal.json`.
6. Exact comparison of that live projection with `config/clients/klyrow-portal.json`, including the reviewed `https://klyrow.com/` redirect.
7. A credential-free JSON evidence artifact containing only hashes, issuer, environment, redirect URI, exact repository SHA, timestamp, and the explicit `mutation_attempted=false` marker.

The collector rejects redirects, non-HTTPS endpoints, ambiguous/missing clients, malformed discovery/JWKS data, environment mismatch, desired/live drift, and HTTP mutation methods.

## Required protected Environment values

Both `staging` and `production` must provide their own values for:

```text
KC_BASE_URL
KC_PUBLIC_URL
KC_TARGET_REALM
KC_ADMIN_REALM
KC_ADMIN_CLIENT_ID
KC_ADMIN_CLIENT_SECRET
```

The first four values must exactly match the selected canonical endpoint contract. The two credentials must belong to the dedicated least-privilege read-back identity; do not reuse a human administrator credential and do not commit either secret.

## Running the evidence workflow

1. Merge this PR through the existing protected checks and independent review.
2. Confirm the `keycloak-deploy` runner is online and scoped to the intended Keycloak host/network.
3. Open **Actions → Keycloak activation read-back → Run workflow** from `main`.
4. Select `staging` first and paste the exact protected-main SHA into `expected_repository_sha`.
5. Preserve the emitted `keycloak-activation-readback-<environment>-<run_id>` artifact with the issue evidence.
6. Repeat for `production` only as a read-only canary after staging passes.

## Evidence boundary

A passing artifact proves the selected issuer/JWKS are reachable and the managed Klyrow client projection matches protected source at the exact reviewed repository SHA. It does **not** prove the full service-token matrix, backup/restore rehearsal, Kong/Middleware configuration digests, browser login completion, SMTP delivery, or any production apply. Those remain separate acceptance gates already required by the existing certification and GitOps runbooks.

No issue should be closed solely because this workflow exists. Close #2/#84 only after their remaining live evidence is attached and independently reviewed.
