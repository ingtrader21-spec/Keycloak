# Keycloak / Klyrow SMTP activation: 2026-09-10

Status: **BLOCKED; password-reset delivery has not been activated.**

## Live evidence

- Keycloak on core server `65.109.65.169` is healthy, but its existing CLI
  administrative session is expired. Live realm SMTP/recovery readback failed.
- Klyrow on `37.27.128.39` exposes its relay at `10.40.0.4:587`.
- STARTTLS is advertised. Certificate verification against the IP fails with
  an identity mismatch. Verification for `mail.klyrow.com` on the same private
  endpoint succeeds: `Verify return code: 0 (ok)`.
- Worker and relay image:
  `sha256:1b0caed0283f03bf3e1f05e8411ca7e28f30ab42c4b854b570471a22671a740b`.
  Reported source: `da9d85891a4e313748e309aed86662d6c03d26bb`.
- SECURITY SMTP code is deployed, but no dedicated SECURITY SMTP credential or
  sender exists. Relay and worker have no SECURITY environment bindings or
  SECURITY payload-key mount. The existing read-only preflight reports
  `KLYROW_SECURITY_SMTP_TENANT_ID is required`.
- The `codestra.co` provider domain is `SENDING_ENABLED`. This alone does not
  verify a SECURITY sender, credential, or payload encryption.
- No live realm settings, credentials, passwords, mail flags, or containers
  were changed. A later user-authorized reset request failed to send; see below.
- Earlier Odoo SMTP test messages used a different general Postal credential;
  they do not certify Keycloak password recovery.

## Source correction

Use `mail.klyrow.com` as the realm SMTP host and TLS certificate identity.
Keycloak's Compose host mapping pins that name to `10.40.0.4`; port 587,
authenticated STARTTLS, and the private route are retained.

Validation rejects missing/private-address drift, public DNS fallback,
bare-IP certificate identity, changed ports, realm endpoint drift, and disabled
STARTTLS or authentication.

Production currently uses
`/opt/codestra/identity-platform/deploy/compose.identity.yaml`. The canonical
Compose has not replaced that runtime. Apply its reviewed host mapping through
the existing protected deployment, then inspect effective Compose and container
resolution before updating the realm.

## Remaining activation steps

1. Reauthenticate an existing authorized Keycloak administrator, or bind the
   approved administration service-account credential through private storage.
   Do not recover credentials from the database, create a replacement superuser,
   or disable MFA.
2. Provision the dedicated Klyrow SECURITY sender and expiring SMTP credential
   through normal administration. Verify domain, tenant, sender and envelope
   policy, and payload encryption; retain unrelated delivery settings.
3. Bind the SECURITY runtime settings and payload key in relay/worker. Run the
   read-only provider preflight in disabled mode.
4. Review and apply the exact Keycloak configuration plan. Do not apply the
   whole canonical realm to the legacy runtime without validating its custom
   providers, browser flows, and registration prerequisites.
5. Follow the one-recipient canary in Klyrow's
   `docs/SECURITY_SMTP_ACTIVATION.md`. Verify Keycloak issuance, Klyrow/Postal
   delivery, controlled inbox receipt, expiry, replay rejection, and forced
   reauthentication before production promotion.

No credentials, reset links, authentication tokens, or message bodies are
included in this evidence.

## Validation

- Full `scripts/validate.sh`: PASS.
- Password-reset transport regression tests: 19 passed (including runtime route
  checks and environment-example consistency).
- Realm-security and password-reset contract validation: PASS.
- `git diff --check`: PASS.

## Release review

PR #108 is unmerged. The bootstrap check rejected the changed validator
source digest. The immutable source/policy proposals are recorded below for
independent review; `pr108-ca901237.json` is retained as historical evidence. The active trust
manifest and release checks remain unchanged. Follow the proposal-directory
README for separate protected-main policy maintenance before release.

## Approval follow-up and reset request

An independent GitHub approval was recorded on source head
`ce4ae5aa1cd4ab4acd9a41b70d7e1749143cd721`. Subsequent corrections address both
review findings: runtime transport verification before apply and the stale
SMTP environment example. These changes require a fresh exact-head review and
a new immutable digest proposal; the old source proposal is historical only.

At 2026-09-10 02:11:47 UTC, one user-requested password-reset attempt through
the Codestra account login produced Keycloak event `KC-SERVICES0026`:
`EmailException: Invalid sender address 'null'`. The login page displayed its
generic confirmation, but server-side delivery failed. The missing sender is
now confirmed in the live recovery path. No reset email was delivered by this
attempt, and no account password was changed. The requested mailbox and all
reset/session links are intentionally omitted from this repository record.

The existing administrative CLI session remains expired. The secure browser
sign-in request was declined. Live realm changes still require normal
authentication by an existing authorized administrator.

The revised source is `4b0d97686cd794d3486720bdb4eb5c39384db195`. Its
immutable proposed digest set is `config/bootstrap/proposals/pr108-4b0d976.json`.
This replaces the earlier proposal for release review only. The active trust
manifest and the production mutation stop flag remain unchanged.

## Bootstrap digest correction after source approval

The user requested correction of failed bootstrap run `34429780319`.
Independent collaborator `kazan555` approved source commit
`ea9f918a4397993a860df54233b5a7a42ddb7a55` on 2026-09-10 after the Odoo
SSO changes from main `52c9f4c8069d2fa827b66f0f8a49ef864cbca9a0` were merged.

The branch manifest is now refreshed for exactly two independently reviewed
source files: `scripts/validate-password-reset-contract.py` and
`scripts/validate.sh`. The other eight file bindings are unchanged. The
canonical manifest digest is
`85b54d37c17f16f24d8730e1a2bc9d6a0a5155ac4f03581c1756cc950d738adb`.
The earlier immutable proposals remain historical records and do not match
the combined SMTP/Odoo validator.

The local source-hash check and all 17 existing bootstrap/manifest tests pass.
This corrects source consistency only: it does not establish independent
protected-main release authority, replace fresh exact-head approval/CI, or
activate production. The revised commit requires fresh review under GitHub's
stale-approval protection. No workflow, required check, review rule, or
production mutation flag is changed by this correction.

The earlier full local plan-gate run exceeded its 550-second execution limit;
it is not a passing certification result. The isolated missing-route rejection
and 19 SMTP regression tests passed. CI on the final merged source remains the
authority for the complete plan-gate test.
