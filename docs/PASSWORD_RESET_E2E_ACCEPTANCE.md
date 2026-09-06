# Password-recovery staging acceptance

This package converts the password-reset activation checklist into one
credential-free evidence run. It is deliberately separate from the Keycloak
SMTP desired-state pull request so that an approved identity/configuration SHA
is not changed by test-harness work.

## Scope

The protected workflow proves all eleven acceptance gates:

1. A disposable user reaches **Forgot Password** through the real Codestra
   Keycloak browser flow.
2. Keycloak creates a real expiring reset action.
3. Keycloak authenticates to the dedicated Klyrow `SECURITY` SMTP path.
4. Klyrow persists the message as `stream=SECURITY` and `sandbox=false`.
5. Postal returns a provider message identity and a `SENT` or `DELIVERED`
   state.
6. A controlled inbox receives the same Message-ID through Postal.
7. The action link changes the password exactly once.
8. Reuse of the same action link is rejected.
9. A separately generated 60-second `UPDATE_PASSWORD` action is rejected after
   expiration.
10. A browser session created before the reset no longer satisfies
    `prompt=none`; the user must authenticate again.
11. Middleware's sanitized audit view contains no password, reset token, full
    reset URL, action token, SMTP credential, or `kc_action` material.

The disposable user is deleted in a `finally` block. Generated passwords,
access tokens, reset URLs, mailbox credentials, database credentials, and
middleware credentials are masked and excluded from the evidence artifact.

## Workflow

```text
.github/workflows/password-reset-staging-e2e.yml
```

It is intentionally constrained to:

```text
TRIGGER=workflow_dispatch only
BRANCH=refs/heads/main only
RUNNER=self-hosted,linux,x64,codestra-staging
ENVIRONMENT=password-reset-staging
CONFIRMATION=ACTIVATE_STAGING_TEST
MAX_RUNTIME=25 minutes
```

It cannot run from a pull request, push, schedule, arbitrary branch, or
production environment. The workflow sends exactly the two security messages
needed to prove first-use/replay and expiration behavior. It does not dispatch
marketing, SMS, CRM, Odoo, n8n, dialing, or general external-delivery work.

## Protected variables

Configure these as environment variables in the protected
`password-reset-staging` GitHub Environment:

```text
KEYCLOAK_VERSION_URL
KLYROW_VERSION_URL
E2E_IMAP_PORT
E2E_IMAP_MAILBOX
E2E_IMAP_STARTTLS
E2E_POSTAL_RECEIVED_MARKER
KLYROW_E2E_MESSAGE_TABLE
MIDDLEWARE_E2E_AUDIT_URL
```

The version endpoints must return the exact deployed Git SHA in a JSON field
named `sha`, `git_sha`, `commit`, `commit_sha`, `revision`, or `source_sha`.
The workflow rejects a runtime that does not match both reviewed SHAs supplied
at dispatch time.

## Protected secrets

Store these only in the same protected environment:

```text
KEYCLOAK_E2E_ADMIN_CLIENT_ID
KEYCLOAK_E2E_ADMIN_CLIENT_SECRET
E2E_RECIPIENT_TEMPLATE
E2E_IMAP_HOST
E2E_IMAP_USERNAME
E2E_IMAP_PASSWORD
KLYROW_E2E_DATABASE_URL
MIDDLEWARE_E2E_AUDIT_TOKEN
```

`E2E_RECIPIENT_TEMPLATE` must contain `{run_id}` exactly once, for example a
controlled plus-addressing route. Do not commit the actual address.

The Keycloak service account must be separately reviewed and restricted to a
dedicated E2E user scope. It needs only the ability to create/delete disposable
users and issue `UPDATE_PASSWORD` action emails in `realm=codestra`. It must not
receive `realm-admin`, `manage-realm`, unrestricted `manage-users`, or client
administration.

`KLYROW_E2E_DATABASE_URL` must be a read-only account restricted to the Klyrow
message-evidence table. It must not be able to update, delete, enqueue, retry,
or replay messages.

## Middleware audit contract

`MIDDLEWARE_E2E_AUDIT_URL` is a protected, read-only runtime binding. The
workflow sends these query parameters:

```text
identity_subject=<disposable Keycloak user id>
since=<UTC timestamp>
event_family=identity.password
```

The endpoint must return either a JSON array or:

```json
{
  "events": []
}
```

The response may contain privacy-safe identifiers, event type, outcome,
correlation ID, provider message ID hash, and timestamps. It must never contain
passwords, temporary passwords, reset tokens, action tokens, full reset URLs,
SMTP credentials, `kc_action`, or an action-token path.

An empty event array is valid because the password-recovery data plane is
Keycloak → Klyrow/Postal, not Middleware. Any sanitized lifecycle event must
remain credential-free.

## Klyrow evidence contract

The workflow queries the configured read-only Klyrow table for the controlled
recipient and Message-ID. A passing row must have:

```text
stream=SECURITY
sandbox=false
status=SENT or DELIVERED
provider_message_id=present
```

Only hashes of the Klyrow record and provider message identity are written to
the artifact.

## Evidence

The workflow uploads:

```text
evidence/password-reset-e2e.json
```

The artifact has mode `0600`, a 14-day retention period, and contains no reset
URL, token, password, SMTP secret, mailbox secret, database URL, or middleware
token. A successful report must contain all eleven named gates with `PASS` and
both exact reviewed runtime SHAs.

## Activation order

1. Merge the secure Keycloak GitOps foundation.
2. Merge the service identity/API/webhook contracts.
3. Merge the approved fifteen-domain and SMTP password-reset desired state.
4. Merge and deploy the approved Klyrow `SECURITY` SMTP implementation with
   both live gates still disabled.
5. Rotate every Postal DKIM key previously exposed in diagnostics and publish
   the new DNS records.
6. Verify the private STARTTLS path and create a dedicated `SECURITY` sender and
   SMTP credential outside Git.
7. Apply the reviewed Keycloak SMTP plan in staging.
8. Enable only the staging `SECURITY` gates for the controlled test tenant.
9. Dispatch this workflow with the exact deployed Keycloak and Klyrow SHAs.
10. Review the credential-free evidence and immediately disable the staging
    live gate after the canary.
11. Prepare a separate production plan and approval; never reuse the staging
    credential or evidence hash.
