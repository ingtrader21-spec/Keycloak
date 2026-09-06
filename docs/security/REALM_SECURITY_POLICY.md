# Codestra realm security policy

`config/realms/codestra.json` is a managed Keycloak realm overlay. It is read
during check, projected against the live realm, included in the deterministic
plan with pre/desired hashes, revalidated immediately before its own `PUT`, and
verified by the post-apply convergence plan.

The policy disables self-registration, remember-me, duplicate emails, and
username editing. Email verification and centralized password recovery remain
enabled. Passwords require 14–128 characters, upper/lower/digit/special
categories, username and email rejection, twelve-entry history, and 600,000
hash iterations. A reviewed common-password provider is still required and is
an explicit blocker in `config/security/realm-security-policy.json`.

Brute-force protection locks progressively after five failures, with a
one-minute increment and fifteen-minute maximum wait. Permanent lockout is
disabled so recovery remains possible.

TOTP uses SHA-256, six digits, a 30-second period, and a one-step look-ahead.
WebAuthn requires user verification and uses the `codestra.co` RP ID, valid for
both production and staging authentication subdomains. The managed browser flow
requires password plus TOTP, so password-only administrator login is rejected.
Phishing-resistant WebAuthn is preferred, recovery
requires a second administrator, and break-glass material stays outside Git.

Git configuration is not live evidence. TOTP enrollment, privileged WebAuthn,
administrator recovery, and required-action behavior must be verified in a
controlled environment before production approval.

`KC_SMTP_CREDENTIAL_VERSION` is a non-secret deployment variable. Incrementing
it creates reviewed realm drift and schedules an update even when only the
external SMTP credentials changed; the credentials remain absent from Git and
the plan.
