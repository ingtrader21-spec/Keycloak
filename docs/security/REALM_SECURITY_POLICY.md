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
WebAuthn requires user verification and binds to `auth.codestra.co`.
Administrators require MFA; phishing-resistant WebAuthn is preferred, recovery
requires a second administrator, and break-glass material stays outside Git.

Git configuration is not live evidence. TOTP enrollment, privileged WebAuthn,
administrator recovery, and required-action behavior must be verified in a
controlled environment before production approval.
