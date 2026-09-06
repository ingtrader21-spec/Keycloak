# MoneyBee SECURITY sender policy

## Canonical identity-mail domain

MoneyBee security email must use the canonical MoneyBee domain:

- Canonical application domain: `moneybeeloan.com`
- Preferred SECURITY sender: `security@moneybeeloan.com`
- Preferred display name: `MoneyBee Security`
- Preferred envelope sender: `security@moneybeeloan.com`
- Required Klyrow stream: `SECURITY`

Operator evidence supplied on 2026-08-27 reports `moneybeeloan.com` as Klyrow/Postal verified and sending-enabled. Runtime activation must still re-verify the sender identity and dedicated SMTP credential before production use.

## Eligible MoneyBee clients

The policy applies only to MoneyBee human clients:

- `moneybee-borrower`
- `moneybee-lender`
- `moneybee-admin`

Public self-registration remains borrower-only. Lender and administrator accounts are not public-registration clients.

## Shared-realm constraint

The `codestra` realm is shared by multiple applications. Do not globally change the realm `KC_SMTP_FROM` to a MoneyBee address unless all shared-realm applications are intentionally migrated to that sender.

MoneyBee-branded security mail therefore requires a reviewed client-aware sender policy in the MoneyBee OTP/identity-mail path or another application-scoped mechanism. Until that mechanism is activated and verified, the shared realm SMTP sender remains application-neutral.

## Legacy domain

`moneybee.loan` may be a verified sending domain, but it is a legacy MoneyBee identity alias and must not be used for MoneyBee authentication, registration, recovery, or verification mail.

- Canonical domain: `moneybeeloan.com`
- Legacy domain: `moneybee.loan`
- Legacy identity-mail use: `DISALLOWED`

## Security boundary

Passwords, OTP values, reset tokens, reset URLs, SMTP credentials, access tokens, and refresh tokens must not be sent to MoneyBee Backend, Kong, Middleware, Odoo, n8n, Mautic, analytics, or audit payloads.

Klyrow transports the SECURITY message and Postal performs outbound delivery. Middleware/Odoo/n8n remain outside the synchronous identity-verification path.

## Production gate

Before activation, require all of the following:

1. `moneybeeloan.com` remains verified and sending-enabled in Klyrow/Postal.
2. `security@moneybeeloan.com` (or an explicitly reviewed replacement on the same canonical domain) is an approved sender identity.
3. The Keycloak SMTP credential is dedicated to identity SECURITY mail and sender-restricted.
4. STARTTLS and SMTP authentication pass on the private Klyrow endpoint.
5. Klyrow SECURITY encrypted-payload retention controls are deployed and verified.
6. Registration and password-recovery staging mail is accepted by Postal and received in a controlled inbox.
7. No shared-realm application receives an unintended MoneyBee From address.
8. No live activation occurs from a feature branch; use the protected exact-merged-SHA check/plan/apply process.
