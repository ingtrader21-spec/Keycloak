# Keycloak security email through Klyrow and Postal

## Authority boundary

The `codestra` realm at `https://auth.codestra.co/realms/codestra` is the only
password, login-email verification, MFA, recovery-token and browser-session
authority for Codestra-managed human users.

```text
Application login / registration UI
  -> Codestra Keycloak
  -> private authenticated STARTTLS SMTP
  -> Klyrow SECURITY relay
  -> Postal delivery
  -> user inbox
```

Application APIs, Kong, Codestra Middleware, Odoo, n8n, Mautic and machine
clients must never receive a password, verification code, verification-code
hash, reset token, complete reset URL, SMTP password or Keycloak administrator
credential. They may record only privacy-safe operational evidence such as a
provider message ID, delivery outcome, correlation ID and timestamp.

## MoneyBee identity mapping

The canonical MoneyBee root domain is `moneybeeloan.com`.

| Application | Client | Origin |
|---|---|---|
| Borrower | `moneybee-borrower` | `https://app.moneybeeloan.com` |
| Lender | `moneybee-lender` | `https://lenders.moneybeeloan.com` |
| Administrator | `moneybee-admin` | `https://admin.moneybeeloan.com` |

`moneybee.loan` is a disabled legacy alias. It must not be used for runtime
login, registration, password recovery, redirect URIs or web origins.
`moneybee-portal` is obsolete and must not be reintroduced.

All three browser clients use Authorization Code Flow with PKCE `S256`.
Public self-registration is permitted only when the initiating client is
`moneybee-borrower`. Lender and administrator accounts remain invitation /
privileged-provisioning flows.

## MoneyBee email verification code

MoneyBee borrower registration uses the Keycloak required action
`moneybee-verify-email-otp` after the standard Keycloak registration form.
Keycloak remains the credential authority; the MoneyBee frontend never receives
or submits a password to the MoneyBee API.

The verification contract is:

```text
CODE_LENGTH=6 numeric digits
TTL=600 seconds
MAX_ATTEMPTS=5
RESEND_COOLDOWN=60 seconds
MAX_SENDS_PER_HOUR=5
ONE_TIME_USE=true
INVALIDATE_PREVIOUS_ON_RESEND=true
PLAINTEXT_CODE_PERSISTENCE=false
```

Only an HMAC verifier is stored in the Keycloak authentication session. The
runtime HMAC secret is supplied outside Git through
`MONEYBEE_EMAIL_OTP_HMAC_KEY` and must be a long random secret.

The Keycloak email theme provides HTML and plain-text messages and does not use
Mautic, tracking pixels or marketing content.

## Klyrow SMTP contract

The reviewed private endpoint contract is:

```text
SMTP_HOST=10.40.0.4
SMTP_PORT=587
ENCRYPTION=STARTTLS
AUTHENTICATION=REQUIRED
STREAM=SECURITY
```

The Klyrow credential must be dedicated to Keycloak, restricted to exactly the
`SECURITY` stream and one reviewed verified sender. The live endpoint,
firewall path, certificate, sender domain/identity and credential must be
verified before activation.

The Git repository stores only variable and secret names. Configure these in a
protected GitHub Environment or approved runtime secret provider:

```text
KC_SMTP_HOST
KC_SMTP_PORT
KC_SMTP_USERNAME
KC_SMTP_PASSWORD
KC_SMTP_FROM
KC_SMTP_FROM_DISPLAY_NAME
KC_SMTP_REPLY_TO
KC_SMTP_ENVELOPE_FROM
MONEYBEE_EMAIL_OTP_HMAC_KEY
```

Never commit their live values.

## Password recovery

Password recovery remains Keycloak-only and uses the same Klyrow SECURITY
transport. The protected configuration must preserve:

```text
Forgot password = enabled
Update Password required action = enabled
Force login after reset = enabled
Reset-token lifespan = 900 seconds
SMTP authentication = enabled
STARTTLS = enabled
```

Account lookup responses must remain generic so the recovery UI does not reveal
whether an account exists.

## Runtime activation sequence

1. Review and merge the Keycloak registration/OTP extension and themes.
2. Build and deploy the exact reviewed Keycloak image with registration still
   fail-closed until the custom providers are confirmed installed.
3. Verify Klyrow's dedicated SECURITY credential, verified sender/domain,
   encrypted ephemeral payload storage and private STARTTLS path.
4. Run the protected Keycloak configuration check and review the exact plan.
5. Register/enable the custom required action and borrower-only registration
   flow through a separately approved configuration change.
6. Exercise borrower registration in staging: create account, receive one code,
   reject a wrong code, verify one correct code, reject replay, complete PKCE,
   and bootstrap exactly one MoneyBee account.
7. Confirm lender/admin public registration is denied.
8. Confirm Middleware, Odoo, n8n and Mautic receive no code/reset/password
   material.
9. Repeat with a separately reviewed production plan and canary.

## Fail-closed conditions

Do not enable MoneyBee registration, password recovery or SECURITY live delivery
when any of these is unverified:

```text
MONEYBEE_REGISTRATION_PROVIDER_INSTALLED=NO
MONEYBEE_REQUIRED_ACTION_REGISTERED=NO
KLYROW_SECURITY_STREAM=UNAVAILABLE
SMTP_STARTTLS=FAIL
SMTP_CERTIFICATE=FAIL
SMTP_AUTHENTICATION=FAIL
SENDER_DOMAIN=UNVERIFIED
SENDER_IDENTITY=INACTIVE
FIREWALL_PATH=UNVERIFIED
SECURITY_PAYLOAD_ENCRYPTION=FAIL
EXACT_REDIRECT_URI=UNVERIFIED
EXACT_POST_LOGOUT_URI=UNVERIFIED
EXACT_WEB_ORIGIN=UNVERIFIED
PUBLIC_LENDER_REGISTRATION=ENABLED
PUBLIC_ADMIN_REGISTRATION=ENABLED
```
