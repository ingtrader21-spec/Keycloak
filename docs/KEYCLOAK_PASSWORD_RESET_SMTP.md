# Keycloak registration and password recovery through Klyrow

## Authority boundary

The `codestra` realm at `https://auth.codestra.co/realms/codestra` is the only
human password, email-verification, MFA, recovery-token, and browser-login
authority for Codestra-managed applications.

```text
Browser
  -> Caddy / auth.codestra.co
  -> Keycloak registration, login, verification, or recovery
  -> authenticated STARTTLS SMTP
  -> Klyrow SECURITY stream
  -> Postal
  -> user inbox
```

Kong, Codestra Middleware, n8n, Odoo, product APIs, and machine identities must
never receive a password, reset token, complete reset URL, temporary password,
verification secret, or SMTP password. They may retain only privacy-safe
operational evidence such as delivery state, provider message ID, correlation ID,
and timestamps.

## Registration policy

Realm-wide self-registration is dangerous in a shared realm because enabling the
standard registration switch would otherwise expose registration to every
eligible browser client. The Git repository therefore installs a
`codestra-registration-gate` FormAction and defines the reviewed policy in:

```text
config/identity/browser-registration-policy.json
```

Only these clients are approved for public self-registration:

```text
moneybee-borrower
beyvra-web-production
```

`moneybee-lender` and `moneybee-admin` remain invitation/provisioning-only. No
other browser or machine client becomes eligible merely because it exists in the
realm.

The source realm intentionally keeps `registrationAllowed=false` until a
protected environment proves all of the following against the exact candidate
image:

1. the `codestra-registration-gate` provider is installed;
2. a reviewed `codestra-registration` flow exists as a copy of the built-in
   registration flow;
3. the gate is `REQUIRED` inside the registration-form scope;
4. an unapproved client is rejected;
5. both approved clients reach the standard Keycloak registration form;
6. Keycloak standard verify-email remains enabled;
7. no product API receives a user password or verification secret.

Only after that read-back evidence may a separately reviewed activation set the
realm registration flow and enable registration.

## MoneyBee and Beyvra identity mappings

MoneyBee uses three reviewed public PKCE clients:

```text
moneybee-borrower -> https://app.moneybeeloan.com
moneybee-lender   -> https://lenders.moneybeeloan.com
moneybee-admin    -> https://admin.moneybeeloan.com
```

`moneybeeloan.com` remains the canonical MoneyBee identity domain. A mail/DNS
activation for `moneybee.loan` does not automatically authorize it as a login,
redirect, origin, or password-recovery domain.

Beyvra uses:

```text
beyvra-web-production -> https://beyvra.com
```

Both applications use Authorization Code Flow with PKCE `S256`. Passwords remain
inside Keycloak. After verified authentication, each product may create its own
local issuer+subject binding and authorization records, but not credential rows.

## Klyrow SMTP contract

The August 29 activation settings are represented as:

```text
SMTP_HOST=mail.klyrow.com
SMTP_PORT=25
SMTP_STARTTLS=true
SMTP_AUTHENTICATION=required
STREAM=SECURITY
```

The protected runtime supplies the active username and password from the approved
secret store. Git contains only the environment/secret names:

```text
KC_SMTP_HOST
KC_SMTP_PORT
KC_SMTP_USERNAME
KC_SMTP_PASSWORD
KC_SMTP_FROM
KC_SMTP_FROM_DISPLAY_NAME
KC_SMTP_REPLY_TO
KC_SMTP_ENVELOPE_FROM
```

Keycloak has one realm SMTP configuration. Connecting many product mail domains
to Klyrow does **not** give one Keycloak realm a different `From:` address for
each application. The current realm therefore uses one reviewed security sender.
Per-product Keycloak senders require a separate reviewed sender-provider or realm
architecture; they must not be simulated by routing reset material through a
product API or Middleware.

## Password recovery policy

The protected realm policy requires:

```text
Forgot password = enabled
Update Password required action = enabled
Force login after reset = enabled
Reset-token lifespan = 900 seconds
Generic account lookup response = enabled
SMTP authentication = enabled
STARTTLS = enabled
```

The complete reset URL and action token remain inside Keycloak and the email body
handled by the Klyrow SECURITY transport. Business email integrations do not own
or reconstruct those links.

## Connected mail-domain evidence

The activation guide supplied on 2026-08-29 reports the following mail domains as
fully connected:

```text
beyvra.com
breero.com
breero.shop
codestra.agency
codestra.cloud
codestra.co
codestra.digital
codestra.media
klyrow.com
kyqra.com
moneybee.loan
moneybeeloan.com
nativoenglish.com
telnexa.co
```

This is mail-connectivity evidence, not automatic authorization to create or
enable a Keycloak browser client, redirect URI, web origin, registration flow,
or recovery entry point. Identity activation remains governed by the exact
application-domain and client contracts in this repository.

`booked4seasons.com` remains blocked in the current identity registry until its
separate Postal/DNS evidence is updated through a reviewed change.

## Application email versus identity email

Identity/security email:

```text
Keycloak -> Klyrow SECURITY SMTP -> Postal -> inbox
```

Normal cross-system product email/event work:

```text
product durable outbox -> Middleware -> approved Klyrow connector -> Postal
```

A product must not call Klyrow SMTP, Postal, the Klyrow API, or the Kong public
edge as a shortcut around Middleware. Conversely, Keycloak reset material must
not be forced through Middleware just to satisfy the business-integration path.
These are intentionally separate trust boundaries.

## Activation gates

Before staging registration/recovery activation, require:

```text
REGISTRATION_PROVIDER_INSTALLED=PASS
REGISTRATION_FLOW_GATED=PASS
MONEYBEE_BORROWER_REGISTRATION=PASS
BEYVRA_REGISTRATION=PASS
MONEYBEE_LENDER_REGISTRATION=REJECTED
MONEYBEE_ADMIN_REGISTRATION=REJECTED
UNAPPROVED_CLIENT_REGISTRATION=REJECTED
KEYCLOAK_VERIFY_EMAIL=PASS
KEYCLOAK_PASSWORD_RESET=PASS
RESET_LINK_ONE_TIME_USE=PASS
EXPIRED_RESET_LINK=REJECTED
FORCED_RELOGIN_AFTER_RESET=PASS
SMTP_HOST=mail.klyrow.com
SMTP_PORT=25
SMTP_STARTTLS=PASS
SMTP_AUTHENTICATION=PASS
KLYROW_SECURITY_STREAM=PASS
RESET_MATERIAL_IN_MIDDLEWARE=NONE
RESET_MATERIAL_IN_KONG=NONE
RESET_MATERIAL_IN_PRODUCT_DB=NONE
```

Production requires a separate reviewed exact-SHA plan, protected approval,
read-back, rollback evidence, and fresh delivery evidence. Source configuration
alone is not proof that the live realm or SMTP path has been activated.
