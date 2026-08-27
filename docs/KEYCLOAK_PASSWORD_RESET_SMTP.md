# Keycloak password reset through Klyrow and Postal

## Authority boundary

The `codestra` realm at `https://auth.codestra.co/realms/codestra` is the only
password authority for Codestra-managed human users.

```text
Application login UI
  -> Codestra Keycloak login/reset-credentials flow
  -> authenticated STARTTLS SMTP over the private VLAN
  -> Klyrow SECURITY relay
  -> Postal delivery
  -> user inbox
```

Application APIs, Odoo, n8n, Codestra Middleware, and machine clients must never
receive a reset token, temporary password, new password, SMTP password, or
complete reset URL. They may record only privacy-safe operational evidence such
as a provider message ID, delivery outcome, correlation ID, and timestamp.

## Fifteen-domain identity registry

The authoritative desired-state registry is:

```text
config/identity/application-domain-registry.json
```

It contains exactly fifteen root domains:

| Domain | Keycloak mapping | Identity state | Postal DNS evidence |
|---|---|---|---|
| `codestra.agency` | legacy alias of `codestra-portal-production` | disabled; no redirect or recovery | operator-reported SPF/DKIM/MX/return-path OK |
| `codestra.co` | `codestra-portal-production` | declared; exact runtime binding required | operator-reported OK |
| `nativoenglish.com` | `nativoenglish-portal` | declared; exact runtime binding required | operator-reported OK |
| `moneybeeloan.com` | alias of `moneybee-portal` | declared; exact runtime binding required | operator-reported OK |
| `codestra.cloud` | `codestra-cloud-service` | confidential service only; no human recovery | operator-reported OK |
| `codestra.digital` | `codestra-digital-portal` | declared; exact runtime binding required | operator-reported OK |
| `codestra.media` | `codestra-media-portal` | declared; exact runtime binding required | operator-reported OK |
| `moneybee.loan` | `moneybee-portal` | declared canonical MoneyBee domain | operator-reported OK |
| `klyrow.com` | `klyrow-portal` | managed with exact `https://klyrow.com/` redirect | operator-reported OK |
| `beyvra.com` | `beyvra-web-production` + `beyvra-api-production` audience | declared trading frontend/backend mapping | operator-reported OK |
| `kyqra.com` | `kyqra-portal` + `kyqra-gateway` audience | declared | operator-reported OK |
| `breero.com` | `breero-portal` + `breero-api-production` audience | declared | operator-reported OK |
| `breero.shop` | alias of `breero-portal` | declared alias | operator-reported OK |
| `telnexa.co` | `telnexa-portal` + `telnexa-gateway` audience | declared | operator-reported OK |
| `booked4seasons.com` | `booked4seasons-portal` | declared but DNS-blocked | no completed Postal DNS check confirmed |

The Postal status above is operator-provided evidence and is not a substitute
for a fresh protected runtime preflight. The registry requires runtime
reverification before staging or production activation.

A domain declaration does not authorize a wildcard redirect or a live client.
Except for the already reviewed Klyrow redirect, every browser client remains
disabled with empty redirect and origin lists until the deployed callback path
is verified from the application repository and runtime.

The registry enforces these rules:

```text
EXACT_DOMAIN_COUNT=15
PUBLIC_PKCE_DOMAINS=13
SERVICE_ONLY_DOMAINS=1
LEGACY_DISABLED_DOMAINS=1
POSTAL_DNS_REPORTED_OK_DOMAINS=14
BOOKED4SEASONS_DNS_BLOCK=ENFORCED
WILDCARD_REDIRECTS=DISALLOWED
LOCAL_PASSWORD_RESET=DISALLOWED
CLIENT_CREATION_BEFORE_RUNTIME_VERIFICATION=DISALLOWED
```

## Application password-recovery clients

The thirteen human domains delegate recovery to Keycloak:

```text
codestra-portal-production
nativoenglish-portal
moneybee-portal
codestra-digital-portal
codestra-media-portal
klyrow-portal
beyvra-web-production
kyqra-portal
breero-portal
telnexa-portal
booked4seasons-portal
```

`moneybeeloan.com` and `moneybee.loan` share the reviewed MoneyBee application
client. `breero.com` and `breero.shop` share the reviewed Breero application
client. `codestra.agency` is legacy-disabled and must not initiate authentication
or recovery. `codestra.cloud` is service-only and receives no browser client.
`booked4seasons.com` remains disabled even though its future recovery authority
is Keycloak, because its Postal DNS status and exact callback/origin bindings
are not confirmed.

Human applications use Authorization Code Flow with PKCE `S256`. Machine
clients and API audiences never initiate password recovery and never receive
reset material.

## Klyrow SMTP contract

The reviewed private endpoint contract is:

```text
SMTP_HOST=10.40.0.4
SMTP_PORT=587
ENCRYPTION=STARTTLS
AUTHENTICATION=REQUIRED
STREAM=SECURITY
```

The live endpoint, firewall path, certificate, sender domain, sender identity,
and credential must still be verified at runtime. The Klyrow credential must be
dedicated to Keycloak and limited to one verified sender and the `SECURITY`
stream.

Keycloak has one realm SMTP configuration. Declaring fifteen application/mail
domains does not configure fifteen From addresses. One reviewed security sender
must be selected and verified for the realm. Alternative senders require their
own reviewed change.

The Git repository stores only variable and secret names. Configure these in a
protected GitHub Environment or the approved runtime secret provider:

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

Never commit their live values.

## Realm settings

The protected apply must configure and verify:

```text
Forgot password = enabled
Update Password required action = enabled
Force login after reset = enabled
Reset-token lifespan = 900 seconds
SMTP authentication = enabled
STARTTLS = enabled
```

Use generic responses so the forgot-password page does not reveal whether an
account exists.

## Activation sequence

1. Protected-merge the secure Keycloak GitOps foundation.
2. Protected-merge the service identity/API/webhook contracts.
3. Protected-merge this fifteen-domain/password-reset contract.
4. Rotate every Postal DKIM private key exposed in previous diagnostic output,
   publish replacement DNS records, and verify the new selectors.
5. Implement and review the Klyrow `SECURITY` SMTP stream.
6. Reverify all fourteen reported-good Postal domains and complete the missing
   Postal DNS check for `booked4seasons.com`.
7. Verify `10.40.0.1 -> 10.40.0.4:587` connectivity without sending mail.
8. Register and verify the approved sender domain and address in Klyrow.
9. Create a dedicated, expiring Klyrow SMTP credential and store it outside Git.
10. Verify each application's exact callback, post-logout redirect, and origin
    before enabling its declared Keycloak client.
11. Run a Keycloak drift check and review the exact plan hash.
12. Apply realm email settings through protected staging approval.
13. Exercise password recovery from every enabled human application in staging.
14. Verify one delivery, expiration, one-time use, replay rejection, disabled
    user denial, and forced re-login; confirm no machine client received reset
    material.
15. Repeat with a separately reviewed production plan.

## Fail-closed conditions

Do not enable the reset flow or a declared client when any of these is
unverified:

```text
KLYROW_SECURITY_STREAM=UNAVAILABLE
SMTP_STARTTLS=FAIL
SMTP_CERTIFICATE=FAIL
SMTP_AUTHENTICATION=FAIL
SENDER_DOMAIN=UNVERIFIED
SENDER_IDENTITY=INACTIVE
FIREWALL_PATH=UNVERIFIED
RESET_TOKEN_LIFESPAN=UNAPPROVED
EXACT_REDIRECT_URI=UNVERIFIED
EXACT_POST_LOGOUT_URI=UNVERIFIED
EXACT_WEB_ORIGIN=UNVERIFIED
LOCAL_PASSWORD_RESET_STILL_ACTIVE=YES
POSTAL_DKIM_ROTATION=INCOMPLETE
BOOKED4SEASONS_POSTAL_DNS=UNCONFIRMED
```
