# Codestra browser self-registration policy

Keycloak is the only credential, email-verification, and password-recovery authority for reviewed public browser applications.

## Approved self-registration clients

Public self-registration is permitted only through the reviewed Keycloak registration flow for:

- `moneybee-borrower` — MoneyBee borrower signup.
- `beyvra-web-production` — Beyvra customer signup.
- `breero-portal` — Breero public customer/provider identity signup.

`moneybee-lender` and `moneybee-admin` are explicitly denied public self-registration. MoneyBee lender/admin access requires invitation or privileged provisioning.

Breero staff/admin privilege is not created by public signup. Breero remains authoritative for its local tenant, department, role, permission, invitation, and record-scope state. The public `breero-portal` Keycloak client remains disabled until its exact production callback, post-logout redirect, and web origin are independently verified.

## Fail-closed activation

The source realm intentionally keeps `registrationAllowed=false`. A protected activation must first install and read back the `codestra-registration-gate` FormAction as `REQUIRED` inside a copied `codestra-registration` registration form. Only after the gate is proven present may realm registration be enabled.

Before activation, staging must prove positive registration for every approved client and rejection for denied/unapproved clients. A workflow or application flag must never enable registration by itself.

## Recovery and email

Password reset and email verification stay inside Keycloak. Reset tokens, passwords, verification secrets, and complete recovery URLs must not enter Kong, Middleware, Odoo, n8n, product databases, application outboxes, or normal logs.

Keycloak security mail uses the reviewed Klyrow SECURITY SMTP contract. Klyrow/Postal is transport only and does not become the password authority.

## Application boundary

When Keycloak is authoritative, MoneyBee, Beyvra, and Breero must not collect or mutate user passwords locally. Product backends may bind the verified Keycloak `(issuer, subject)` to their own tenant and authorization records after authentication.

No production activation, SMTP send, client enablement, or realm mutation is authorized by this document.
