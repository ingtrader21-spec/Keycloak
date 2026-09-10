# Klyrow connection reconciliation

The Klyrow gateway on 37.27.128.39 successfully reaches Codestra Keycloak on
65.109.65.169: discovery and JWKS return HTTPS 200, and the real Klyrow login
redirect reaches the Keycloak password form with client `klyrow-portal`, PKCE
S256 and callback `https://app.klyrow.com/auth/callback`.

The previous desired client still used `https://klyrow.com/`. Applying it would
break the existing BFF callback. This change aligns root, callback, origin and
logout with `app.klyrow.com`, limits scopes, and emits `klyrow-api` only in access
tokens. Klyrow verifies ID tokens against `klyrow-portal` and API bearer tokens
against `klyrow-api`; those audiences serve different purposes.

The live realm currently has no SMTP configuration. The approved SECURITY relay
answers on private 10.40.0.4:587, but its certificate covers `mail.klyrow.com`.
A strict TLS check against the IP fails. Connecting to the same private address
with the certificate hostname verifies successfully, advertises AUTH after TLS,
and returns NOOP 250. No SMTP authentication, mail submission or password reset
was attempted. The certificate expires 2026-11-13.

The SMTP contract now uses `mail.klyrow.com`, explicitly records private address
10.40.0.4, and the dedicated Keycloak Compose service fixes hostname resolution
to that address. Validators require that exact binding and authenticated
STARTTLS. This fixes hostname verification without allowing public SMTP egress
or weakening TLS. The live identity-platform Compose stack is different from
this repository's dedicated stack; verify runtime paths and carry the hostname
binding into the approved deployed service before the realm change is applied.

The deployment workflow now runs `scripts/verify_runtime_smtp.py` before apply.
It selects the active `keycloak` service through the approved Compose/env paths,
checks the running container's Compose identity and `ExtraHosts`, reads its
active `/etc/hosts`, and rejects a missing/conflicting binding or a replacement
container. It uses the local Docker daemon and never restarts a service or
changes networking. Production `apply-plan.sh` repeats this check before admin
authentication and immediately before the realm PUT. Source-only `extra_hosts`
changes cannot satisfy it. Inspection failures report fixed codes rather than
potentially secret-bearing Compose output.

The live Klyrow gateway lacks the SECURITY tenant/username/sender configuration,
and the inspected Keycloak secret directory contains no dedicated SMTP credential.
Provision that identity through Klyrow's reviewed SECURITY stream workflow, bind
the approved sender, and supply `KC_SMTP_USERNAME` / `KC_SMTP_PASSWORD` only through
the protected apply environment. Keep the activation controls closed until the
configured credential passes authentication and a separately authorized controlled
message confirms delivery. Reverting to the IP literal is not a working rollback;
pause security-mail delivery and retain the verified hostname/private route.

The canonical `klyrow-gateway` machine client is desired in Git but absent from
the inspected live Codestra realm. Two legacy clients, `klyrow-email-provider`
and `klyrow-email-adapter`, remain. The latter has full scope enabled. Reconcile
their consumers and least-privilege policy through the protected plan before
retirement; do not reuse their credentials for the canonical gateway.

This change also declares the `odoo-sms` product service identity required by
Odoo PR #93 and Middleware PR #221. It has only `odoo.sms.command.write` and
`odoo.sms.status.read`, audience `middleware-api`, a 300-second lifetime, and the
existing service-account `tenant_id` attribute mapper. It has no browser grants,
redirects or direct provider authority. Bind a non-wildcard tenant attribute
matching the Odoo company/business-unit configuration after reviewed creation.
Missing tenant claims remain rejected by Middleware.

Run `make validate` and the protected plan-gate tests. A merge does not deploy:
runtime-path verification, an exact-main check plan, independent review and the
protected apply are mandatory. The bootstrap policy must be reviewed independently
for changed executable/configuration files. This PR does not change its own trust
root or create an approval status. Full human login, signup, logout propagation,
service token issuance, SMTP AUTH and end-to-end delivery remain runtime
certification work after the reviewed deployment prerequisites are satisfied.

`config/bootstrap/proposals/klyrow-odoo-sms-20260910.json` records the two changed
files in the existing declared manifest, derived from immutable source commit
`fea8a3c48d2ca39a9c8f27e29814c7a5a1d5f8b5` and protected-main policy
`27e754ba8f56eaa279cde82ffe1bbc63c9fa0bcc`. It is a review proposal only. The
legacy declared set does not cover all changed configuration or the new SMS
files; independent closure review must account for those as well before apply.
The subsequent deployment-binding repair is recorded by
`config/bootstrap/proposals/klyrow-production-smtp-binding-20260910.json`, using
source `454974092dd47a32cb9a47a86f5355fe6df0f8d2`. This newer proposal supersedes
the earlier validator hashes for review and still grants no release authority.

## Production attempt — 2026-09-10 02:05 UTC

Odoo #93, Middleware #221 and Klyrow #108 passed their required CI, but GitHub
rejected normal merges with HTTP 405 because independent approval is missing.
Middleware explicitly requires code-owner review from `kazan555`. Keycloak #107
also remains blocked by the active bootstrap validator digests. No branch rule,
certification stop flag, trust anchor or production workload was changed.

The core Odoo, Middleware and Keycloak containers and the Klyrow gateway remain
healthy. Fresh read-only checks still find no `odoo-sms` or `klyrow-gateway`
client in the live Codestra realm, no SMTP settings, and no `mail.klyrow.com`
binding in the live Keycloak container. Administrative credential directories
exist, but credential availability does not establish an approved release or
authorize skipping its reviewed plan. SMS remains disabled; this is not a
successful production activation or delivery certificate.
