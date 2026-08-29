# Security test matrix

Release evidence must cover login/logout, registration policy, verification, reset, MFA and required actions; discovery, JWKS, Authorization Code with PKCE, Client Credentials, refresh and logout; audience, scope and cross-client isolation; rejection of wildcard redirects, implicit/password grants, wrong issuer/audience, expired and tampered tokens; container/database/reboot recovery; and backup, restore, rollback and partial APPLY.

Kong certification must prove one authorized request succeeds and missing, malformed, expired, wrong-issuer, wrong-audience, insufficient-scope, invalid-signature and disabled-client requests fail. Untested rows are `BLOCKED` or `NOT RUN`, never `PASS`.
