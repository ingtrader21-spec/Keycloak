# Machine identity policy

Codestra uses twelve independent confidential Keycloak clients. Each enables
service accounts and Client Credentials only; browser, implicit, direct grant,
device, and CIBA flows are disabled. Full-scope mode, redirects, web origins,
and authorization services are disabled. Access tokens are limited to 300
seconds.

Audiences and scopes are rendered deterministically from
`config/contracts/service-access-matrix.json`. A token receives only the target
audiences and scopes attached to explicit caller grants. There is no wildcard
grant and no implicit transitive access.

Every client has a unique protected apply secret named in
`machine-secret-destinations.json`. The value must be generated and stored in
the protected Environment before the reviewed create. Apply injects it only
into a mode-0600 temporary request and never into Git, plans, reviews, rollback
exports, logs, or artifacts. Missing credentials fail before the first create.

Credential delivery to the consuming workload remains an external operational
step. A created client is not integration evidence until that workload obtains
its credential through its approved secret provider and completes a scoped
token test.
