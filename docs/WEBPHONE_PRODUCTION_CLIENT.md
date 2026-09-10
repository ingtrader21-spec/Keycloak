# Webphone production authentication repair

The deployed webphone issuer calls the production provisioning verifier, which
requires authorized party and audience `codestra-provisioning-service` and
the exact `codestra_scopes` claim. Its former staging client is rejected.
The separately managed `provisioning-service` identity targets Middleware
and has a different audience and scope contract; its credential is not a substitute.

This compatibility client is dedicated to `middleware-webphone-session-issuer`.
Its only required direct realm-management assignment and client scope mapping
is `view-users`, for the issuer's existing read-only user lookup. No realm
roles or user-mutation roles are authorized by this change. Keycloak's effective
read-only composite prerequisites must be checked during live read-back.

The generic client planner handles the client overlay and protocol mappers.
It does **not** assign service-account roles or role scope mappings. Those
bindings require an independently reviewed role-binding change through the
identity owner's supported administration process. A token without the required
role must fail the webphone authentication preflight; client creation alone
does not establish readiness.

The new protected secret binding is
`KC_CLIENT_SECRET_CODESTRA_PROVISIONING_SERVICE`. Supply it through the existing
protected Environment secret system. No value belongs in this repository, plan,
artifact, chat, or logs. Existing-client secret rotation is a separately reviewed
credential operation; the generic overlay updater does not rotate secrets.

Before enabling the consumer:

1. Complete the existing protected source review and exact-main check/plan/review
   process in `docs/GITOPS.md`. Preserve the production mutation stop flag.
2. Apply the approved client configuration only after the existing production
   certification and protected Environment requirements are satisfied.
3. Verify service-account `view-users` assignment and matching client scope
   mapping, no broader effective privileges, RS256, canonical issuer, exact
   audience/authorized party/scopes, and token lifetime at most 300 seconds.
4. Deliver the client-specific credential through the supported protected secret
   channel into the issuer's separate production secret file. Do not reuse the
   inactive provisioning adapter's `keycloak_client_secret` or a staging secret.
5. Run the consumer's authenticated preflight before recreating that consumer.
   Keep SIP provisioning, campaign activation and calling under their existing
   separate controls.

The production provisioning adapter's broader proposed Keycloak identity policy
does not grant those roles to this webphone consumer. That adapter needs its own
reviewed identity before its Keycloak capability is enabled.

Rollback uses the existing allowlisted overlay and protected review flow.
For a newly created client, disable first; deletion needs its existing separate
review. Roll the consumer back to its prior configuration and credential binding.

The explicit client-role mapper emits only realm-management roles and does not
grant them. Its fields follow the [Keycloak mapper API](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/protocol/oidc/mappers/UserClientRoleMappingMapper.html)
and [mapper constants](https://www.keycloak.org/docs-api/latest/javadocs/constant-values.html).
Empty default client scopes do not implicitly supply this mapper.
