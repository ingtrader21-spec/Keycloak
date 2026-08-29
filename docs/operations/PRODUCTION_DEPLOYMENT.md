# Production deployment

The approved checkout is `/srv/keycloak`, cloned with a read-only deploy key from `git@github.com:appolon1908-hue/Keycloak.git`. Check out `main` at the exact approved 40-character SHA without local modifications. Keep environment files and SSH material outside the checkout. Run `runtime-preflight.sh --expected-deploy-sha SHA --require-approved FINGERPRINT`, then the protected CHECK workflow. APPLY requires the identical SHA, plan artifact and SHA-256, independent review and GitHub production-environment approval.

Never run `docker compose up`, APPLY, DNS changes, credential rotation or retirement as an incidental migration step. The repository prepares those operations; an approved cutover performs them.
