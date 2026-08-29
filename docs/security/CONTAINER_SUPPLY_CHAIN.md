# Container supply-chain policy

Production Compose never builds Keycloak in place. It requires
`KEYCLOAK_IMAGE` to identify the GHCR application image using both a source-SHA
version tag and an immutable `sha256` digest. PostgreSQL and both Keycloak
Dockerfile stages are likewise pinned by version and digest.

The manual `Release immutable Keycloak image` workflow is the only repository
path that publishes the application image. It requires a protected Environment,
an exact merged `main` SHA, and explicit SHA confirmation. It refuses an
existing source-SHA tag, builds and pushes once, enables BuildKit SBOM and
max-mode provenance attestations, records the returned registry digest, scans
that exact digest, creates a CycloneDX SBOM, and uploads checksummed evidence.

The vulnerability policy fails on any unresolved High or Critical image
vulnerability. A failed scan leaves a published but non-deployable image: its
digest must not be placed in the runtime environment. The workflow never edits
Compose or performs a Keycloak apply.

Release evidence must include:

- exact source SHA;
- immutable image digest;
- BuildKit metadata and attestations;
- exact-digest vulnerability result;
- CycloneDX SBOM;
- checksums for retained artifacts.

Changing a base-image digest or scanner version requires normal pull-request
review. A tag alone, including `latest`, is never deployment authority.
