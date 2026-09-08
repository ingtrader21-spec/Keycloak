# Certified release and recovery gate

The inspected protected main was dee685730f209c967325052fd9258e29d3ae96d7 (tree b2c3e64c7d9bcac484cc97aee048ec4304cd8f97). This change must pass review and protected-main checks before selecting the resulting new release SHA. Do not build the old SHA while claiming this workflow or Dockerfile is part of it.

The Maven and Keycloak bases are digest-pinned. Maven verification, repository configuration/unit checks, dependency scanning, immutable image scan, SBOM, build provenance and hosted-only PostgreSQL 17.6 synthetic-realm checks gate release evidence. Synthetic compatibility does not certify the real recovery dump or identity baseline.

Independent production approval must bind source SHA, tree, image digest, scan reports, SBOM, provenance and recovery evidence. Main review or successful publication alone is not production approval. The release environment must support independent required reviewers; never bypass a protection failure.

No production deployment, route change, secret restoration or Server C runtime operation is included. The recovery dump predates registered identities. Reconciliation must preserve existing users, keep incomplete machine identities disabled and mark unrecoverable credentials ROTATION_REQUIRED_AFTER_RECOVERY. A complete, separately reviewed baseline is still required.

## Supported publication protection

Required-reviewer environments are unavailable on the current plan. The compensating mechanism is documented in release/intents/README.md and enforced by scripts/release/verify_intent.py. Protected main retains independent review, last-push approval, stale-review dismissal and administrator enforcement. A separately merged and independently reviewed exact-source/tree publication intent with a matching canonical JSON hash is mandatory. No executable intent is supplied, no image publication is authorized, and deployment remains separately forbidden. Scraper CI may run while its release workflow remains disabled pending review.
