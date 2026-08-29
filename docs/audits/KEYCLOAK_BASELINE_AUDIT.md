# Keycloak repository baseline audit

Audit date: 2026-08-29 UTC  
Repository: `https://github.com/appolon1908-hue/Keycloak`  
Recorded `main` SHA: `85b8c3f54d79331cd93a3efe5bd2f4bfb9064667`  
Working branch: `fix/keycloak-apply-transaction-safety`

This audit records repository capability, not production readiness. It does not
assert that the public Keycloak runtime is controlled by this repository.

## Inventory

| Area | Baseline |
| --- | --- |
| GitHub Actions | Three workflows: source/merge validation, runtime preflight, protected deploy |
| Runtime | One multi-stage `Dockerfile` and one dedicated `compose.yaml` |
| Scripts | 19 shell/Python files, including validation, plan, apply, export, preflight, and smoke testing |
| Managed clients | Four active browser overlays |
| Machine identities | Twelve contracts marked `declared-not-created` |
| Realm desired state | One partial `codestra` realm invariant |
| Policies | Managed-client and separately creatable-client boundaries |
| Endpoint contracts | Canonical `auth.codestra.co` issuer and endpoint contract |
| Documentation | Seven operational/contract documents on baseline `main` |
| Tests | Shell mock-server plan gate, runtime-preflight tests, and Python contract validators |
| TODO/stub indicators | Seven non-documentation matches; these are deliberate declared/not-created or validation markers, not executable stubs |

## Pull request #14

PR #14, `docs: establish Keycloak as independent identity authority`, was open,
mergeable, and had successful source-head and merge-result checks when this
branch was created. It adds the authority statement and mission-plan material.
It remains a documentation prerequisite. This branch is based directly on
`main` and does not duplicate PR #14's files.

## Implemented

- Exact source-head and synthetic merge-result validation.
- Full-SHA pinning for third-party GitHub Actions.
- Exact-SHA runtime preflight with remote, branch, worktree, path, SSH key, and
  known-host verification.
- Separate non-mutating check and protected apply workflow modes.
- Deterministic canonical plan and reviewed SHA-256 gate.
- Managed and separately creatable client boundaries.
- Pre-apply validation of all reviewed client state.
- Create-target absence checks before mutation.
- Allowlisted rollback exports that exclude known secret-bearing fields.
- Post-apply convergence plan and read-only OIDC smoke checks.
- Browser-client validation for Authorization Code with PKCE S256, exact HTTPS
  redirects, and disabled implicit/direct grants.
- Twelve named service identity contracts with independent audiences and scope
  namespaces.

## Partially implemented

- Realm management is an invariant check, not full security-policy
  reconciliation.
- Machine clients are contracts only and are intentionally not provisioned.
- Rollback evidence exists, but baseline apply did not persist per-operation
  results after mutation.
- SMTP has a reviewed contract but requires external credentials and live
  verification.
- The image is version-tagged and built in CI, but no release digest, SBOM,
  provenance, or exact-digest vulnerability gate exists.
- Runtime hardening includes non-root Keycloak, `no-new-privileges`, dropped
  capabilities, private PostgreSQL, localhost bindings, health/metrics, tmpfs,
  and a stop grace period; resource/PID limits, immutable images, and evaluated
  read-only filesystems remain incomplete.

## Missing

- Immediate pre-`PUT` revalidation for every update.
- Durable partial-apply recovery manifest and failure-injection coverage.
- Immutable production Keycloak and PostgreSQL image digests.
- Complete Git-managed password, session, token, MFA, WebAuthn, and recovery
  policy.
- Active service-client overlays and reviewed caller-to-audience grants.
- Exact-digest SBOM, provenance, and vulnerability policy enforcement.
- Production-grade off-host backup and automated restore rehearsal tooling.
- Kong positive and negative token certification evidence.
- A declared observability and security-test matrix.

## Unsafe

- Baseline apply creates full merged client representations during validation
  and writes them later without an immediate state check. A concurrent change
  can be overwritten.
- A later operation failure can leave earlier changes applied without a durable
  operation-state artifact.
- Runtime images are selected by mutable tags.

## Blocked by runtime access or external evidence

- Authenticated inventory of the current public `auth.codestra.co` authority.
- Live realm/client drift and whether the twelve service clients exist.
- SMTP delivery and end-user recovery testing.
- Kong issuer, audience, scope, and rejection certification.
- Current production image digest and exact-digest vulnerability disposition.

## Blocked by production approval

- Starting or modifying the obsolete stopped Keycloak deployment.
- Reading or modifying its production database through a started service.
- Credential rotation, production check/apply, DNS changes, and cutover.
- Disabling or retiring any potential identity authority.
- Production backup, restore, rollback, restart, or reboot rehearsal.

Known stop conditions are active: the reviewed server had unsafe disk capacity,
unverified Keycloak backups, and an ambiguous authoritative host. Repository
work may proceed; production mutation may not.
