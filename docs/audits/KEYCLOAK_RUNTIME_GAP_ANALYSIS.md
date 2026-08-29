# Keycloak runtime gap analysis

The inspected legacy directory `/srv/codestra-platform` is not a Git checkout and cannot identify a source SHA. Its stopped runtime differs from this repository, used shared secrets and mutable images, had failed backups and was observed on a nearly full disk. The public DNS target was not the inspected host, so the authoritative runtime is ambiguous. These facts block cutover.

The target is a dedicated `/srv/keycloak` exact checkout, immutable image digests, isolated secrets, protected CHECK/APPLY, verified off-host backup and restore, and explicit retirement of every stale instance. Repository controls do not claim those live outcomes have occurred.

## GitHub environment protection

On 2026-08-29 the GitHub API reported `production`, `staging`, `keycloak-drift-review`, and `keycloak-image-release` with no protection rules, no deployment branch policy, and administrator bypass enabled. Attempts to require the existing independent collaborator as reviewer, prevent self-review, disable administrator bypass, and restrict deployment to protected branches were rejected with HTTP 422 because the repository billing plan does not support required-reviewer environment protection.

This is a production stop condition. Upgrade the GitHub plan or move the private repository to an organization/plan supporting environment reviewers, then configure and read back all four environments. Workflow-level plan review remains defense in depth but is not a substitute for the explicitly required protected APPLY environment.
