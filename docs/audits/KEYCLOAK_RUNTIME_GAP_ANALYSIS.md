# Keycloak runtime gap analysis

The inspected legacy directory `/srv/codestra-platform` is not a Git checkout and cannot identify a source SHA. Its stopped runtime differs from this repository, used shared secrets and mutable images, had failed backups and was observed on a nearly full disk. The public DNS target was not the inspected host, so the authoritative runtime is ambiguous. These facts block cutover.

The target is a dedicated `/srv/keycloak` exact checkout, immutable image digests, isolated secrets, protected CHECK/APPLY, verified off-host backup and restore, and explicit retirement of every stale instance. Repository controls do not claim those live outcomes have occurred.
