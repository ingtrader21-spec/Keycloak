# Keycloak runtime gap analysis

Assessment date: 2026-08-29 UTC  
Target authority: `https://github.com/appolon1908-hue/Keycloak`  
Target dedicated checkout: `/srv/keycloak` or another explicitly approved path

This is read-only discovery evidence. It does not authorize a restart, database
operation, DNS change, credential rotation, image release, or production apply.

## Authority gap

The obsolete deployment is defined by
`/srv/codestra-platform/compose.apps.yaml`, outside a Git worktree. It has no
remote URL or exact deployment SHA and is therefore not a valid production
authority. Its Keycloak and PostgreSQL containers were stopped on 2026-08-20.
The public issuer resolved to a different server than the inspected host, so the
current authoritative host remains ambiguous.

Required disposition: preserve the cold database, establish the real public
authority, create a dedicated exact-SHA checkout, and prevent the obsolete
deployment from automatically starting before any cutover approval.

## Runtime differences

| Control | Discovered obsolete runtime | Repository target |
| --- | --- | --- |
| Provenance | Non-Git server directory | Exact reviewed `main` SHA |
| Topology | Broad unrelated platform Compose | Dedicated Keycloak/PostgreSQL Compose |
| Keycloak | Stock 26.7.0 mutable tag | Optimized 26.7.2 base pinned by digest; GHCR release deployed by digest |
| PostgreSQL | 16 mutable tag | 17.6 Alpine pinned by digest |
| Secrets | Shared environment exposed unrelated credentials | Per-purpose secret contracts and exact service environment allowlists |
| Filesystem | Writable container roots | Read-only roots with explicit volume/tmpfs writes |
| Limits | Partial Compose deploy limits | CPU, memory, PID, log, and stop limits |
| Apply | Manual/unproven | Exact-SHA check, reviewed hash, protected apply |
| Recovery evidence | No per-operation apply state | Durable operation manifest and rollback artifact reference (PR #16) |

## Active production blockers

- The inspected root filesystem was approximately 99% full.
- The Keycloak backup service was failing because PostgreSQL was stopped.
- Last recorded successful Keycloak dump was 2026-08-20; no verified off-host
  copy or current restore rehearsal was demonstrated.
- SMTP sender configuration was absent and recovery/verification email failed.
- The authoritative public host remains ambiguous.
- Exact current public realm/client state was not authenticated or exported.
- Production credentials and protected approval were not available or used.
- Kong positive and negative authorization certification is incomplete.

## Current image-security evidence

A checksum-verified Trivy 0.74.0 scan of the locally built, digest-pinned
Keycloak 26.7.2 application image on 2026-08-29 found two High findings and no
Critical findings in the selected High/Critical report:

| Finding | Component | Installed | Fixed version reported |
| --- | --- | --- | --- |
| CVE-2026-22020 | `java-21-openjdk-headless` | `1:21.0.12.1.1-1.2.el9` | None |
| CVE-2025-59250 | `com.microsoft.sqlserver:mssql-jdbc` | `13.2.1` | Scanner lists version-qualified alternatives |

These are unresolved release blockers, not accepted risks. The protected image
release workflow intentionally fails on High or Critical findings. A reviewed
base update, removal of provably unused vulnerable material with startup tests,
or explicit security risk approval is required before an image digest is
eligible for deployment.

## Exit evidence still required

- Safe disk capacity and alert threshold.
- Checksummed cold database copy stored off-host.
- Successful isolated restore and identity inventory.
- One explicitly named authoritative production host.
- Exact `/srv/keycloak` checkout SHA and runtime-path fingerprint.
- Published GHCR digest with SBOM, provenance, checksums, and passing or
  approved vulnerability disposition.
- Successful backup, restore, rollback, restart, and reboot rehearsals.
- SMTP, account recovery, MFA, service Client Credentials, and Kong acceptance
  and rejection evidence.

Until these are attached, production activation remains blocked.
