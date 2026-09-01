# Codestra Production Readiness Gate — Keycloak

Status: NOT PRODUCTION CERTIFIED

Governed by `Infustruction-repo/CODESTRA_PRODUCTION_READINESS_WAVE_20260901.md`.

Required: exact-head GitOps validation; Critical=0; High=0; protected realm/client authority; service identities with exact audiences/scopes; no direct provider grants; short-lived credentials; workload identities aligned to OpenBao; export/read-back drift checks; rollback; staging certification; production read-only canary.

Do not expose client secrets in Git or CI. Do not modify SSH access. Do not bypass protected branches or reviews.
