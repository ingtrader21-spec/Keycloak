#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
required = [
    "docs/architecture/KEYCLOAK_AUTHORITY_ARCHITECTURE.md",
    "docs/operations/PRODUCTION_DEPLOYMENT.md",
    "docs/operations/BACKUP_RESTORE.md",
    "docs/operations/DISASTER_RECOVERY.md",
    "docs/operations/OLD_RUNTIME_RETIREMENT.md",
    "docs/security/SECURITY_TEST_MATRIX.md",
    "docs/evidence/RELEASE_EVIDENCE_TEMPLATE.md",
]
missing = [name for name in required if not (root / name).is_file()]
if missing:
    print("Missing authority controls: " + ", ".join(missing), file=sys.stderr)
    raise SystemExit(1)
for script in ("scripts/backup-postgres.sh", "scripts/verify-backup.sh"):
    text = (root / script).read_text()
    if "STATUS=SUCCESS" not in text or "set -Eeuo pipefail" not in text:
        raise SystemExit(f"{script} is not fail-closed")
backup_script = (root / "scripts/backup-postgres.sh").read_text()
for required_control in (
    'KEYCLOAK_PGPASSFILE',
    'PGPASSFILE="$KEYCLOAK_PGPASSFILE" pg_dump',
    'parsed.password is None',
    '"$(basename -- "$final")"',
):
    if required_control not in backup_script:
        raise SystemExit(f"Backup credential/checksum control is missing: {required_control}")
verify_script = (root / "scripts/verify-backup.sh").read_text()
for required_control in (
    'recorded_name',
    '"$(basename -- "$backup")"',
    'sha256sum -- "$backup"',
    'RESTORE_TEST_PGPASSFILE',
    'PGPASSFILE="$RESTORE_TEST_PGPASSFILE" pg_restore',
):
    if required_control not in verify_script:
        raise SystemExit(f"Restore checksum binding is missing: {required_control}")
kong_script = (root / "scripts/certify-kong.sh").read_text()
for case_name in ("missing", "malformed", "wrong_issuer", "wrong_audience", "insufficient_scope", "expired", "invalid_signature"):
    if case_name not in kong_script:
        raise SystemExit(f"Kong certification is missing case: {case_name}")
alert_contract = (root / "config/observability/keycloak-alerts.yaml").read_text()
required_alerts = {
    "KeycloakUnavailable",
    "KeycloakDatabaseUnavailable",
    "KeycloakRestartLoop",
    "KeycloakHighServerErrors",
    "KeycloakHighRequestLatency",
    "KeycloakLoginFailures",
    "KeycloakTokenIssuanceFailures",
    "KeycloakSmtpFailures",
    "KeycloakAdminAuthenticationFailures",
    "KeycloakBruteForceLockouts",
    "KeycloakBackupStale",
    "KeycloakReconciliationFailed",
    "KeycloakConfigurationDrift",
    "IdentityCertificateExpiring",
    "IdentityHostDiskCritical",
}
missing_alerts = sorted(name for name in required_alerts if f"alert: {name}" not in alert_contract)
if missing_alerts:
    raise SystemExit("Missing observability alerts: " + ", ".join(missing_alerts))
print("PRODUCTION_AUTHORITY_CONTROLS=PASS")
