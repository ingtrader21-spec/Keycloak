# Backup and restore

`scripts/backup-postgres.sh` streams `pg_dump` custom format through age encryption, promotes output only after every pipeline stage succeeds, and writes a checksum. `BACKUP_DESTINATION` must be an off-host mounted destination or the completed encrypted file must be copied off-host and independently verified. Plaintext dumps are not written.

Restore rehearsal uses `scripts/verify-backup.sh` against a dedicated isolated PostgreSQL database. It requires an explicit destructive-test acknowledgement, validates the checksum, restores with exit-on-error, and inventories the decrypted archive. Never point it at production. A generated file without a successful restore rehearsal is not a verified backup.

Target RPO is 24 hours and target RTO is four hours until measured rehearsals justify tighter values. Retain 14 daily, 8 weekly and 12 monthly encrypted copies; monitor failures and staleness.

The systemd service/timer templates under `deploy/systemd` run as a dedicated account and write only to `/srv/keycloak-backups`. Installation and timer enablement are cutover actions requiring approval; an operator must verify timer status and deliberately test failure alerting.
