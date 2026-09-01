# Backup and restore

`scripts/backup-postgres.sh` streams `pg_dump` custom format through age encryption, promotes output only after every pipeline stage succeeds, and writes a relocatable basename-only checksum record. `KEYCLOAK_DATABASE_URL` must be a credential-free PostgreSQL URI. Database authentication is supplied only through the absolute, non-symlink `KEYCLOAK_PGPASSFILE`, owned by the dedicated backup account and mode `0400` or `0600`; never put the database password in the URI or `backup.env`. `BACKUP_DESTINATION` must be an off-host mounted destination or the completed encrypted file and sidecar must be copied together off-host and independently verified. Plaintext dumps are not written.

Restore rehearsal uses `scripts/verify-backup.sh` against a dedicated isolated PostgreSQL database. It requires an explicit destructive-test acknowledgement, a credential-free `RESTORE_TEST_DATABASE_URL`, and a protected `RESTORE_TEST_PGPASSFILE`; requires the sidecar basename to match the supplied copy; computes the digest from that exact copy; restores with exit-on-error; and inventories the decrypted archive. Never point it at production. A generated file without a successful restore rehearsal is not a verified backup.

Target RPO is 24 hours and target RTO is four hours until measured rehearsals justify tighter values. Retain 14 daily, 8 weekly and 12 monthly encrypted copies; monitor failures and staleness.

The systemd service/timer templates under `deploy/systemd` run as a dedicated account and write only to `/srv/keycloak-backups`. Installation and timer enablement are cutover actions requiring approval; an operator must verify timer status and deliberately test failure alerting.
