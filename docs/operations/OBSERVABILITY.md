# Observability

`config/observability/keycloak-alerts.yaml` is a vendor-neutral Prometheus rule contract for readiness, restart loops, server errors, stale backups, GitOps drift and disk pressure. Deployment owners must bind metric names to the installed exporter and add alerts for database health, login/token/SMTP/admin failures, brute-force lockouts, latency and certificate expiry. Logs must redact authorization headers, tokens and credentials. Alert routing is a production-environment responsibility and remains unverified until exercised.
