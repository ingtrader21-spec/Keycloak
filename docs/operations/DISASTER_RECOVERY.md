# Disaster recovery

Declare an incident, freeze APPLY, identify the last reviewed repository SHA and last restore-tested backup, and provision an isolated recovery environment. Restore the database, deploy the exact image digest and Git SHA, verify discovery/JWKS/login and client credentials, then obtain incident and security approval before traffic changes. Record measured RPO/RTO, checksums and all approvers. Do not activate recovery while another production authority receives traffic.
