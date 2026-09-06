# Keycloak secret boundaries and rotation

Production values live only in the approved runtime secret provider or a
protected GitHub Environment. Example files under `deploy/secrets/` define
names and injection boundaries; they are not runtime values and must never be
copied into Git with real credentials.

| Boundary | Consumer | Rotation impact |
| --- | --- | --- |
| PostgreSQL password | Keycloak PostgreSQL and Keycloak only | Coordinate database role and Keycloak restart during an approved window |
| Bootstrap administrator | Keycloak bootstrap only | Remove after permanent administration is verified; never use for routine apply |
| Administration API client | Protected check/apply workflow only | Rotate in Keycloak and GitHub Environment without exposing it to containers |
| SMTP credential | Protected realm reconciliation only | Rotate at provider and Environment, then test verification and recovery email |
| Monitoring credential | Approved monitoring client only | Rotate independently from administration and applications |
| Runtime deploy key | Git checkout/preflight only | Replace key and independently approve its runtime fingerprint |

Before rotation, verify backup and rollback evidence, identify every consumer,
and record the exact approved repository SHA. After rotation, revoke the prior
credential and run the smallest relevant authentication check. A rotation must
not start or reactivate the obsolete Keycloak instance, create a second
authority, or place secrets in command output, artifacts, shell history, or
logs.

The dedicated Compose file contains only Keycloak and PostgreSQL. Static policy
validation rejects unrelated environment variables in either service. In
particular, credentials for Matomo, GlitchTip, SonarQube, OAuth proxies, or
unrelated applications are prohibited from both containers.
