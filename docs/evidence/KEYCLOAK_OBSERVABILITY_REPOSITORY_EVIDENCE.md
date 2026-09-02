# Keycloak observability repository evidence

This evidence is limited to source validation. It is not deployment or production evidence.

| Control | Repository evidence |
|---|---|
| Exact clients | Three desired client JSON files under `config/desired-state/observability/clients/` |
| Exact realm roles | Five non-composite desired role files under `config/desired-state/observability/realm-roles/` |
| OIDC controls | Exact redirect/origin, PKCE, grants, token/session, logout, and mapper assertions in `scripts/observability_desired_state.py` |
| Secret safety | No secret value in source; OpenBao authority plus runtime file references only |
| Role isolation | Family, MFA, independent-approval, and negative cross-family tests |
| Rendered source plan | `release/observability/keycloak-observability-desired-state-plan.json` |
| Configuration checksum | `2234bcddd0dcc4e78d84e9e7102d91ad98aa821b8c023166669bb1f7f2e2b42b` |
| Plan artifact checksum | Recorded in `release/observability/keycloak-observability-desired-state-plan.sha256` |
| Live apply | Prohibited; desired resources are excluded from live-capable managed policies |
| Rollback | Source procedure documented; live before-state remains a later-mission prerequisite |

Protected merge identity and release authority can be recorded only after required checks, independent approval, protected merge, and immutable release publication complete. No release identity is guessed here.
