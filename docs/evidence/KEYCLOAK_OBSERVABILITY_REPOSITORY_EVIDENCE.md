# Keycloak observability repository evidence

This evidence is limited to source validation. It is not deployment or production evidence.

| Control | Repository evidence |
|---|---|
| Exact clients | Three desired client JSON files under `config/desired-state/observability/clients/` |
| Exact realm roles | Five non-composite desired role files plus three explicit client realm-role scope mappings |
| OIDC controls | Exact redirect/origin, PKCE, grants, token/session, logout, and mapper assertions in `scripts/observability_desired_state.py` |
| Secret safety | No secret value in source; OpenBao authority plus runtime file references only |
| Role isolation | Family-limited scope mappings, independent-approval controls, and negative cross-family tests |
| MFA enforcement | Dedicated per-client browser flow requires password plus OTP on every login; no cookie/IdP/non-OTP fallback |
| Rendered source plan | `release/observability/keycloak-observability-desired-state-plan.json` |
| Configuration checksum | Recorded in the deterministic rendered plan and printed by exact-head CI |
| Plan artifact checksum | Recorded in `release/observability/keycloak-observability-desired-state-plan.sha256` |
| Live apply | Prohibited; desired resources are excluded from live-capable managed policies |
| Rollback | Source procedure documented; live before-state remains a later-mission prerequisite |

Protected merge identity and release authority can be recorded only after required checks, independent approval, protected merge, and immutable release publication complete. No release identity is guessed here.
