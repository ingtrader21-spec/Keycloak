# PAS-157 — Caller + token certification

PAS-157 defines the Keycloak-side identity boundary for callers of the Middleware V3 API. It is a repository-only certification lane: it does **not** create live clients, mint production tokens, grant scopes, modify realm defaults, or authorize a Keycloak apply.

## Authority

The caller authority is:

`config/contracts/middleware-caller-classification.v1.json`

Every Middleware caller is classified as one of four types:

- `CONCRETE_SERVICE_CLIENT` — short-lived `client_credentials` workload identity.
- `CONCRETE_HUMAN_CLIENT` — Authorization Code + PKCE; MFA is required for privileged use.
- `CLIENT_FAMILY` — a logical selector that must resolve to a separately reviewed concrete member.
- `SYMBOLIC_RUNTIME_SELECTOR` — a fail-closed policy selector such as `none` or a reviewed automation family; never a wildcard AZP.

The authority explicitly resolves the previously open caller vocabulary including `callback-ui`, `n8n-operations-automation`, `github-app`, `observability-collector`, `production-operator`, and the V3 `platform-command-client` family. `platform-command-family` is an explicit alias of `platform-command-client`.

`service-or-user-jwt` is allowed only where the caller rule names the permitted actor kinds. Workloads use `client_credentials`; humans use Authorization Code + PKCE. Privileged human actions require MFA.

The V3 replay boundary is compound and fail-closed:

- scope: `platform.command.replay`
- realm role: `platform-operator`
- actor: human user
- grant: Authorization Code
- PKCE: required
- MFA: required

The dirty desktop client `codestra-agent-desktop` is explicitly protected from automatic Middleware access. PAS-157 does not enroll it in any caller family.

## Token matrix

`config/certification/v3-token-matrix.v1.json` contains synthetic positive and negative cases for all required dimensions: issuer, audience, AZP/reviewed family membership, tenant, scope, role, expiry/bounded lifetime, and replay.

The validator refuses wildcard caller/scopes, privileged scopes leaked into default client scopes, an unresolved caller identity, a service identity using a human grant, a human identity without PKCE/MFA handling, and replay without all required controls.

## Middleware contract pin

PAS-157 targets the final Middleware V3 public route contract:

- repository: `ingtrader21-spec/Middleware-`
- contract: `deploy/public-api-route-contract.json`
- route count: `117`
- digest: `9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b`

Since PAS-8 (2026-09-24) the repository's default route contract (`config/desired-state/edge-integration-certification/middleware-public-api-route-contract.v2.json`) is the 117-route contract read from Middleware `main` at `0606b0d`, so `--check` reports `TARGET_ROUTE_CONTRACT_MATCH=PASS` and `tests/test_middleware_v3_freeze_certification.py` enforces `--require-target-contract` on every `scripts/validate.sh` run. A contract that drifts from the frozen digest fails with `target Middleware route contract mismatch`.

## Commands

Current stacked-base regression:

```powershell
py -3.12 scripts/validate_middleware_caller_classification.py --check
py -3.12 scripts/validate_v3_token_matrix.py --check
py -3.12 -m pytest -q tests/test_middleware_caller_classification.py tests/test_v3_token_matrix.py
```

Final V3 contract certification:

```powershell
py -3.12 scripts/validate_middleware_caller_classification.py --check --route-contract <path-to-final-public-api-route-contract.json> --require-target-contract
```

Required success evidence includes:

```text
PAS157_CALLER_TOKEN_CERTIFICATION=PASS
TARGET_ROUTE_CONTRACT_MATCH=PASS
ROUTE_COUNT=117
UNKNOWN_CALLER_IDENTITIES=0
HUMAN_SERVICE_BOUNDARY=PASS
TOKEN_MATRIX_DIMENSIONS=8
PRIVILEGED_DEFAULT_SCOPE_LEAKS=0
DIRTY_DESKTOP_AUTO_GRANT=PROHIBITED
KEYCLOAK_LIVE_APPLY=PROHIBITED
```

PAS-157 does not authorize staging or production activation. PAS-158 owns exact-head cross-repository identity parity and the subsequent integration gate.
