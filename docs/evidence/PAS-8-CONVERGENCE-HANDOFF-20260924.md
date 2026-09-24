# PAS-8 Keycloak production convergence — handoff 2026-09-24

Linear authority: PAS-8 (children PAS-155…PAS-161). `PRODUCTION_GO=NO`.

## Repository truth at handoff

| Item | Value |
| --- | --- |
| `origin/main` | `45a487d71a516ae3039b00c250752897469ffe7a` (PR #118 merge, 2026-09-20) |
| Work branch | `worktree-pas8-convergence-20260924`, based on `45a487d`, local only (not pushed) |
| Worktree | `Keycloak/.claude/worktrees/pas8-convergence-20260924` |
| Middleware `main` | `0606b0db9ff59802f8da3824d209d2effc13f87d` |
| Kong `main` | `3e68cb2a4955bd71ddb3e839f4d9e3770465fc08` |
| Caddy `main` | `0feae8a493f54e5f32dfd1f63ba5c967aa5fbf90` |
| Route contract | `9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b`, 117 routes (105 shared_edge, 2 private_only, 10 denied) |
| Open Keycloak PRs | #115, #123 (PAS-158), #124, #125 |

### Preserved dirty state (primary checkout — untouched)

`Keycloak` @ `codex/keycloak-edge-certification-v2` / `c8b45ff`, 1 ahead / 13 behind
`origin/main`. There are 344 status entries:

* 327 tracked files differ only by CRLF line endings. There are no content changes.
* 1 tracked `.pyc` truncated to 0 bytes (`tests/__pycache__/test_provider_control_authority.cpython-310.pyc`).
* Real, unpushed `codestra-agent-desktop` work (mtime 2026-09-15):

| File | SHA-256 |
| --- | --- |
| `config/clients/codestra-agent-desktop.json` (untracked) | `db9298848502215b535a092b6a300fb78426472219d4979afeae42447ca485dc` |
| `config/contracts/agent-desktop-realtime-client.json` (untracked) | `251368e4e63c05762948c76d946a853981bd2e806fe09df5ba992ecd78b038d1` |
| `config/export-allowlists/codestra-agent-desktop.json` (untracked) | `32751906bad6fdeaeb71343498a1703a7cccf7be4c251206a14fe0f8f86d181f` |
| `config/policy/creatable-clients.json` (adds `codestra-agent-desktop`) | `602df049e4f6cd7f143a6d27ff829864aa52fd99842fbced3f9edbe6bc804e06` |
| `config/policy/managed-clients.json` (adds `codestra-agent-desktop`) | `602df049e4f6cd7f143a6d27ff829864aa52fd99842fbced3f9edbe6bc804e06` |

The frozen token policy lists `codestra-agent-desktop` in `protectedUngrantableClientIds`
with `dirtyDesktopAutoGrantAuthorized=false`. Integrating this work needs its own
reviewed PR. It must not be merged as a side effect of convergence.

## Lane 1 — merged-main trust root and release CI: BLOCKED (external)

* **GitHub Actions is billing-locked.** Every run since 2026-09-22 fails with "The job
  was not started because your account is locked due to a billing issue". This
  affects the daily PR-authority audit on `main` (runs 35713834069, 35846526394,
  35985315533) and the release-trust-root checks on PRs #123/#124/#125.
* Merged-main hosted CI (run before the lock): Validate Keycloak GitOps, Repository
  Name Authority and password-reset acceptance were all green on `45a487d`. The
  release trust root has no merged-main PASS. The last run on the final PR #118 head
  (`fc5265e`, run 35544257307) failed on missing exact-head independent approval.
* Local trust closure: `config/bootstrap/executable-closure.json` shows 13/13 digests
  matching in this worktree. No closure-pinned file (`validate.sh`, `validate.yml`,
  trust-root scripts) is modified, so this change set cannot trigger
  `BOOTSTRAP_REJECTED=source-digest`.
* Immutable release: the last `Release immutable Keycloak image` run (34298241691,
  2026-09-09) failed at "Verify separately reviewed source and publication intent".
  `release/intents/` holds only `keycloak-20260909.json`. There is no intent for `45a487d`.

## Lane 2 — freeze: PASS (repository)

Frozen, and enforced on every `scripts/validate.sh` run by
`tests/test_middleware_v3_freeze_certification.py`:

* Audience `middleware-api` for 113 routes, with exactly four explicit exceptions:
  `codestra-callback-api` (2 callback-ui routes) and `codestra-odoo` (2
  middleware-worker private_only routes).
* Issuer `https://auth.codestra.co/realms/codestra` (staging:
  `auth-staging.codestra.co`). Access-token lifetime is at most 300 s. Services use
  `client_credentials`. Humans use `authorization_code` with PKCE.
* Caller model: 18 selectors, 0 unknown callers, 84 `service-or-user-jwt` routes.
  Human and service boundary PASS.
* `platform.command`, `platform.command.read` and `platform.command.replay` are
  optional-only. They are never a realm or client default, and no client attaches them.
* `platform-operator`: non-composite, MFA required, independent approval required,
  `PREPARED_DISABLED`. It is required only by `POST /platform/v1/operations/{operation_id}/replay`.

The fix in this change set: Keycloak's edge desired state
(`config/desired-state/edge-integration-certification/*`) still pinned the old
92-route contract `7580123…`. The caller certifier therefore reported
`TARGET_ROUTE_CONTRACT_MATCH=PENDING_BASE_INTEGRATION`. That desired state is now
repinned to the Middleware-main 117-route contract. The regenerated
`canonical-service-authority.v2.json` widens no grant: still 21 route grants, one
`operation_id` rename (`ingress_odoo_event`), and `platform-command-client` is added
only to the *unresolved* selector list. The TEST_SYN edge contract routes and retired
paths are unchanged. The edge-certification plan was regenerated with
`--write`/`--check`.

## Lane 3 — cross-repo parity: PASS (static, read-only)

`scripts/certify_cross_repo_identity_parity.py` compared read-only exports of
Middleware, Kong and Caddy `main` (input SHA-256 values: Middleware contract
`0724a0c6…`, Kong authority `33ed6175…`, Caddy `sites/api.codestra.co.caddy`
`975df331…`):

```text
CROSS_REPO_IDENTITY_PARITY=PASS
ROUTE_CONTRACT_SHA256=9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b
ROUTE_COUNT=117
SHARED_EDGE_ROUTES=105
KEYCLOAK_EDGE_CONTRACT_MISMATCHES=0
KEYCLOAK_ACCESS_AUTHORITY_MISMATCHES=0
KONG_MISMATCHES=0
CADDY_MISMATCHES=0
```

Kong `main` now covers 105/105 shared_edge routes, with issuer, audience, scope, azp,
auth and operation all equal. Caddy `main` routes 105/105 shared_edge routes and 0
denied or private routes through its canonical method matchers, and `@kong` includes
`/platform/v1*`. **Both external blockers recorded by PR #123 (PAS-158 at Kong
`5ac254c` / Caddy `84c2b7b`) are resolved at current mains.** PR #123's verdict
`BLOCKED_CROSS_REPO_PARITY` is stale.

Observation: Kong still carries the legacy
`deploy/kong-production-standby/keycloak/codestra-api-audience.json` (audience
`codestra-api`). It is outside the V3 route authority, so it needs a Kong-owner
decision to retire it.

Re-run (read-only):

```bash
gh api 'repos/ingtrader21-spec/Middleware-/contents/deploy/public-api-route-contract.json?ref=main' --jq .content | base64 -d > mw.json
gh api 'repos/ingtrader21-spec/Kong/contents/config/kong-middleware-authority.v2.json?ref=main' --jq .content | base64 -d > kong.json
gh api 'repos/ingtrader21-spec/Caddy/contents/sites/api.codestra.co.caddy?ref=main' --jq .content | base64 -d > api.caddy
python3 scripts/certify_cross_repo_identity_parity.py --middleware-contract mw.json --kong-authority kong.json --caddy-site api.caddy
```

## Lane 4 — staging token matrix / TEST_SYN: PREPARED, NOT RUN

* `config/certification/v3-token-matrix.v1.json`: 8 dimensions, 8 positive and 8
  negative cases. `validate_v3_token_matrix.py` PASS.
* `edge_certification_desired_state.py --check --middleware-repo <Middleware main snapshot>`
  gives `EDGE_CONTRACT_CROSS_CHECK=PASS`.
* Not run because `auth-staging.codestra.co` and `auth.codestra.co` are unreachable
  from this host (TCP connect timeout, 2026-09-24), and no TEST_SYN client-secret
  files are provisioned here. The live run is
  `CERTIFY_ENVIRONMENT=staging CERTIFY_CAMPAIGN_ID=TEST_SYN CERTIFY_CLIENT_SECRET_FILE_<ROLE>=… python3 scripts/certify_edge_identity_staging.py --output <evidence>`,
  on the staging runner, after `reconcile_edge_certification_staging.py` plan review.

## Lane 5 — backup/restore, rotation and revocation: PREPARED, NOT RUN

* `scripts/test-backup-contract.sh` PASS (inside `validate.sh`). This is a contract
  test only.
* No real restore rehearsal was run. `age` is not installed on this host, and
  certification requires the staging or production-shaped database plus
  `verify-backup.sh` into an isolated restore DB. Targets are RPO 24 h and RTO 4 h
  (`docs/operations/BACKUP_RESTORE.md`).
* Rotation and revocation follow `docs/operations/SECRET_ROTATION.md`. No live secret
  was rotated. Revocation evidence needs the rotated credential to be rejected
  (401), which requires staging reachability.
* Note for operators: in a backgrounded shell with no closed stdin,
  `test-backup-contract.sh` hangs in its fake `pg_restore` (`cat`). Run
  `validate.sh </dev/null` in CI-like or background contexts.

## Lane 6 — immutable release and readback: BLOCKED

These depend on lane 1 (Actions billing) and on a separately reviewed release intent
for the exact certified SHA. `config/certification/activation-readback.json` covers
only `klyrow-portal`. **No readback contract exists yet for the V3 identity**
(platform scopes, `platform-operator`, middleware-api audience mappers), so
"production readback drift=0" cannot yet be measured for PAS-8.

## Tests run in this worktree (2026-09-24)

| Command | Result |
| --- | --- |
| `python3 -m pytest -q tests` | 257 passed, 340 subtests |
| `bash scripts/validate.sh </dev/null` | exit 0, `VALIDATION=PASS` (includes the 7 freeze tests) |
| `validate_middleware_api_access_v3.py` | PASS, 117 routes, missing scopes 0 |
| `validate_middleware_caller_classification.py --require-target-contract` | PASS, target match PASS, unknown 0 |
| `validate_v3_token_matrix.py` | PASS 8/8/8 |
| `edge_certification_desired_state.py --check --middleware-repo <snapshot>` | PASS, cross-check PASS |
| `certify_cross_repo_identity_parity.py` (current mains) | PASS, 0 mismatches |
| Executable-closure digest check | 13/13 match |

## Blockers

1. GitHub Actions account billing lock. **Owner action**: restore billing for
   `ingtrader21-spec`.
2. Exact-head independent approval / release trust root PASS on merged main. This is
   governance and needs a separate reviewer.
3. Staging identity plane unreachable from the agent host, and no TEST_SYN secrets here.
4. No V3 identity readback contract. There is also no release intent for the
   candidate SHA.
5. `codestra-agent-desktop` dirty work conflicts with the frozen "protected
   ungrantable" policy, so it needs an explicit decision.

## Next exact action

1. The owner restores GitHub Actions billing.
2. Push `worktree-pas8-convergence-20260924` and open a PR against `main` (the agent
   did not push). Obtain independent review, and require Validate Keycloak GitOps and
   Keycloak release trust root to PASS on the exact PR head.
3. Close or refresh PR #123 with the parity result above.
4. After merge, run PAS-159 staging: plan-only `reconcile_edge_certification_staging.py`,
   review, apply to staging only, then `certify_edge_identity_staging.py` for TEST_SYN.
