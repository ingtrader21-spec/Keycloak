# Independent validation bootstrap — inactive proposal

PR #96 must not establish its own validation authority by changing its validator,
closure manifest and reciprocal fingerprints together. This proposal is based on
protected main and does not import PR #96 code.

`verify.py` runs only from the exact protected base commit on
`pull_request_target`. It reads candidate Git objects through GET requests,
checks their Git object identities, and computes a deterministic SHA-256 manifest
of every regular tracked file. It never checks out, imports or executes candidate
code. Paths that escape the repository, symlinks and gitlinks are rejected.
Changes to `.github/trust-root/` or this workflow are rejected for candidates.

The approval policy is deliberately empty. No source observation can pass until
a separate independently reviewed main change binds an approved source manifest
and the dedicated GitHub App identity. A successful source observation still
contains `merge_authorized: false`.

## Activation prerequisites

1. Independently review this bootstrap PR and require successful CI and zero
   unresolved threads. Do not bypass existing required checks to merge it.
   Protected main currently requires `orchestrator-contract`; the bootstrap's
   `trust-bootstrap-tests` deliberately does not impersonate that check. The
   bootstrap merge path must preserve and satisfy that existing requirement.
2. Provision an approved, separately administered GitHub App. Configure the
   required `keycloak-independent-source-authority` check with that App as its
   expected source. A plain check name from GitHub Actions is insufficient.
   This proposal neither provisions the App nor changes branch protection.
3. Implement and independently review the App's publisher. Before it issues
   success it must authenticate the trusted workflow/run, verify its immutable
   workflow identity and protected base, match repository, PR, current head and
   manifest digest, and verify current required-check policy. Never trust an
   arbitrary uploaded artifact, PR comment or same-named Actions check. Recheck
   head/base immediately before issuing a status. The publisher is not included
   in this initial proposal; no authority is claimed without it.
4. After the bootstrap lands, reconcile PR #96 onto main without changing any
   trust files. Complete its runtime and executable-closure findings. Independently
   review a canonical candidate source manifest in a separate trust-policy PR.
   Configure `required_check_app_id`, `approved_manifest_sha256` and
   `approved-source.json` only through that reviewed update. The same external
   authority must separately authenticate bootstrap updates; they cannot approve
   themselves through a candidate status.
5. Require fresh CI, independent exact-head review, zero unresolved threads and
   the App-bound authority check before PR #96 can merge. Preserve the full
   production orchestrator checks. This observation workflow does not replace
   their runtime or executable dependency analysis.

`python3 .github/trust-root/verify.py --snapshot <full-commit-sha>` prepares a
candidate manifest from local Git objects. Its output is a proposal, not approval.
The entire tracked-source snapshot conservatively includes executable files but
**does not prove recursive executable dependency resolution or reject dynamic
execution**. PR #96 finding D remains a separate mandatory gate.

No credentials belong in this directory, an artifact, or a review comment. The
workflow has read-only repository/PR permissions and no deployment, publication,
production runtime or SSH authority. Empty policy failures are intentional.
