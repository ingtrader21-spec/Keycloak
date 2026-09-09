# Independently reviewed manifest proposals

The active bootstrap manifest is `config/bootstrap/executable-closure.json`.
Files in this directory are proposals, not active policy or release authority.

PR #96's general CI passed at `93e6e7fc57a95940dd725b704e976be0710a44c4`,
but its bootstrap rejected a stale `scripts/validate-workflows.py` digest. The
proposal in this directory records every declared-file difference against the
protected-main policy at `e15e20088a529c4f8f9ac3cecb873f21e28e3ed3`, rather than
patching only the first reported failure.

Generate a fresh proposal from immutable Git objects:

```sh
python3 scripts/bootstrap_manifest.py \
  --policy-sha <full-protected-main-commit-sha> \
  --source-sha <full-reviewed-source-commit-sha> \
  --output config/bootstrap/proposals/<new-proposal-name>.json
```

The tool validates canonical paths, manifest structure and digest, reads only
regular tracked files from the specified commits, and computes deterministic
SHA-256 entries and a manifest digest. Dirty working-tree files cannot affect
its output. It does not run candidate code, contact GitHub, use credentials,
modify the active manifest, or overwrite an existing proposal.

Before activation:

1. Independently review the proposed file changes and their source commit. A
   manifest digest proves integrity, not approval or executable safety.
2. Land the reviewed policy through the separate protected-main maintenance PR.
   PR #96 must not establish its own trust anchor by changing source and policy
   together without that independent review.
3. Recompare every bound file with the final reconciled candidate. Review any
   additional changes; do not silently reuse stale hashes.
4. Have a trusted protected-main verifier consume the independently approved
   policy and require fresh exact-head CI, approval and resolved review threads.
   The existing PR-head checkout workflow is not an independent verifier and
   must not be reported as such merely because this proposal is approved.

This proposal preserves the existing declared file set. It does not establish
complete recursive executable closure, nor independently sourced status-check
authority. Those two PR #96 findings remain separate mandatory gates. The
current active manifest and workflow are intentionally unchanged by this PR.
