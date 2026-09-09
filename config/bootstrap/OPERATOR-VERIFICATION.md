# Protected-main operator verification

This is a read-only preparation path, not a replacement for the independently
required GitHub status. It must land through independent review before use.
The existing `keycloak-release-trust-root.yml` still runs candidate code and
must not be treated as independent validation authority.

`protected-candidate.json` proposes approval of the complete regular-file tree
at `8258715f8cb36970151606b1c299f832cf912e21`. Review the source changes as well
as this policy. Every file is bound by SHA-256, path, and executable mode; the
canonical policy is bound by SHA-256. This conservative full-tree inventory
covers executable dependencies without relying on a manually complete script
list. It does not claim to prove that dynamic execution is safe; runtime and
executable-dependency validation remain separate required checks.

The four trust-owned paths declared in the verifier are excluded from the
candidate policy to avoid self-referential hashes. They are instead required
to match protected main exactly, including file mode. The candidate cannot
update those paths to authorize its own changes. Other file additions,
deletions, byte changes, and mode changes require a separately reviewed policy
update on main. Symlinks, submodules, and noncanonical paths are rejected.

After independent merge, an authorized operator must:

1. Fetch protected main and the candidate commit into a trusted clone. Do not
   check out, install, import, or execute candidate code in the trusted checkout.
2. Create a clean detached worktree at the current protected main commit. Fetch
   the policy's reviewed source commit as well if it is not available locally.
3. From that clean worktree, run with the operator's existing `gh` login:

   ```sh
   python3 -I -B scripts/verify_protected_candidate.py \
     --pr 96 --candidate-sha <full-current-candidate-sha>
   ```

The command requires its own checkout to equal current protected main, verifies
branch protection and a clean checkout, compares the candidate with the trusted
policy, checks fresh independent approval from an eligible collaborator, requires
GitHub’s native exact-head review decision to be APPROVED with last-push
approval and stale-review protections enforced (including administrators), reads
all review-thread pages, rejects incomplete or unsuccessful checks, and rechecks
main and PR identities before returning. Git replacement objects are disabled.
It never prints credentials, executes candidate code, posts a status, merges,
publishes, or deploys. Tokens are handled by `gh`, not passed as command arguments.

An exact-head success here is only operator evidence. The output explicitly
records `INDEPENDENT_REQUIRED_STATUS_AUTHORITY=NOT_ESTABLISHED`. An approved
GitHub App or externally enforced workflow must still issue the required status
with independently verifiable provenance. Do not resolve the remaining trust
finding or merge PR96 merely because this preparation PR passes CI.

After reconciling PR96 with this maintenance PR, any changes outside the four
trust-owned paths (including source-binding refreshes) intentionally fail the
policy comparison. Prepare and independently review a new policy for those
bytes; do not silently regenerate the policy inside PR96.

GitHub performs the last-push actor comparison; commit author and committer
metadata are not substitutes for that identity. A missing native decision or
inaccessible protection evidence is a rejection, not an inferred approval. See
[GitHub’s protected-branch approval rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).
