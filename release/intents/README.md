# Repository-reviewed image publication

Environment reviewer protection is unavailable on the current billing plan. This gate does not change main protection or authorize deployment.

1. Merge source only after required CI, independent exact-head review, last-push approval and resolution of all review threads.
2. In a separate PR, add a JSON intent naming that reachable source SHA and tree, repository, image_repository, schema `reviewed-image-publication/v1`, and booleans publish_image=true, deploy_production=false, external_effects=false, sbom_required=true, provenance_required=true. Do not include secret values.
3. Independently review and merge the intent PR. It must pass all required CI and resolve all threads; the author/last committer cannot supply its independent approval.
4. Compute SHA256 of JSON serialized with sorted keys and compact separators. Dispatch only from the current protected main, supplying the intent path, exact source SHA and plan hash.
5. The verifier checks live non-bypassable branch policy, both merged PRs, independent approvals on their exact heads, CI success, review threads, source ancestry/tree and plan hash before registry authentication or build.
6. Publishing a candidate requires tests, scans, SBOM/provenance and immutable tags. Production use requires a later independent approval of the exact resulting digest and recovery evidence. Nothing here deploys.

No executable publication intent is supplied in this PR. A malformed, missing, stale or unreviewed intent fails closed. Release workflows remain disabled in the scraper repository until the gate itself is reviewed on protected main. Read-only CI can be enabled separately.
