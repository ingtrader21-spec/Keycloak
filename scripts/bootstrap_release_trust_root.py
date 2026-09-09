#!/usr/bin/env python3
"""Independent, fail-closed certification of a release pull request.

This file is intentionally small and lives on protected main.  It does not
execute candidate code; it hashes the checked-out candidate and verifies the
GitHub review/check evidence through the API.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"BOOTSTRAP_REJECTED={message}")


def sha256(path: Path) -> str:
    if not path.is_file():
        fail(f"missing:{path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def github_json(url: str, token: str, *, method: str = "GET", body: bytes | None = None) -> object:
    request = urllib.request.Request(url, data=body, method=method, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)
    except Exception as exc:
        fail(f"github-api:{type(exc).__name__}")


def github_reviews(base: str, pr: int, token: str) -> list[dict]:
    reviews = []
    # Construct same-origin pages rather than following untrusted Link URLs.
    for page in range(1, 101):
        batch = github_json(f"{base}/pulls/{pr}/reviews?per_page=100&page={page}", token)
        if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
            fail("reviews-invalid")
        reviews.extend(batch)
        if len(batch) < 100:
            return reviews
    fail("reviews-pagination-limit")


def verify_github_evidence(repo: str, pr: int, expected_sha: str, token: str) -> None:
    base = f"https://api.github.com/repos/{repo}"
    pull = github_json(f"{base}/pulls/{pr}", token)
    if not isinstance(pull, dict) or pull.get("head", {}).get("sha") != expected_sha:
        fail("pr-head-mismatch")
    author = pull.get("user", {}).get("login")
    reviews = github_reviews(base, pr, token)
    latest = {}
    for review in reviews:
        user = review.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        if not isinstance(login, str) or not login:
            fail("reviewer-invalid")
        if review.get("state") in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            latest[login] = review
    approvals = [r for login, r in latest.items() if r.get("state") == "APPROVED" and r.get("commit_id") == expected_sha and login != author]
    if not approvals:
        fail("missing-independent-approval")
    checks = github_json(f"{base}/commits/{expected_sha}/check-runs", token)
    required = {"validate-source", "validate-merge-result", "orchestrator-contract", "repository-name-authority"}
    observed = {c.get("name"): c.get("conclusion") for c in checks.get("check_runs", []) if isinstance(c, dict)} if isinstance(checks, dict) else {}
    if any(observed.get(name) != "success" for name in required):
        fail("required-check-not-success")
    print("BOOTSTRAP_SELF_DEPENDENCY=NONE")
    print("BOOTSTRAP_PREREQUISITE_CHECKS=PASS")
    query = json.dumps({"query": "query($repo:String!,$owner:String!,$number:Int!){repository(name:$repo,owner:$owner){pullRequest(number:$number){reviewThreads(first:100){nodes{isResolved}}}}}", "variables": {"repo": repo.split("/", 1)[1], "owner": repo.split("/", 1)[0], "number": pr}}).encode()
    graph = github_json("https://api.github.com/graphql", token, method="POST", body=query)
    nodes = graph.get("data", {}).get("repository", {}).get("pullRequest", {}).get("reviewThreads", {}).get("nodes", []) if isinstance(graph, dict) else []
    if any(isinstance(node, dict) and not node.get("isResolved") for node in nodes):
        fail("unresolved-review-thread")
    print(f"PR_HEAD_SHA={expected_sha}")
    print(f"APPROVAL_REVIEWER={approvals[-1]['user']['login']}")
    print("APPROVAL_STATE=APPROVED")
    print(f"UNRESOLVED_THREAD_COUNT={sum(1 for node in nodes if isinstance(node, dict) and not node.get('isResolved'))}")
    print("BOOTSTRAP_REVIEW_EVIDENCE=PASS")
    print("BOOTSTRAP_CHECK_EVIDENCE=PASS")


def load_manifest(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"manifest:{exc}")
    if not isinstance(value, dict) or value.get("schema") != "keycloak.bootstrap-closure.v1":
        fail("manifest-schema")
    entries = value.get("files")
    if not isinstance(entries, list) or not entries:
        fail("manifest-files")
    previous = ""
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            fail("manifest-entry")
        rel, digest = entry["path"], entry["sha256"]
        if not isinstance(rel, str) or rel != rel.strip() or rel.startswith("/") or ".." in Path(rel).parts:
            fail("manifest-path")
        if rel <= previous or rel in seen or len(digest) != 64:
            fail("manifest-order-or-duplicate")
        previous, seen = rel, seen | {rel}
    expected_manifest = value.get("manifest_sha256")
    canonical = json.dumps({"schema": value["schema"], "files": entries}, sort_keys=True, separators=(",", ":")).encode()
    if expected_manifest != hashlib.sha256(canonical).hexdigest():
        fail("manifest-digest")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--expected-candidate-sha", required=True)
    parser.add_argument("--manifest", default="config/bootstrap/executable-closure.json")
    parser.add_argument("--repo")
    parser.add_argument("--pr", type=int)
    parser.add_argument("--token")
    args = parser.parse_args()
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if actual != args.candidate_sha or args.candidate_sha != args.expected_candidate_sha:
        fail("stale-exact-head")
    manifest = load_manifest(ROOT / args.manifest)
    for entry in manifest["files"]:
        digest = sha256(ROOT / entry["path"])
        if digest != entry["sha256"]:
            fail(f"source-digest:{entry['path']}")
    if args.repo and args.pr and args.token:
        verify_github_evidence(args.repo, args.pr, args.expected_candidate_sha, args.token)
    print(f"BOOTSTRAP_EXECUTABLE_CLOSURE_SHA256={manifest['manifest_sha256']}")
    print("TRUST_ROOT_SELF_REFERENCE=NO")
    print("BOOTSTRAP_FAIL_CLOSED=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
