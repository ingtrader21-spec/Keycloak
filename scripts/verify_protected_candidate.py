#!/usr/bin/env python3
"""Read-only operator verification using code and policy from protected main.

Candidate Git objects are data only. This command neither executes candidate
code nor publishes a status, merges a PR, or grants release authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "appolon1908-hue/Keycloak"
POLICY = "config/bootstrap/protected-candidate.json"
TRUST_FILES = frozenset({
    POLICY, "scripts/verify_protected_candidate.py",
    "tests/test_verify_protected_candidate.py", "config/bootstrap/OPERATOR-VERIFICATION.md",
})
SCHEMA = "keycloak.protected-candidate.v1"
REQUIRED_CHECKS = frozenset({
    "validate", "validate-source", "validate-merge-result", "orchestrator-contract",
    "repository-name-authority", "validate-source-e2e", "validate-merge-result-e2e",
})


class Rejected(ValueError):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise Rejected(message)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(root), *args], stderr=subprocess.DEVNULL,
    )


def snapshot(root: Path, sha: str) -> list[dict[str, str]]:
    require(re.fullmatch(r"[0-9a-f]{40}", sha), "full-commit-sha-required")
    require(git(root, "cat-file", "-t", sha).strip() == b"commit", "commit-required")
    files = []
    for record in git(root, "ls-tree", "-rz", "--full-tree", sha).split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8")
        require(mode in {"100644", "100755"} and kind == "blob", "non-regular-source")
        require(path and "\\" not in path and all(ord(c) >= 32 and ord(c) != 127 for c in path)
                and all(p not in {"", ".", "..", ".git"} for p in path.split("/")), "unsafe-source-path")
        files.append({"path": path, "mode": mode,
                      "sha256": hashlib.sha256(git(root, "cat-file", "blob", oid)).hexdigest()})
    return sorted(files, key=lambda item: item["path"])


def make_policy(root: Path, sha: str) -> dict:
    payload = {"schema": SCHEMA, "reviewed_source_sha": sha,
               "files": [f for f in snapshot(root, sha) if f["path"] not in TRUST_FILES]}
    return {**payload, "manifest_sha256": hashlib.sha256(canonical(payload)).hexdigest()}


def verify_source(root: Path, main_sha: str, candidate_sha: str, policy: dict) -> None:
    require(isinstance(policy, dict) and set(policy) == {
        "schema", "reviewed_source_sha", "files", "manifest_sha256"}, "policy-fields")
    # Reconstruct from the pinned reviewed commit, not candidate declarations.
    require(policy == make_policy(root, policy["reviewed_source_sha"]), "policy-binding")
    main_files = {f["path"]: f for f in snapshot(root, main_sha)}
    candidate = snapshot(root, candidate_sha)
    candidate_files = {f["path"]: f for f in candidate}
    for path in TRUST_FILES:
        require(path in main_files and candidate_files.get(path) == main_files[path], "candidate-trust-root-change")
    require([f for f in candidate if f["path"] not in TRUST_FILES] == policy["files"], "unreviewed-source-change")


def api(endpoint: str) -> object:
    # gh keeps credentials out of argv and output; no candidate-controlled endpoint.
    return json.loads(subprocess.check_output(["gh", "api", endpoint], stderr=subprocess.DEVNULL))


def pages(endpoint: str) -> list:
    result = []
    for page in range(1, 101):
        batch = api(f"{endpoint}?per_page=100&page={page}")
        require(isinstance(batch, list), "invalid-api-page")
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise Rejected("pagination-limit")


def verify_reviews(pr: int, sha: str, author: str) -> None:
    latest = {}
    for review in pages(f"repos/{REPOSITORY}/pulls/{pr}/reviews"):
        require(isinstance(review, dict) and isinstance(review.get("user"), dict), "invalid-review")
        if review.get("state") not in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            continue
        login = review["user"].get("login")
        require(isinstance(login, str) and re.fullmatch(r"[A-Za-z0-9-]+", login), "invalid-reviewer")
        if review.get("state") in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            latest[login] = review
    approved = False
    for login, review in latest.items():
        if login == author or review.get("commit_id") != sha or review.get("state") != "APPROVED":
            continue
        permission = api(f"repos/{REPOSITORY}/collaborators/{login}/permission")
        if isinstance(permission, dict) and permission.get("permission") in {"admin", "write", "maintain"}:
            approved = True
    require(approved, "missing-independent-exact-head-approval")


def verify_threads(pr: int) -> None:
    cursor = None
    seen = set()
    for _ in range(100):
        query = ('query($cursor:String){repository(owner:"appolon1908-hue",name:"Keycloak")'
                 '{pullRequest(number:' + str(pr) + '){reviewThreads(first:100,after:$cursor)'
                 '{nodes{isResolved}pageInfo{hasNextPage endCursor}}}}}')
        response = json.loads(subprocess.check_output(
            ["gh", "api", "graphql", "--input", "-"],
            input=canonical({"query": query, "variables": {"cursor": cursor}}), stderr=subprocess.DEVNULL))
        require(isinstance(response, dict) and not response.get("errors"), "thread-api-error")
        try:
            connection = response["data"]["repository"]["pullRequest"]["reviewThreads"]
            nodes, info = connection["nodes"], connection["pageInfo"]
            require(isinstance(nodes, list) and all(isinstance(n, dict) and n.get("isResolved") is True for n in nodes),
                    "unresolved-or-invalid-thread")
            require(type(info["hasNextPage"]) is bool, "thread-pagination-invalid")
            if not info["hasNextPage"]:
                return
            cursor = info["endCursor"]
            require(isinstance(cursor, str) and cursor and cursor not in seen, "thread-pagination-invalid")
            seen.add(cursor)
        except (KeyError, TypeError):
            raise Rejected("thread-evidence-missing") from None
    raise Rejected("thread-pagination-limit")


def verify_checks(sha: str) -> None:
    checks = []
    for page in range(1, 101):
        response = api(f"repos/{REPOSITORY}/commits/{sha}/check-runs?per_page=100&page={page}")
        require(isinstance(response, dict) and isinstance(response.get("check_runs"), list), "check-evidence-invalid")
        batch = response["check_runs"]
        checks.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise Rejected("check-pagination-limit")
    latest = {}
    for check in checks:
        require(isinstance(check, dict) and type(check.get("id")) is int
                and isinstance(check.get("name"), str), "check-evidence-invalid")
        name = check["name"]
        if name not in latest or check["id"] > latest[name]["id"]:
            latest[name] = check
    require(REQUIRED_CHECKS <= latest.keys(), "required-check-missing")
    for check in latest.values():
        require(check.get("head_sha") == sha and check.get("status") == "completed"
                and check.get("conclusion") == "success", "check-not-success")
    # These checks remain supplementary; their common Actions App identity does
    # not prove an independently enforced workflow origin.


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--candidate-sha", required=True)
    args = parser.parse_args()
    try:
        require(args.pr > 0, "invalid-pr")
        main_branch = api(f"repos/{REPOSITORY}/branches/main")
        require(main_branch.get("protected") is True, "main-not-protected")
        main_sha = main_branch["commit"]["sha"]
        require(git(ROOT, "rev-parse", "HEAD").decode().strip() == main_sha, "run-from-current-protected-main")
        require(not git(ROOT, "status", "--porcelain", "--untracked-files=all"), "dirty-trusted-checkout")
        pull = api(f"repos/{REPOSITORY}/pulls/{args.pr}")
        require(pull["state"] == "open" and pull["base"]["ref"] == "main"
                and pull["head"]["sha"] == args.candidate_sha, "stale-or-invalid-pr")
        policy = json.loads((ROOT / POLICY).read_text())
        verify_source(ROOT, main_sha, args.candidate_sha, policy)
        verify_reviews(args.pr, args.candidate_sha, pull["user"]["login"])
        verify_threads(args.pr)
        verify_checks(args.candidate_sha)
        require(api(f"repos/{REPOSITORY}/pulls/{args.pr}")["head"]["sha"] == args.candidate_sha, "head-changed-during-verification")
        require(api(f"repos/{REPOSITORY}/branches/main")["commit"]["sha"] == main_sha, "main-changed-during-verification")
        print(f"PROTECTED_MAIN_SHA={main_sha}\nCANDIDATE_SHA={args.candidate_sha}")
        print(f"CANDIDATE_MANIFEST_SHA256={policy['manifest_sha256']}")
        print("OPERATOR_SOURCE_AND_REVIEW_VERIFICATION=PASS")
        print("INDEPENDENT_REQUIRED_STATUS_AUTHORITY=NOT_ESTABLISHED")
        return 0
    except (Rejected, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        print(f"PROTECTED_CANDIDATE_REJECTED={exc if isinstance(exc, Rejected) else type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
