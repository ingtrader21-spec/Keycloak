#!/usr/bin/env python3
"""Audit every open Keycloak pull request against one immutable main SHA.

This script is intentionally read-only with respect to pull requests and Keycloak.
It writes only sanitized Markdown/JSON repository evidence for the caller to commit.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

REPOSITORY = os.environ["GITHUB_REPOSITORY"]
EXPECTED_MAIN_SHA = os.environ["EXPECTED_MAIN_SHA"]
TOKEN = os.environ["GITHUB_TOKEN"]
OWNER, NAME = REPOSITORY.split("/", 1)
API = "https://api.github.com"
GRAPHQL = "https://api.github.com/graphql"
REPORT_MD = Path("docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.md")
REPORT_JSON = Path("docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json")
SUCCESS_CONCLUSIONS = {"success", "neutral", "skipped"}
FAILURE_CONCLUSIONS = {
    "failure",
    "timed_out",
    "cancelled",
    "action_required",
    "startup_failure",
    "stale",
}


def request_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> Any:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {TOKEN}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "codestra-keycloak-open-pr-auditor",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"GitHub API {exc.code} for {url}: {detail}") from exc
    if not data:
        return None
    return json.loads(data.decode("utf-8"))


def api(path: str) -> Any:
    return request_json(f"{API}{path}")


def graphql(query: str, variables: dict[str, Any]) -> Any:
    result = request_json(
        GRAPHQL,
        method="POST",
        payload={"query": query, "variables": variables},
    )
    if result.get("errors"):
        messages = [str(item.get("message", "unknown GraphQL error")) for item in result["errors"]]
        raise RuntimeError("; ".join(messages))
    return result["data"]


def run_git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({completed.returncode}):\n{completed.stdout[:2000]}"
        )
    return completed


def count_unresolved_threads(number: int) -> tuple[int, str | None]:
    query = """
    query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          reviewThreads(first: 100, after: $cursor) {
            nodes { isResolved isOutdated }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
    """
    cursor: str | None = None
    unresolved = 0
    try:
        while True:
            data = graphql(
                query,
                {"owner": OWNER, "name": NAME, "number": number, "cursor": cursor},
            )
            threads = data["repository"]["pullRequest"]["reviewThreads"]
            unresolved += sum(
                1
                for node in threads["nodes"]
                if not node["isResolved"] and not node["isOutdated"]
            )
            page = threads["pageInfo"]
            if not page["hasNextPage"]:
                return unresolved, None
            cursor = page["endCursor"]
    except Exception as exc:  # fail closed while still producing evidence
        return -1, str(exc)


def exact_head_review_state(number: int, head_sha: str) -> dict[str, Any]:
    reviews = api(f"/repos/{REPOSITORY}/pulls/{number}/reviews?per_page=100")
    latest: dict[str, dict[str, Any]] = {}
    for review in reviews:
        login = ((review.get("user") or {}).get("login") or "").casefold()
        if not login or review.get("commit_id") != head_sha:
            continue
        prior = latest.get(login)
        if prior is None or (review.get("submitted_at") or "") >= (prior.get("submitted_at") or ""):
            latest[login] = review
    states = {login: review.get("state") for login, review in sorted(latest.items())}
    approved = sorted(login for login, state in states.items() if state == "APPROVED")
    changes_requested = sorted(
        login for login, state in states.items() if state == "CHANGES_REQUESTED"
    )
    return {
        "states": states,
        "approved_reviewers": approved,
        "changes_requested_by": changes_requested,
        "required_reviewer_approved": "kazan555" in approved,
    }


def exact_head_checks(head_sha: str) -> dict[str, Any]:
    check_document = api(f"/repos/{REPOSITORY}/commits/{head_sha}/check-runs?per_page=100")
    checks = check_document.get("check_runs", [])
    status_document = api(f"/repos/{REPOSITORY}/commits/{head_sha}/status")
    statuses = status_document.get("statuses", [])

    normalized: list[dict[str, str | None]] = []
    for item in checks:
        normalized.append(
            {
                "name": item.get("name"),
                "status": item.get("status"),
                "conclusion": item.get("conclusion"),
                "source": "check-run",
            }
        )
    for item in statuses:
        state = item.get("state")
        normalized.append(
            {
                "name": item.get("context"),
                "status": "completed" if state in {"success", "failure", "error"} else "in_progress",
                "conclusion": "success" if state == "success" else ("failure" if state in {"failure", "error"} else None),
                "source": "commit-status",
            }
        )

    failures = [
        item["name"]
        for item in normalized
        if item.get("conclusion") in FAILURE_CONCLUSIONS
    ]
    pending = [
        item["name"]
        for item in normalized
        if item.get("status") != "completed" or item.get("conclusion") is None
    ]
    successes = [
        item["name"]
        for item in normalized
        if item.get("status") == "completed"
        and item.get("conclusion") in SUCCESS_CONCLUSIONS
    ]
    green = bool(normalized) and not failures and not pending
    return {
        "green": green,
        "total": len(normalized),
        "successes": sorted(set(filter(None, successes))),
        "pending": sorted(set(filter(None, pending))),
        "failures": sorted(set(filter(None, failures))),
    }


def analyze_git(number: int, head_sha: str) -> dict[str, Any]:
    ref = f"refs/remotes/pull/{number}"
    run_git("fetch", "--no-tags", "origin", f"pull/{number}/head:{ref}")
    actual = run_git("rev-parse", ref).stdout.strip()
    if actual != head_sha:
        raise RuntimeError(f"PR #{number} head moved during audit: expected {head_sha}, fetched {actual}")

    merge_base = run_git("merge-base", EXPECTED_MAIN_SHA, head_sha).stdout.strip()
    behind = int(run_git("rev-list", "--count", f"{head_sha}..{EXPECTED_MAIN_SHA}").stdout.strip())
    ahead = int(run_git("rev-list", "--count", f"{EXPECTED_MAIN_SHA}..{head_sha}").stdout.strip())
    paths = [
        value
        for value in run_git(
            "diff", "--name-only", "-z", f"{EXPECTED_MAIN_SHA}...{head_sha}"
        ).stdout.split("\0")
        if value
    ]

    cherry_lines = [
        line.strip()
        for line in run_git("cherry", EXPECTED_MAIN_SHA, head_sha).stdout.splitlines()
        if line.strip()
    ]
    unique_patch_commits = [line[2:] for line in cherry_lines if line.startswith("+")]
    equivalent_patch_commits = [line[2:] for line in cherry_lines if line.startswith("-")]
    patch_equivalent = bool(cherry_lines) and not unique_patch_commits

    merge = run_git(
        "merge-tree",
        "--write-tree",
        "--messages",
        EXPECTED_MAIN_SHA,
        head_sha,
        check=False,
    )
    conflict_paths = sorted(
        set(
            match.group(1).strip()
            for match in re.finditer(r"CONFLICT .*? in (.+)$", merge.stdout, re.MULTILINE)
        )
    )
    merge_clean = merge.returncode == 0
    merge_tree = merge.stdout.splitlines()[0].strip() if merge_clean and merge.stdout else None

    return {
        "merge_base": merge_base,
        "ahead_by": ahead,
        "behind_by": behind,
        "changed_paths": sorted(paths),
        "changed_path_count": len(paths),
        "patch_equivalent_to_main": patch_equivalent,
        "equivalent_patch_commits": equivalent_patch_commits,
        "unique_patch_commits": unique_patch_commits,
        "merge_clean": merge_clean,
        "merge_tree": merge_tree,
        "conflict_paths": conflict_paths,
        "merge_tree_diagnostic": None if merge_clean else merge.stdout[-4000:],
    }


def decision_for(item: dict[str, Any]) -> str:
    git = item["git"]
    checks = item["checks"]
    reviews = item["reviews"]
    unresolved = item["unresolved_threads"]
    if item["head_sha"] == EXPECTED_MAIN_SHA or git["changed_path_count"] == 0:
        return "CLOSE_NO_PAYLOAD"
    if git["patch_equivalent_to_main"]:
        return "CLOSE_SUPERSEDED_BY_MAIN"
    if item["draft"]:
        return "DRAFT_REWORK_REQUIRED" if not git["merge_clean"] else "DRAFT_REBASE_CANDIDATE"
    if not git["merge_clean"]:
        return "CONFLICT_REMEDIATION_REQUIRED"
    if (
        checks["green"]
        and reviews["required_reviewer_approved"]
        and not reviews["changes_requested_by"]
        and unresolved == 0
        and item.get("mergeable") is not False
    ):
        return "EXACT_HEAD_GATES_PASS_REBASE_REQUIRED"
    return "CLEAN_REBASE_GATES_PENDING"


def markdown(report: dict[str, Any]) -> str:
    rows = []
    for item in report["pull_requests"]:
        rows.append(
            "| #{number} | {draft} | `{head}` | {behind} | {paths} | {merge} | {checks} | {approval} | {threads} | **{decision}** |".format(
                number=item["number"],
                draft="yes" if item["draft"] else "no",
                head=item["head_ref"],
                behind=item["git"]["behind_by"],
                paths=item["git"]["changed_path_count"],
                merge="clean" if item["git"]["merge_clean"] else "conflict",
                checks="green" if item["checks"]["green"] else (
                    "failed" if item["checks"]["failures"] else "pending/absent"
                ),
                approval="yes" if item["reviews"]["required_reviewer_approved"] else "no",
                threads=("unknown" if item["unresolved_threads"] < 0 else item["unresolved_threads"]),
                decision=item["decision"],
            )
        )

    details: list[str] = []
    for item in report["pull_requests"]:
        details.extend(
            [
                f"### PR #{item['number']} — {item['title']}",
                "",
                f"- Exact head: `{item['head_sha']}`",
                f"- Base recorded by GitHub: `{item['base_ref']}@{item['base_sha']}`",
                f"- Current-main divergence: `{item['git']['ahead_by']}` unique commits ahead, `{item['git']['behind_by']}` commits behind",
                f"- Merge simulation: `{'PASS' if item['git']['merge_clean'] else 'CONFLICT'}`",
                f"- Exact-head checks: successes `{len(item['checks']['successes'])}`, pending `{len(item['checks']['pending'])}`, failures `{len(item['checks']['failures'])}`",
                f"- Exact-head approval by `kazan555`: `{'YES' if item['reviews']['required_reviewer_approved'] else 'NO'}`",
                f"- Active unresolved review threads: `{item['unresolved_threads'] if item['unresolved_threads'] >= 0 else 'UNKNOWN'}`",
                f"- Decision: **{item['decision']}**",
                "",
                "Changed paths:",
                "",
                *( [f"- `{path}`" for path in item['git']['changed_paths']] or ["- none"] ),
            ]
        )
        if item["git"]["conflict_paths"]:
            details.extend(["", "Conflict paths:", ""])
            details.extend(f"- `{path}`" for path in item["git"]["conflict_paths"])
        if item["checks"]["failures"]:
            details.extend(["", "Failed checks:", ""])
            details.extend(f"- `{name}`" for name in item["checks"]["failures"])
        if item["checks"]["pending"]:
            details.extend(["", "Pending or incomplete checks:", ""])
            details.extend(f"- `{name}`" for name in item["checks"]["pending"])
        if item["thread_query_error"]:
            details.extend(["", f"Thread query error: `{item['thread_query_error']}`"])
        details.append("")

    counts = report["decision_counts"]
    return "\n".join(
        [
            "# Keycloak open pull-request reconciliation — 2026-09-03",
            "",
            f"Repository: `{report['repository']}`  ",
            f"Immutable current-main authority: `{report['expected_main_sha']}`  ",
            f"Audited at: `{report['generated_at']}`",
            "",
            "This is a source-only audit. It did not contact a Keycloak runtime, read a secret, issue a token, change SSH/DNS, deploy, or merge a pull request.",
            "",
            "## Summary",
            "",
            f"- Open pull requests audited: **{len(report['pull_requests'])}**",
            *[f"- `{name}`: **{count}**" for name, count in sorted(counts.items())],
            "",
            "## Exact-head matrix",
            "",
            "| PR | Draft | Head branch | Behind main | Paths | Merge | Checks | Approval | Threads | Decision |",
            "|---:|:---:|---|---:|---:|:---:|:---:|:---:|---:|---|",
            *rows,
            "",
            "## Decision semantics",
            "",
            "- `CLOSE_NO_PAYLOAD`: no remaining diff against the immutable main authority.",
            "- `CLOSE_SUPERSEDED_BY_MAIN`: every unique patch is already represented on main.",
            "- `DRAFT_REBASE_CANDIDATE`: unique draft payload merges cleanly but remains intentionally blocked.",
            "- `DRAFT_REWORK_REQUIRED`: draft payload conflicts with current main and needs a clean replacement branch.",
            "- `CONFLICT_REMEDIATION_REQUIRED`: non-draft payload conflicts and must not be merged or force-rebased blindly.",
            "- `CLEAN_REBASE_GATES_PENDING`: payload merges cleanly, but exact-head review/check gates are incomplete.",
            "- `EXACT_HEAD_GATES_PASS_REBASE_REQUIRED`: visible gates pass, but the stale branch still must be recreated on current main and revalidated.",
            "",
            "## Pull-request details",
            "",
            *details,
            "## Safety",
            "",
            "```text",
            "KEYCLOAK_RUNTIME_CONTACTED=false",
            "KEYCLOAK_RUNTIME_APPLY=false",
            "SECRETS_READ=0",
            "TOKENS_ISSUED=0",
            "PRS_MERGED=0",
            "SSH_CHANGED=false",
            "PRODUCTION_CHANGED=false",
            "```",
            "",
        ]
    )


def main() -> int:
    actual_main = run_git("rev-parse", "origin/main").stdout.strip()
    if actual_main != EXPECTED_MAIN_SHA:
        raise RuntimeError(
            f"main moved before audit: expected {EXPECTED_MAIN_SHA}, actual {actual_main}"
        )

    pulls = api(f"/repos/{REPOSITORY}/pulls?state=open&per_page=100&sort=updated&direction=desc")
    results: list[dict[str, Any]] = []
    for summary in pulls:
        number = int(summary["number"])
        detail = api(f"/repos/{REPOSITORY}/pulls/{number}")
        head_sha = detail["head"]["sha"]
        thread_count, thread_error = count_unresolved_threads(number)
        item = {
            "number": number,
            "title": detail["title"],
            "url": detail["html_url"],
            "draft": bool(detail.get("draft")),
            "state": detail["state"],
            "mergeable": detail.get("mergeable"),
            "mergeable_state": detail.get("mergeable_state"),
            "head_ref": detail["head"]["ref"],
            "head_sha": head_sha,
            "base_ref": detail["base"]["ref"],
            "base_sha": detail["base"]["sha"],
            "reviews": exact_head_review_state(number, head_sha),
            "checks": exact_head_checks(head_sha),
            "unresolved_threads": thread_count,
            "thread_query_error": thread_error,
            "git": analyze_git(number, head_sha),
        }
        item["decision"] = decision_for(item)
        results.append(item)
        print(
            f"PR={number} DECISION={item['decision']} HEAD={head_sha} "
            f"BEHIND={item['git']['behind_by']} MERGE_CLEAN={item['git']['merge_clean']}"
        )

    results.sort(key=lambda item: item["number"], reverse=True)
    decision_counts: dict[str, int] = defaultdict(int)
    for item in results:
        decision_counts[item["decision"]] += 1

    report = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "expected_main_sha": EXPECTED_MAIN_SHA,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "decision_counts": dict(sorted(decision_counts.items())),
        "pull_requests": results,
        "safety": {
            "keycloak_runtime_contacted": False,
            "keycloak_runtime_apply": False,
            "secrets_read": 0,
            "tokens_issued": 0,
            "prs_merged": 0,
            "ssh_changed": False,
            "production_changed": False,
        },
    }
    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    REPORT_MD.write_text(markdown(report), encoding="utf-8")
    print(f"KEYCLOAK_OPEN_PR_AUDIT=PASS COUNT={len(results)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"KEYCLOAK_OPEN_PR_AUDIT=FAIL ERROR={exc}", file=sys.stderr)
        raise
