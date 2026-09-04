#!/usr/bin/env python3
"""Produce a fail-closed, read-only audit of open Keycloak pull requests."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

API = "https://api.github.com"
GRAPHQL = "https://api.github.com/graphql"
FAILURE_CONCLUSIONS = frozenset(
    {"action_required", "cancelled", "failure", "startup_failure", "stale", "timed_out"}
)
PENDING_STATUSES = frozenset({"queued", "in_progress", "pending", "requested", "waiting"})
SUCCESS_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})
PROTECTED_SEQUENCE = ("development", "test", "staging", "production", "main")
TEMPORARY_PREFIXES = (
    "remediation/",
    "security/",
    "upgrade/",
    "hotfix/",
    "sync/",
)


class AuditError(RuntimeError):
    """Raised when exact-head evidence is absent, malformed or contradictory."""


def fail(message: str) -> NoReturn:
    raise AuditError(message)


def request_json(
    url: str,
    *,
    token: str,
    method: str = "GET",
    body: Mapping[str, Any] | None = None,
) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "codestra-keycloak-pr-audit",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(url, headers=headers, data=data, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        fail(f"GitHub API request failed: HTTP {exc.code}: {detail}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        fail(f"GitHub API request failed: {exc}")


def rest_pages(path: str, *, token: str, parameters: Mapping[str, str] | None = None) -> list[Any]:
    output: list[Any] = []
    page = 1
    while True:
        query = dict(parameters or {})
        query.update({"per_page": "100", "page": str(page)})
        url = f"{API}{path}?{urllib.parse.urlencode(query)}"
        payload = request_json(url, token=token)
        if not isinstance(payload, list):
            fail(f"expected a list response from {path}")
        output.extend(payload)
        if len(payload) < 100:
            return output
        page += 1


def check_runs(repository: str, sha: str, *, token: str) -> list[dict[str, Any]]:
    page = 1
    runs: list[dict[str, Any]] = []
    while True:
        url = f"{API}/repos/{repository}/commits/{sha}/check-runs?per_page=100&page={page}"
        payload = request_json(url, token=token)
        if not isinstance(payload, Mapping) or not isinstance(payload.get("check_runs"), list):
            fail("malformed check-runs response")
        batch = payload["check_runs"]
        for run in batch:
            if not isinstance(run, Mapping):
                fail("malformed check run")
            runs.append(
                {
                    "name": run.get("name"),
                    "status": run.get("status"),
                    "conclusion": run.get("conclusion"),
                    "head_sha": run.get("head_sha"),
                    "url": run.get("html_url"),
                }
            )
        if len(batch) < 100:
            break
        page += 1
    return runs


THREAD_QUERY = """
query($owner:String!, $name:String!, $number:Int!, $cursor:String) {
  repository(owner:$owner, name:$name) {
    pullRequest(number:$number) {
      reviewDecision
      reviewThreads(first:100, after:$cursor) {
        nodes { id isResolved isOutdated path line }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""


def review_threads(owner: str, name: str, number: int, *, token: str) -> tuple[str | None, list[dict[str, Any]]]:
    cursor: str | None = None
    decision: str | None = None
    threads: list[dict[str, Any]] = []
    while True:
        payload = request_json(
            GRAPHQL,
            token=token,
            method="POST",
            body={
                "query": THREAD_QUERY,
                "variables": {"owner": owner, "name": name, "number": number, "cursor": cursor},
            },
        )
        if not isinstance(payload, Mapping) or payload.get("errors"):
            fail(f"GraphQL review-thread query failed: {payload}")
        try:
            pull_request = payload["data"]["repository"]["pullRequest"]
            connection = pull_request["reviewThreads"]
        except (KeyError, TypeError) as exc:
            fail("malformed review-thread response")
        decision = pull_request.get("reviewDecision")
        nodes = connection.get("nodes")
        if not isinstance(nodes, list):
            fail("malformed review-thread nodes")
        threads.extend(dict(node) for node in nodes if isinstance(node, Mapping))
        page_info = connection.get("pageInfo")
        if not isinstance(page_info, Mapping):
            fail("malformed review-thread pagination")
        if not page_info.get("hasNextPage"):
            return decision, threads
        cursor = page_info.get("endCursor")
        if not isinstance(cursor, str) or not cursor:
            fail("missing review-thread cursor")


def latest_reviews(repository: str, number: int, *, token: str) -> list[dict[str, Any]]:
    reviews = rest_pages(f"/repos/{repository}/pulls/{number}/reviews", token=token)
    output = []
    for review in reviews:
        if not isinstance(review, Mapping):
            fail("malformed review")
        output.append(
            {
                "author": (review.get("user") or {}).get("login"),
                "state": review.get("state"),
                "commit_id": review.get("commit_id"),
                "submitted_at": review.get("submitted_at"),
            }
        )
    return output


def promotion_allowed(base: str, head: str) -> tuple[bool, str]:
    if base == "development":
        allowed = any(head.startswith(prefix) for prefix in TEMPORARY_PREFIXES)
        return allowed, "temporary remediation/security/upgrade/hotfix/sync branch -> development"
    if base in PROTECTED_SEQUENCE[1:]:
        previous = PROTECTED_SEQUENCE[PROTECTED_SEQUENCE.index(base) - 1]
        return head == previous, f"required protected promotion is {previous} -> {base}"
    return False, "target is outside the protected promotion sequence"


def classify_checks(runs: Sequence[Mapping[str, Any]], head_sha: str) -> tuple[str, list[str]]:
    blockers: list[str] = []
    if not runs:
        return "ABSENT", ["no exact-head check runs observed"]
    for run in runs:
        if run.get("head_sha") != head_sha:
            blockers.append(f"check not bound to exact head: {run.get('name')}")
        conclusion = run.get("conclusion")
        status = run.get("status")
        if conclusion in FAILURE_CONCLUSIONS:
            blockers.append(f"failing check: {run.get('name')} ({conclusion})")
        elif status in PENDING_STATUSES or conclusion is None:
            blockers.append(f"pending check: {run.get('name')} ({status})")
        elif conclusion not in SUCCESS_CONCLUSIONS:
            blockers.append(f"unrecognized check result: {run.get('name')} ({conclusion})")
    return ("PASS" if not blockers else "BLOCKED"), blockers


def exact_head_approved(reviews: Iterable[Mapping[str, Any]], head_sha: str) -> bool:
    latest: dict[str, Mapping[str, Any]] = {}
    for review in reviews:
        author = review.get("author")
        if isinstance(author, str) and author:
            latest[author] = review
    return any(
        review.get("state") == "APPROVED" and review.get("commit_id") == head_sha
        for review in latest.values()
    )


def audit(repository: str, *, token: str) -> dict[str, Any]:
    owner, name = repository.split("/", 1)
    pulls = rest_pages(
        f"/repos/{repository}/pulls",
        token=token,
        parameters={"state": "open", "sort": "updated", "direction": "desc"},
    )
    records: list[dict[str, Any]] = []
    for summary in pulls:
        if not isinstance(summary, Mapping) or not isinstance(summary.get("number"), int):
            fail("malformed pull-request summary")
        number = summary["number"]
        detail = request_json(f"{API}/repos/{repository}/pulls/{number}", token=token)
        if not isinstance(detail, Mapping):
            fail("malformed pull-request detail")
        head = detail.get("head") or {}
        base = detail.get("base") or {}
        head_sha = head.get("sha")
        head_ref = head.get("ref")
        base_ref = base.get("ref")
        if not all(isinstance(item, str) and item for item in (head_sha, head_ref, base_ref)):
            fail(f"pull request #{number} has malformed refs")
        runs = check_runs(repository, head_sha, token=token)
        check_state, blockers = classify_checks(runs, head_sha)
        decision, threads = review_threads(owner, name, number, token=token)
        unresolved = [thread for thread in threads if not thread.get("isResolved") and not thread.get("isOutdated")]
        reviews = latest_reviews(repository, number, token=token)
        allowed, promotion_reason = promotion_allowed(base_ref, head_ref)
        approved = exact_head_approved(reviews, head_sha)
        if detail.get("draft"):
            blockers.append("pull request is draft")
        if not allowed:
            blockers.append(f"invalid promotion path: {promotion_reason}")
        if detail.get("mergeable") is not True:
            blockers.append(f"mergeability is not clean: {detail.get('mergeable')}/{detail.get('mergeable_state')}")
        if unresolved:
            blockers.append(f"unresolved active review threads: {len(unresolved)}")
        if decision == "CHANGES_REQUESTED":
            blockers.append("review decision is CHANGES_REQUESTED")
        if not approved:
            blockers.append("no independent exact-head approval")
        records.append(
            {
                "number": number,
                "title": detail.get("title"),
                "url": detail.get("html_url"),
                "draft": bool(detail.get("draft")),
                "base": base_ref,
                "base_sha": base.get("sha"),
                "head": head_ref,
                "head_sha": head_sha,
                "mergeable": detail.get("mergeable"),
                "mergeable_state": detail.get("mergeable_state"),
                "review_decision": decision,
                "exact_head_approved": approved,
                "unresolved_active_threads": len(unresolved),
                "check_state": check_state,
                "check_runs": runs,
                "promotion_path_allowed": allowed,
                "promotion_reason": promotion_reason,
                "merge_authorized": not blockers,
                "blockers": blockers,
            }
        )
    return {
        "schema_version": 1,
        "repository": repository,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_mutation": False,
        "pull_requests": records,
        "merge_authorized": [record["number"] for record in records if record["merge_authorized"]],
    }


def markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Keycloak exact-head pull-request audit",
        "",
        f"Repository: `{report['repository']}`",
        f"Generated: `{report['generated_at']}`",
        "",
        "| PR | Draft | Base <- Head | Exact head | Checks | Threads | Review | Merge authorized |",
        "|---:|:---:|---|---|---|---:|---|:---:|",
    ]
    for record in report["pull_requests"]:
        lines.append(
            f"| [#{record['number']}]({record['url']}) | {'yes' if record['draft'] else 'no'} | "
            f"`{record['base']}` <- `{record['head']}` | `{record['head_sha'][:12]}` | "
            f"{record['check_state']} | {record['unresolved_active_threads']} | "
            f"{record['review_decision'] or 'NONE'} | {'yes' if record['merge_authorized'] else 'no'} |"
        )
        if record["blockers"]:
            lines.append("")
            lines.append(f"**#{record['number']} blockers:** " + "; ".join(record["blockers"]))
            lines.append("")
    lines += [
        "",
        "## Safety",
        "",
        "This audit is read-only and never deploys Keycloak, changes realms or clients, reads secrets, issues credentials, changes SSH/DNS, or promotes a protected branch.",
    ]
    return "\n".join(lines) + "\n"


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "appolon1908-hue/Keycloak"))
    value.add_argument("--json-output", type=Path, default=Path("artifacts/keycloak-pr-audit.json"))
    value.add_argument("--markdown-output", type=Path, default=Path("artifacts/keycloak-pr-audit.md"))
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print("KEYCLOAK_PR_AUDIT=FAIL ERROR=missing GitHub token", file=sys.stderr)
        return 1
    try:
        report = audit(args.repository, token=token)
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        args.markdown_output.write_text(markdown(report), encoding="utf-8")
    except AuditError as exc:
        print(f"KEYCLOAK_PR_AUDIT=FAIL ERROR={exc}", file=sys.stderr)
        return 1
    print("KEYCLOAK_PR_AUDIT=PASS")
    print(f"OPEN_PULL_REQUESTS={len(report['pull_requests'])}")
    print(f"MERGE_AUTHORIZED={len(report['merge_authorized'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
