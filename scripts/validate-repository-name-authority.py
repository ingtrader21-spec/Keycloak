#!/usr/bin/env python3
"""Validate stable repository IDs used by Keycloak workflows before rename cutover."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config" / "policy" / "repository-name-aliases.v1.json"
RUNTIME_PREFLIGHT = ROOT / ".github" / "workflows" / "runtime-preflight.yml"
EXPECTED = {
    1221155447: (
        "appolon1908-hue/Frontend-Resturant-",
        "appolon1908-hue/restaurant-frontend",
    ),
    1343761049: (
        "appolon1908-hue/transportaion-Frontend",
        "appolon1908-hue/freight-platform-frontend",
    ),
    1343962199: (
        "appolon1908-hue/LARIM-A-Fornt-end",
        "appolon1908-hue/LARIM-A-Frontend",
    ),
    1351353723: (
        "appolon1908-hue/Codesrea-Social-",
        "appolon1908-hue/Codestra-Social-Control-Plane",
    ),
    1350724356: (
        "appolon1908-hue/documentaions",
        "appolon1908-hue/Codestra-Documentation",
    ),
    1350724865: (
        "appolon1908-hue/Infustruction-repo",
        "appolon1908-hue/Codestra-Infrastructure",
    ),
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load() -> dict[str, Any]:
    try:
        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid repository alias manifest: {exc}")
    if not isinstance(value, dict):
        fail("repository alias manifest root must be an object")
    return value


def cross_repository_token() -> str:
    token = os.environ.get("CODESTRA_REPOSITORY_READ_TOKEN") or os.environ.get(
        "GH_TOKEN"
    )
    if not token:
        fail(
            "live repository identity validation requires the protected "
            "CODESTRA_REPOSITORY_READ_TOKEN secret"
        )
    return token


def github_headers() -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {cross_repository_token()}",
        "User-Agent": "codestra-keycloak-repository-authority",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def fetch_live_repository_id(
    repository: str,
    opener: Callable[..., Any] | None = None,
) -> int:
    request = Request(
        f"https://api.github.com/repos/{repository}",
        headers=github_headers(),
    )
    open_request = opener or urlopen
    try:
        with open_request(request, timeout=20) as response:
            payload = json.load(response)
    except HTTPError as exc:
        fail(f"GitHub repository lookup failed for {repository}: HTTP {exc.code}")
    except URLError as exc:
        fail(f"GitHub repository lookup failed for {repository}: {exc.reason}")
    except (OSError, ValueError, TypeError) as exc:
        fail(f"GitHub repository lookup failed for {repository}: {exc}")

    if not isinstance(payload, dict) or not isinstance(payload.get("id"), int):
        fail(f"GitHub repository lookup returned no stable ID for {repository}")
    if payload.get("full_name") != repository:
        fail(
            "GitHub repository lookup resolved an unexpected full name: "
            f"requested {repository}, received {payload.get('full_name')}"
        )
    return int(payload["id"])


def validate_live_repository_ids(
    actual: dict[int, tuple[str, str]],
    fetcher: Callable[[str], int] = fetch_live_repository_id,
) -> None:
    for expected_id, (current, _target) in sorted(actual.items()):
        observed_id = fetcher(current)
        if observed_id != expected_id:
            fail(
                "live GitHub repository ID mismatch: "
                f"{current} expected {expected_id}, observed {observed_id}"
            )


def workflow_step_blocks(text: str) -> list[str]:
    """Return individual named workflow step blocks at their original indentation."""

    lines = text.splitlines()
    starts: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(?P<indent>\s*)-\s+name:\s*", line)
        if match:
            starts.append((index, len(match.group("indent"))))

    blocks: list[str] = []
    for position, (start, indent) in enumerate(starts):
        end = len(lines)
        for candidate_start, candidate_indent in starts[position + 1 :]:
            if candidate_indent <= indent:
                end = candidate_start
                break
        blocks.append("\n".join(lines[start:end]))
    return blocks


def validate_infrastructure_checkout(
    workflow: str,
    current_repository: str,
    target_repository: str,
) -> None:
    if target_repository in workflow:
        fail("runtime preflight uses the target infrastructure name before cutover")

    pattern = re.compile(
        rf"(?m)^\s*repository:\s*[\"']?{re.escape(current_repository)}[\"']?\s*$"
    )
    matches = [block for block in workflow_step_blocks(workflow) if pattern.search(block)]
    if len(matches) != 1:
        fail(
            "runtime preflight must contain exactly one current Infrastructure "
            f"checkout; found {len(matches)}"
        )

    checkout = matches[0]
    if not re.search(r"(?m)^\s*persist-credentials:\s*false\s*$", checkout):
        fail("Infrastructure checkout must keep credentials disabled")
    if "uses: actions/checkout@" not in checkout:
        fail("Infrastructure authority must be retrieved by an actions/checkout step")

    sha_match = re.search(
        r"(?m)^\s*INFRASTRUCTURE_SHA:\s*([0-9a-f]{40})\s*$",
        workflow,
    )
    if sha_match is None:
        fail("runtime preflight must retain an exact infrastructure SHA")
    expected_sha = sha_match.group(1)
    if not re.search(
        rf"(?m)^\s*ref:\s*[\"']?{expected_sha}[\"']?\s*$",
        checkout,
    ):
        fail("Infrastructure checkout ref does not match INFRASTRUCTURE_SHA")


def validate(*, require_live: bool = False) -> None:
    document = load()
    if document.get("schema_version") != "1.0":
        fail("repository alias schema_version must be 1.0")
    if document.get("status") != "PREPARED_NOT_RENAMED":
        fail("repository aliases changed state without a reviewed cutover")
    if document.get("identity_key") != "repository_id":
        fail("repository_id must be the stable repository identity")
    if document.get("historical_evidence_immutable") is not True:
        fail("historical evidence must remain immutable")

    mappings = document.get("mappings")
    if not isinstance(mappings, list) or len(mappings) != 6:
        fail("repository alias manifest must contain exactly six mappings")
    actual: dict[int, tuple[str, str]] = {}
    current_names: set[str] = set()
    target_names: set[str] = set()
    for item in mappings:
        if not isinstance(item, dict):
            fail("repository alias mapping must be an object")
        repository_id = item.get("repository_id")
        current = item.get("current_repository")
        target = item.get("target_repository_after_cutover")
        if not isinstance(repository_id, int) or repository_id <= 0:
            fail("repository alias contains an invalid stable ID")
        if repository_id in actual:
            fail(f"repository alias contains duplicate stable ID: {repository_id}")
        if not isinstance(current, str) or not current.startswith("appolon1908-hue/"):
            fail(f"invalid current repository for ID {repository_id}")
        if not isinstance(target, str) or not target.startswith("appolon1908-hue/"):
            fail(f"invalid target repository for ID {repository_id}")
        if current in current_names or target in target_names:
            fail("repository alias contains duplicate current or target names")
        if item.get("status") != "PREPARED_NOT_RENAMED":
            fail(f"mapping changed state without cutover: {current}")
        actual[repository_id] = (current, target)
        current_names.add(current)
        target_names.add(target)
    if actual != EXPECTED:
        fail("repository aliases do not exactly match the approved stable-ID set")

    workflow = RUNTIME_PREFLIGHT.read_text(encoding="utf-8")
    validate_infrastructure_checkout(
        workflow,
        EXPECTED[1350724865][0],
        EXPECTED[1350724865][1],
    )

    if require_live:
        validate_live_repository_ids(actual)
        print("LIVE_REPOSITORY_IDENTITY=PASS")
    else:
        print("LIVE_REPOSITORY_IDENTITY=REQUIRED_BEFORE_CUTOVER")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--live",
        action="store_true",
        help="require protected cross-repository GitHub API ID readback",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    validate(require_live=args.live)
    print("Keycloak repository-name authority validation: PASS")


if __name__ == "__main__":
    main()
