#!/usr/bin/env python3
"""Prepare reviewable manifest changes from immutable Git objects; never activate them."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

SCHEMA = "keycloak.bootstrap-closure.v1"
POLICY_PATH = "config/bootstrap/executable-closure.json"
REPOSITORY = "appolon1908-hue/Keycloak"


class ManifestError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def valid_sha(value: object, size: int) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(size) + r"}", value) is not None


def safe_path(value: object) -> str:
    if (not isinstance(value, str) or not value or value != value.strip()
            or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(part in {"", ".", "..", ".git"} for part in value.split("/"))):
        raise ManifestError("invalid repository-relative manifest path")
    return value


def seal(entries: list[dict[str, str]]) -> dict:
    payload = {"schema": SCHEMA, "files": entries}
    return {**payload, "manifest_sha256": digest(payload)}


def validate_manifest(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {"schema", "files", "manifest_sha256"}:
        raise ManifestError("invalid manifest fields")
    if value["schema"] != SCHEMA or not isinstance(value["files"], list) or not value["files"]:
        raise ManifestError("invalid manifest schema or file list")
    paths = []
    for entry in value["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise ManifestError("invalid manifest entry")
        paths.append(safe_path(entry["path"]))
        if not valid_sha(entry["sha256"], 64):
            raise ManifestError("invalid file SHA-256")
    if paths != sorted(set(paths)):
        raise ManifestError("manifest paths must be unique and sorted")
    if value != seal(value["files"]):
        raise ManifestError("manifest digest mismatch")
    return value


class GitSource:
    def __init__(self, repository: Path):
        self.repository = repository

    def git(self, *arguments: str) -> bytes:
        try:
            return subprocess.check_output(
                ["git", "--no-replace-objects", "-C", str(self.repository), *arguments], stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            raise ManifestError("unable to read the requested Git object") from None

    def require_commit(self, sha: str) -> None:
        if not valid_sha(sha, 40) or self.git("cat-file", "-t", sha).strip() != b"commit":
            raise ManifestError("a full immutable commit SHA is required")

    def read(self, sha: str, path: str) -> bytes:
        self.require_commit(sha)
        path = safe_path(path)
        entries = self.git("ls-tree", "-z", sha, "--", ":(literal)" + path).split(b"\0")
        entries = [entry for entry in entries if entry]
        if len(entries) != 1:
            raise ManifestError("missing or ambiguous source file: " + path)
        metadata, recorded_path = entries[0].split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        if recorded_path.decode("utf-8") != path or mode not in {"100644", "100755"} or kind != "blob":
            raise ManifestError("source must be a regular tracked file: " + path)
        return self.git("cat-file", "blob", oid)


def propose(source: GitSource, policy_sha: str, source_sha: str) -> dict:
    source.require_commit(policy_sha)
    source.require_commit(source_sha)
    try:
        policy = validate_manifest(json.loads(source.read(policy_sha, POLICY_PATH)))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ManifestError("invalid policy JSON") from None
    entries, changes = [], []
    for previous in policy["files"]:
        path = previous["path"]
        observed = hashlib.sha256(source.read(source_sha, path)).hexdigest()
        entries.append({"path": path, "sha256": observed})
        if observed != previous["sha256"]:
            changes.append({"path": path, "previous_sha256": previous["sha256"], "proposed_sha256": observed})
    return {
        "schema": "keycloak.bootstrap-manifest-proposal.v1",
        "repository": REPOSITORY,
        "policy_commit_sha": policy_sha,
        "reviewed_source_sha": source_sha,
        "previous_manifest_sha256": policy["manifest_sha256"],
        "authorization": "PENDING_INDEPENDENT_REVIEW",
        "scope": "EXISTING_DECLARED_FILES_ONLY",
        "manifest": seal(entries),
        "changes": changes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--policy-sha", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.resolve() == (args.repository / POLICY_PATH).resolve():
            raise ManifestError("cannot overwrite the active trust policy with an unapproved proposal")
        proposal = propose(GitSource(args.repository), args.policy_sha, args.source_sha)
        # Exclusive creation avoids accidentally replacing another reviewed proposal.
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(proposal, output, indent=2, sort_keys=True)
            output.write("\n")
    except (ManifestError, OSError) as error:
        print("MANIFEST_PROPOSAL_ERROR=" + str(error), file=sys.stderr)
        return 1
    print("MANIFEST_CHANGED_FILES=" + str(len(proposal["changes"])))
    print("MANIFEST_PROPOSAL_SHA256=" + digest(proposal))
    print("MANIFEST_AUTHORIZATION=PENDING_INDEPENDENT_REVIEW")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
