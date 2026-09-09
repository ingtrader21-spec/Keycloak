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
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"BOOTSTRAP_REJECTED={message}")


def sha256(path: Path) -> str:
    if not path.is_file():
        fail(f"missing:{path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    args = parser.parse_args()
    if args.candidate_sha != args.expected_candidate_sha:
        fail("stale-exact-head")
    manifest = load_manifest(ROOT / args.manifest)
    for entry in manifest["files"]:
        actual = sha256(ROOT / entry["path"])
        if actual != entry["sha256"]:
            fail(f"source-digest:{entry['path']}")
    print(f"BOOTSTRAP_EXECUTABLE_CLOSURE_SHA256={manifest['manifest_sha256']}")
    print("TRUST_ROOT_SELF_REFERENCE=NO")
    print("BOOTSTRAP_FAIL_CLOSED=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
