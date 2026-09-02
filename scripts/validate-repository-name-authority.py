#!/usr/bin/env python3
"""Validate stable repository IDs used by Keycloak workflows before rename cutover."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

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


def validate() -> None:
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
    infrastructure_current = EXPECTED[1350724865][0]
    infrastructure_target = EXPECTED[1350724865][1]
    if infrastructure_current not in workflow:
        fail("runtime preflight lost the current infrastructure checkout before cutover")
    if infrastructure_target in workflow:
        fail("runtime preflight uses the target infrastructure name before cutover")

    if "INFRASTRUCTURE_SHA:" not in workflow:
        fail("runtime preflight must retain an exact infrastructure SHA")
    if "persist-credentials: false" not in workflow:
        fail("runtime preflight checkout must keep credentials disabled")


def main() -> None:
    validate()
    print("Keycloak repository-name authority validation: PASS")


if __name__ == "__main__":
    main()
