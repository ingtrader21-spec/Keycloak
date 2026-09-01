#!/usr/bin/env python3
"""Enforce the reviewed Middleware↔n8n command/result flow."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "config" / "contracts" / "service-access-matrix.json"


def fail(message: str) -> None:
    print(f"N8N_FLOW_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    try:
        document = json.loads(MATRIX.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable_to_load_matrix:{exc}")

    grants: dict[tuple[str, str], set[str]] = {}
    for raw in document.get("grants", []):
        if not isinstance(raw, dict):
            fail("invalid_grant_shape")
        key = (raw.get("callerClientId"), raw.get("targetClientId"))
        scopes = raw.get("scopes")
        if key in grants or not isinstance(scopes, list):
            fail("duplicate_or_invalid_grant")
        grants[key] = set(scopes)

    expected = {
        ("middleware-api", "n8n-automation"): {
            "workflow.status.read",
            "workflow.trigger",
        },
        ("n8n-automation", "middleware-api"): {
            "automation.command.request",
            "workflow.result.publish",
        },
    }
    for key, scopes in expected.items():
        if grants.get(key) != scopes:
            fail(f"incorrect_grant:{key[0]}->{key[1]}:{sorted(grants.get(key, set()))}")

    prohibited_targets = set(document.get("prohibitedDirectTargets", {}).get("n8n-automation", []))
    expected_targets = {
        "odoo-integration",
        "vicidial-adapter",
        "telnexa-gateway",
        "klyrow-gateway",
        "kyqra-gateway",
        "postly-adapter",
        "ai-provider-adapter",
        "marketing-provider-adapter",
    }
    if prohibited_targets != expected_targets:
        fail("direct_provider_prohibition_changed")
    for target in expected_targets:
        if ("n8n-automation", target) in grants:
            fail(f"direct_provider_grant_present:{target}")

    print("N8N_COMMAND_DIRECTION=PASS")
    print("N8N_RESULT_DIRECTION=PASS")
    print("N8N_MIDDLEWARE_COMMAND_SCOPES=PASS")
    print("N8N_DIRECT_PROVIDER_GRANTS=DISALLOWED")


if __name__ == "__main__":
    main()
