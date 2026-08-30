#!/usr/bin/env python3
"""Focused structural and negative validation for issue #30."""
from __future__ import annotations

import sys
from pathlib import Path

from observability_identity_policy import PolicyError, negative_self_test, validate_source

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    try:
        validate_source(ROOT / "config")
        negative_self_test(ROOT / "config")
    except PolicyError as exc:
        print(f"OBSERVABILITY_MANAGED_IDENTITY_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
    print("OBSERVABILITY_MANAGED_CLIENTS=PASS")
    print("OBSERVABILITY_MANAGED_REALM_ROLES=PASS")
    print("OBSERVABILITY_UNSAFE_GRANT_REJECTION=PASS")
    print("OBSERVABILITY_CALLBACK_DRIFT_REJECTION=PASS")
    print("OBSERVABILITY_ROLE_ISOLATION_REJECTION=PASS")
    print("OBSERVABILITY_SECRET_HANDOFF_POLICY=PASS")
    print("OBSERVABILITY_NO_LIVE_APPLY=PASS")


if __name__ == "__main__":
    main()
