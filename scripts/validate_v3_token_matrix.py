#!/usr/bin/env python3
"""Validate the PAS-157 V3 positive/negative token-policy matrix."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import validate_middleware_caller_classification as caller  # noqa: E402

AUTHORITY_PATH = ROOT / "config" / "contracts" / "middleware-caller-classification.v1.json"
MATRIX_PATH = ROOT / "config" / "certification" / "v3-token-matrix.v1.json"


def certify_matrix(
    authority_path: Path = AUTHORITY_PATH,
    matrix_path: Path = MATRIX_PATH,
) -> dict[str, Any]:
    authority = caller.load_json(authority_path)
    matrix = caller.load_json(matrix_path)
    caller.validate_authority_shape(authority)
    report = caller.validate_token_matrix(authority, matrix)
    leaks = caller.privileged_default_scope_leaks(authority)
    if leaks:
        raise caller.CertificationError(
            "privileged scopes are default-granted: " + "; ".join(leaks)
        )
    return {
        "mission": "PAS-157",
        "verdict": "PASS",
        "dimensions": report["dimensions"],
        "positiveCases": report["positiveCases"],
        "negativeCases": report["negativeCases"],
        "privilegedDefaultScopeLeaks": 0,
        "dirtyDesktopAutoGrantAuthorized": False,
        "liveApplyAuthorized": False,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority", type=Path, default=AUTHORITY_PATH)
    parser.add_argument("--matrix", type=Path, default=MATRIX_PATH)
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = certify_matrix(args.authority.resolve(), args.matrix.resolve())
    except caller.CertificationError as exc:
        print("PAS157_V3_TOKEN_MATRIX=FAIL")
        print(f"ERROR={exc}")
        return 1

    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("PAS157_V3_TOKEN_MATRIX=PASS")
        print(f"TOKEN_MATRIX_DIMENSIONS={report['dimensions']}")
        print(f"TOKEN_MATRIX_POSITIVE={report['positiveCases']}")
        print(f"TOKEN_MATRIX_NEGATIVE={report['negativeCases']}")
        print("PRIVILEGED_DEFAULT_SCOPE_LEAKS=0")
        print("DIRTY_DESKTOP_AUTO_GRANT=PROHIBITED")
        print("KEYCLOAK_LIVE_APPLY=PROHIBITED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
