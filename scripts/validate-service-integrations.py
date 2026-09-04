#!/usr/bin/env python3
"""Compatibility entry point for fail-closed service integration validation."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from service_integration_validator import (  # noqa: E402,F401
    ContractError,
    main,
    validate,
    validate_access_matrix,
    validate_client_document,
    validate_machine_contract,
    validate_webhook_contract,
)


if __name__ == "__main__":
    raise SystemExit(main())
