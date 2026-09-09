#!/usr/bin/env python3
"""Validate per-client machine credential boundaries."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
contract = json.loads((ROOT / "config/contracts/machine-secret-destinations.json").read_text())
machine = json.loads((ROOT / "config/contracts/machine-clients.json").read_text())
products = json.loads((ROOT / "config/contracts/product-middleware-clients.json").read_text())
expected_clients = [item["clientId"] for item in machine["clients"]]
expected_clients.extend(item["clientId"] for item in products["clients"])
environment_name = re.compile(r"^KC_CLIENT_SECRET_[A-Z0-9_]+$")


def fail(message: str) -> None:
    raise SystemExit(f"MACHINE_SECRET_CONTRACT_ERROR={message}")


if contract.get("schemaVersion") != 1:
    fail("schema version")
if contract.get("storagePolicy") != "pre-provisioned-protected-environment-secret":
    fail("storage policy")
for key in ("secretMaterialInPlans", "secretMaterialInArtifacts", "secretMaterialInLogs"):
    if contract.get(key) is not False:
        fail(f"{key} must be false")
entries = contract.get("clients")
if not isinstance(entries, list) or [item.get("clientId") for item in entries] != expected_clients:
    fail("client membership or order")
names = [item.get("applyEnvironment") for item in entries]
if len(names) != len(set(names)) or not all(isinstance(name, str) and environment_name.fullmatch(name) for name in names):
    fail("environment names must be unique protected secret names")
for client_id in expected_clients:
    overlay = json.loads((ROOT / f"config/clients/{client_id}.json").read_text())
    if any(key in overlay for key in ("secret", "clientSecret", "credentials")):
        fail(f"{client_id} overlay contains credential material")

print("MACHINE_SECRET_DESTINATIONS=PASS")
print("MACHINE_SECRET_MATERIAL_OUTSIDE_GIT=PASS")
