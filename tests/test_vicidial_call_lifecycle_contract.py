from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "contracts" / "webhook-contracts.json"

EXPECTED_EVENT_TYPES = (
    "codestra.vicidial.call.completed",
    "codestra.vicidial.call.lifecycle.answered",
    "codestra.vicidial.call.lifecycle.completed",
    "codestra.vicidial.call.lifecycle.connected",
    "codestra.vicidial.call.lifecycle.created",
    "codestra.vicidial.call.lifecycle.failed",
    "codestra.vicidial.call.lifecycle.hangup",
    "codestra.vicidial.call.lifecycle.held",
    "codestra.vicidial.call.lifecycle.missed",
    "codestra.vicidial.call.lifecycle.offered",
    "codestra.vicidial.call.lifecycle.resumed",
    "codestra.vicidial.call.lifecycle.ringing",
    "codestra.vicidial.call.lifecycle.transfer.completed",
    "codestra.vicidial.call.lifecycle.transfer.started",
    "codestra.vicidial.call.started",
    "codestra.vicidial.callback.requested",
)
EXPECTED_LIFECYCLE_TYPES = tuple(
    value for value in EXPECTED_EVENT_TYPES if ".lifecycle." in value
)


def vicidial_contract() -> dict[str, object]:
    document = json.loads(CONTRACT.read_text(encoding="utf-8"))
    matches = [
        item
        for item in document["webhooks"]
        if item.get("producerClientId") == "vicidial-adapter"
    ]
    assert len(matches) == 1
    return matches[0]


def test_vicidial_lifecycle_contract_is_exact_and_least_privilege() -> None:
    contract = vicidial_contract()
    assert contract["consumerClientId"] == "middleware-api"
    assert contract["audience"] == "middleware-api"
    assert contract["requiredScope"] == "telephony.events.publish"
    assert contract["path"] == "/api/v1/vicidial/events"
    assert contract["delivery"] == "at_least_once"
    assert tuple(contract["eventTypes"]) == EXPECTED_EVENT_TYPES
    assert tuple(
        value for value in contract["eventTypes"] if ".lifecycle." in value
    ) == EXPECTED_LIFECYCLE_TYPES
    assert len(set(contract["eventTypes"])) == len(EXPECTED_EVENT_TYPES)


def test_contract_does_not_grant_call_control_or_dialing() -> None:
    contract = vicidial_contract()
    forbidden = (".dial.", ".originate.", "call.place", "ami.command", "ari.command")
    assert not any(
        token in event_type
        for event_type in contract["eventTypes"]
        for token in forbidden
    )
