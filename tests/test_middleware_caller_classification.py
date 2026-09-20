from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from scripts import validate_middleware_caller_classification as cert


AUTHORITY = cert.load_json(cert.AUTHORITY_PATH)
MATRIX = cert.load_json(cert.MATRIX_PATH)
ROUTES = cert.load_json(cert.DEFAULT_ROUTE_CONTRACT)


def test_default_pr118_contract_has_zero_unknown_callers_and_complete_token_matrix() -> None:
    report = cert.certify()
    assert report["verdict"] == "PASS"
    assert report["callerAuthority"]["unknownCallerIdentities"] == 0
    assert report["callerAuthority"]["uniqueCallerSelectors"] == 17
    assert report["callerAuthority"]["serviceOrUserServiceBindings"] > 0
    assert report["callerAuthority"]["serviceOrUserHumanBindings"] > 0
    assert report["tokenMatrix"]["dimensions"] == 8
    assert report["tokenMatrix"]["positiveCases"] == 8
    assert report["tokenMatrix"]["negativeCases"] == 8
    assert report["privilegedDefaultScopeLeaks"] == 0
    assert report["dirtyDesktopAutoGrantAuthorized"] is False
    assert report["liveApplyAuthorized"] is False


def test_known_identity_vocabulary_is_explicitly_classified() -> None:
    callers = AUTHORITY["callers"]
    expected = {
        "callback-ui": "CONCRETE_HUMAN_CLIENT",
        "n8n-operations-automation": "CONCRETE_SERVICE_CLIENT",
        "github-app": "CONCRETE_SERVICE_CLIENT",
        "observability-collector": "CONCRETE_SERVICE_CLIENT",
        "production-operator": "CONCRETE_HUMAN_CLIENT",
        "platform-command-client": "CLIENT_FAMILY",
    }
    for caller, klass in expected.items():
        assert callers[caller]["class"] == klass
    assert AUTHORITY["aliases"]["platform-command-family"] == "platform-command-client"


def test_human_and_service_grant_boundaries_are_fail_closed() -> None:
    callers = AUTHORITY["callers"]
    for caller in ("n8n-automation", "n8n-operations-automation", "github-app", "observability-collector"):
        assert callers[caller]["actorKinds"] == ["service"]
        assert callers[caller]["grantTypes"] == ["client_credentials"]

    for caller in ("callback-ui", "browser-session", "platform-operator", "production-operator"):
        assert callers[caller]["actorKinds"] == ["user"]
        assert callers[caller]["grantTypes"] == ["authorization_code"]
        assert callers[caller]["humanPkceRequired"] is True
        assert callers[caller]["humanMfaPolicy"] in {"required", "required-for-privileged"}


def test_platform_command_replay_requires_scope_role_pkce_and_mfa() -> None:
    replay = AUTHORITY["callers"]["platform-command-client"]["replayRequirements"]
    assert replay == {
        "scope": "platform.command.replay",
        "role": "platform-operator",
        "mfaRequired": True,
        "actorKind": "user",
        "grantType": "authorization_code",
        "pkceRequired": True,
    }
    assert AUTHORITY["tokenPolicy"]["dirtyDesktopAutoGrantAuthorized"] is False
    assert "codestra-agent-desktop" in AUTHORITY["tokenPolicy"]["protectedUngrantableClientIds"]


def test_every_token_dimension_has_positive_and_negative_case() -> None:
    seen = {dimension: set() for dimension in cert.EXPECTED_DIMENSIONS}
    for case in MATRIX["cases"]:
        seen[case["dimension"]].add(case["expect"])
    assert all(verdicts == {"ACCEPT", "REJECT"} for verdicts in seen.values())


@pytest.mark.parametrize(
    ("case_id", "must_fail"),
    [
        ("issuer-negative", "issuer"),
        ("audience-negative", "audience"),
        ("azp-negative", "azp"),
        ("tenant-negative", "tenant"),
        ("scope-negative", "scope"),
        ("role-negative", "role"),
        ("expiry-negative", "expiry"),
        ("replay-negative", "replay"),
    ],
)
def test_negative_matrix_cases_fail_the_intended_boundary(case_id: str, must_fail: str) -> None:
    case = next(row for row in MATRIX["cases"] if row["id"] == case_id)
    fixture = copy.deepcopy(MATRIX["fixtures"][case["fixture"]])
    for dotted, value in case.get("mutations", {}).items():
        cert._set_dotted(fixture, dotted, value)
    assert must_fail in cert.evaluate_token_fixture(AUTHORITY, fixture)


def test_unknown_caller_is_rejected_with_explicit_count() -> None:
    routes = copy.deepcopy(ROUTES)
    routes["routes"].append(
        {
            "operation_id": "test_unknown",
            "method": "GET",
            "path": "/test/unknown",
            "classification": "shared_edge",
            "calling_client": "unreviewed-client",
            "audience": "middleware-api",
            "scope": "identity.request",
            "auth": "service-or-user-jwt",
        }
    )
    with pytest.raises(cert.CertificationError, match="UNKNOWN_CALLER_IDENTITIES=1"):
        cert.validate_routes(AUTHORITY, routes)


def test_platform_command_client_is_accepted_for_future_v3_route() -> None:
    routes = {
        "routes": [
            {
                "operation_id": "submit_platform_command",
                "method": "POST",
                "path": "/platform/v1/commands",
                "classification": "shared_edge",
                "calling_client": "platform-command-client",
                "audience": "middleware-api",
                "scope": "platform.command",
                "auth": "service-or-user-jwt",
            }
        ]
    }
    report = cert.validate_routes(AUTHORITY, routes)
    assert report["unknownCallerIdentities"] == 0
    assert report["serviceOrUserServiceBindings"] == 1
    assert report["serviceOrUserHumanBindings"] == 1


def test_privileged_default_scope_leak_is_detected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "config"
        config.mkdir()
        (config / "leaked.json").write_text(
            json.dumps({"defaultClientScopes": ["platform.command"]}),
            encoding="utf-8",
        )
        with mock.patch.object(cert, "ROOT", root):
            leaks = cert.privileged_default_scope_leaks(AUTHORITY)
    assert leaks == ["config/leaked.json:platform.command"]


def test_old_base_contract_cannot_be_misreported_as_final_target() -> None:
    with pytest.raises(cert.CertificationError, match="target Middleware route contract mismatch"):
        cert.certify(require_target_contract=True)
