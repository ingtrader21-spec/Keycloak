from __future__ import annotations

import copy

from scripts import validate_middleware_caller_classification as caller
from scripts import validate_v3_token_matrix as matrix_cert


AUTHORITY = caller.load_json(caller.AUTHORITY_PATH)
MATRIX = caller.load_json(caller.MATRIX_PATH)


def test_v3_token_matrix_certifies_all_required_dimensions() -> None:
    report = matrix_cert.certify_matrix()
    assert report["verdict"] == "PASS"
    assert report["dimensions"] == 8
    assert report["positiveCases"] == 8
    assert report["negativeCases"] == 8
    assert report["privilegedDefaultScopeLeaks"] == 0
    assert report["dirtyDesktopAutoGrantAuthorized"] is False


def test_staging_token_from_production_issuer_is_rejected() -> None:
    fixture = copy.deepcopy(MATRIX["fixtures"]["service"])
    fixture["claims"]["iss"] = AUTHORITY["tokenPolicy"]["productionIssuer"]
    failures = caller.evaluate_token_fixture(AUTHORITY, fixture)
    assert "issuer" in failures


def test_replay_without_operator_role_and_mfa_is_rejected() -> None:
    fixture = copy.deepcopy(MATRIX["fixtures"]["privilegedHumanReplay"])
    fixture["claims"]["realm_access"]["roles"] = []
    fixture["claims"]["amr"] = ["pwd"]
    failures = caller.evaluate_token_fixture(AUTHORITY, fixture)
    assert "role" in failures
    assert "mfa" in failures
    assert "replay" in failures
