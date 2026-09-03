from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/ci/audit_keycloak_pull_requests.py"
SPEC = importlib.util.spec_from_file_location("audit_keycloak_pull_requests", MODULE_PATH)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def test_protected_promotion_sequence_is_exact() -> None:
    assert AUDIT.promotion_allowed("test", "development") == (
        True,
        "required protected promotion is development -> test",
    )
    assert AUDIT.promotion_allowed("staging", "test")[0] is True
    assert AUDIT.promotion_allowed("production", "staging")[0] is True
    assert AUDIT.promotion_allowed("main", "production")[0] is True
    assert AUDIT.promotion_allowed("production", "development")[0] is False


def test_development_accepts_only_governed_temporary_prefixes() -> None:
    for prefix in AUDIT.TEMPORARY_PREFIXES:
        assert AUDIT.promotion_allowed("development", f"{prefix}example")[0] is True
    for head in ("feature/example", "fix/example", "docs/example", "main", "test"):
        assert AUDIT.promotion_allowed("development", head)[0] is False


def test_no_checks_fails_closed() -> None:
    state, blockers = AUDIT.classify_checks([], "a" * 40)
    assert state == "ABSENT"
    assert blockers == ["no exact-head check runs observed"]


def test_failure_and_pending_checks_block() -> None:
    head = "b" * 40
    state, blockers = AUDIT.classify_checks(
        [
            {"name": "failing", "head_sha": head, "status": "completed", "conclusion": "failure"},
            {"name": "pending", "head_sha": head, "status": "in_progress", "conclusion": None},
        ],
        head,
    )
    assert state == "BLOCKED"
    assert any("failing check" in blocker for blocker in blockers)
    assert any("pending check" in blocker for blocker in blockers)


def test_check_must_be_bound_to_exact_head() -> None:
    state, blockers = AUDIT.classify_checks(
        [{"name": "test", "head_sha": "c" * 40, "status": "completed", "conclusion": "success"}],
        "d" * 40,
    )
    assert state == "BLOCKED"
    assert blockers == ["check not bound to exact head: test"]


def test_only_latest_exact_head_approval_counts() -> None:
    head = "e" * 40
    reviews = [
        {"author": "reviewer", "state": "APPROVED", "commit_id": head},
        {"author": "reviewer", "state": "CHANGES_REQUESTED", "commit_id": head},
    ]
    assert AUDIT.exact_head_approved(reviews, head) is False
    reviews.append({"author": "reviewer", "state": "APPROVED", "commit_id": head})
    assert AUDIT.exact_head_approved(reviews, head) is True


def test_stale_approval_does_not_count() -> None:
    assert AUDIT.exact_head_approved(
        [{"author": "reviewer", "state": "APPROVED", "commit_id": "f" * 40}],
        "0" * 40,
    ) is False


def test_unknown_check_conclusion_fails_closed() -> None:
    head = "1" * 40
    state, blockers = AUDIT.classify_checks(
        [{"name": "mystery", "head_sha": head, "status": "completed", "conclusion": "unexpected"}],
        head,
    )
    assert state == "BLOCKED"
    assert blockers == ["unrecognized check result: mystery (unexpected)"]
