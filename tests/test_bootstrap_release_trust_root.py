import hashlib
from scripts import bootstrap_release_trust_root as bootstrap
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from scripts.bootstrap_release_trust_root import load_manifest, main


class BootstrapTrustRootTests(unittest.TestCase):
    def test_rejects_unsorted_duplicate_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            entries = [{"path": "b.py", "sha256": "0" * 64}, {"path": "a.py", "sha256": "0" * 64}]
            canonical = json.dumps({"schema": "keycloak.bootstrap-closure.v1", "files": entries}, sort_keys=True, separators=(",", ":")).encode()
            path.write_text(json.dumps({"schema": "keycloak.bootstrap-closure.v1", "files": entries, "manifest_sha256": hashlib.sha256(canonical).hexdigest()}))
            with self.assertRaises(SystemExit):
                load_manifest(path)

    def test_rejects_manifest_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps({"schema": "keycloak.bootstrap-closure.v1", "files": [{"path": "a.py", "sha256": "0" * 64}], "manifest_sha256": "0" * 64}))
            with self.assertRaises(SystemExit):
                load_manifest(path)

    def test_rejects_mismatched_expected_head(self):
        with mock.patch("sys.argv", ["bootstrap", "--candidate-sha", "a" * 40, "--expected-candidate-sha", "b" * 40]):
            with self.assertRaises(SystemExit):
                main()

    def test_bootstrap_does_not_require_itself(self):
        source = Path("scripts/bootstrap_release_trust_root.py").read_text()
        self.assertNotIn('required = {"bootstrap",', source)

    def evidence_api(self, pages):
        def request(url, token, **kwargs):
            if "/reviews?" in url:
                page = int(url.rsplit("=", 1)[1])
                return pages[page - 1]
            if url.endswith("/pulls/96"):
                return {"head": {"sha": "a" * 40}, "user": {"login": "author"}}
            if url.endswith("/check-runs"):
                return {"check_runs": [{"name": name, "conclusion": "success"} for name in
                    ("validate-source", "validate-merge-result", "orchestrator-contract", "repository-name-authority")]}
            if url.endswith("/graphql"):
                return {"data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": [{"isResolved": True}]}}}}}
            self.fail("unexpected endpoint")
        return request

    def review(self, state="APPROVED", sha=None, login="reviewer"):
        return {"state": state, "commit_id": sha or "a" * 40, "user": {"login": login}}

    def test_current_approval_on_later_page_is_seen(self):
        pages = [[self.review("COMMENTED") for _ in range(100)], [self.review()]]
        with mock.patch.object(bootstrap, "github_json", side_effect=self.evidence_api(pages)) as api:
            bootstrap.verify_github_evidence("owner/repo", 96, "a" * 40, "synthetic")
        self.assertTrue(any("page=2" in call.args[0] for call in api.call_args_list))

    def test_later_revocation_cannot_leave_old_approval_active(self):
        for state in ("CHANGES_REQUESTED", "DISMISSED"):
            pages = [[self.review()] + [self.review("COMMENTED") for _ in range(99)], [self.review(state)]]
            with self.subTest(state=state), mock.patch.object(bootstrap, "github_json", side_effect=self.evidence_api(pages)):
                with self.assertRaisesRegex(SystemExit, "missing-independent-approval"):
                    bootstrap.verify_github_evidence("owner/repo", 96, "a" * 40, "synthetic")

    def test_old_head_and_self_approval_remain_rejected(self):
        for review in (self.review(sha="b" * 40), self.review(login="author")):
            with mock.patch.object(bootstrap, "github_json", side_effect=self.evidence_api([[review]])):
                with self.assertRaisesRegex(SystemExit, "missing-independent-approval"):
                    bootstrap.verify_github_evidence("owner/repo", 96, "a" * 40, "synthetic")

    def test_invalid_page_and_unbounded_pagination_fail_closed(self):
        for page, reason in (({}, "reviews-invalid"), ([None], "reviews-invalid"),
                             ([self.review()] * 100, "reviews-pagination-limit")):
            with mock.patch.object(bootstrap, "github_json", return_value=page):
                with self.assertRaisesRegex(SystemExit, reason):
                    bootstrap.github_reviews("https://api.github.com/repos/owner/repo", 96, "synthetic")


if __name__ == "__main__":
    unittest.main()
