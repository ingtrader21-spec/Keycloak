import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import verify_protected_candidate as verifier


class ProtectedCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        self.write('app.py', 'reviewed data\n')
        self.source = self.commit()
        self.policy = verifier.make_policy(self.root, self.source)
        for path in verifier.TRUST_FILES:
            self.write(path, json.dumps(self.policy) if path == verifier.POLICY else 'trusted data\n')
        self.main = self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.DEVNULL).decode().strip()

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def commit(self):
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def test_reviewed_source_with_identical_main_trust_files_passes(self):
        verifier.verify_source(self.root, self.main, self.main, self.policy)

    def test_unreviewed_file_addition_rejected(self):
        self.write('new_validator.py', 'new data\n')
        with self.assertRaisesRegex(verifier.Rejected, 'unreviewed-source-change'):
            verifier.verify_source(self.root, self.main, self.commit(), self.policy)

    def test_file_mode_change_rejected(self):
        (self.root / 'app.py').chmod(0o755)
        with self.assertRaisesRegex(verifier.Rejected, 'unreviewed-source-change'):
            verifier.verify_source(self.root, self.main, self.commit(), self.policy)

    def test_candidate_cannot_change_trust_policy(self):
        self.write(verifier.POLICY, '{}')
        with self.assertRaisesRegex(verifier.Rejected, 'candidate-trust-root-change'):
            verifier.verify_source(self.root, self.main, self.commit(), self.policy)

    def test_missing_trust_file_rejected(self):
        (self.root / 'scripts/verify_protected_candidate.py').unlink()
        with self.assertRaisesRegex(verifier.Rejected, 'candidate-trust-root-change'):
            verifier.verify_source(self.root, self.main, self.commit(), self.policy)

    def test_symlink_rejected_without_following_target(self):
        (self.root / 'link').symlink_to('/nonexistent-fixture')
        with self.assertRaisesRegex(verifier.Rejected, 'non-regular-source'):
            verifier.snapshot(self.root, self.commit())

    def test_manifest_tampering_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy['files'] = []
        with self.assertRaisesRegex(verifier.Rejected, 'policy-binding'):
            verifier.verify_source(self.root, self.main, self.main, policy)

    def test_missing_graphql_evidence_rejected(self):
        with patch.object(verifier.subprocess, 'check_output', return_value=b'{"data":null}'):
            with self.assertRaisesRegex(verifier.Rejected, 'thread-evidence-missing'):
                verifier.verify_threads(96)

    def test_graphql_errors_rejected(self):
        with patch.object(verifier.subprocess, 'check_output', return_value=b'{"errors":[{}]}'):
            with self.assertRaisesRegex(verifier.Rejected, 'thread-api-error'):
                verifier.verify_threads(96)

    def test_review_pagination_reaches_second_page(self):
        with patch.object(verifier, 'api', side_effect=[[{}] * 100, [{'review': 'next'}]]) as api:
            self.assertEqual(len(verifier.pages('fixture')), 101)
            self.assertIn('page=2', api.call_args.args[0])

    def test_later_dismissal_invalidates_approval(self):
        reviews = [{'user': {'login': 'reviewer'}, 'state': state, 'commit_id': self.main}
                   for state in ['APPROVED', 'DISMISSED']]
        with patch.object(verifier, 'pages', return_value=reviews):
            with self.assertRaisesRegex(verifier.Rejected, 'missing-independent'):
                verifier.verify_reviews(96, self.main, 'author')

    def test_bot_comment_does_not_block_eligible_approval(self):
        reviews = [{'user': {'login': 'reviewer'}, 'state': 'APPROVED', 'commit_id': self.main},
                   {'user': {'login': 'review[bot]'}, 'state': 'COMMENTED'}]
        with patch.object(verifier, 'pages', return_value=reviews), patch.object(verifier, 'api', return_value={'permission': 'write'}):
            verifier.verify_reviews(96, self.main, 'author')

    def test_pending_check_is_not_pass(self):
        checks = [{'id': i, 'name': name, 'head_sha': self.main, 'status': 'completed', 'conclusion': 'success'}
                  for i, name in enumerate(sorted(verifier.REQUIRED_CHECKS))]
        checks[0]['status'] = 'in_progress'
        with patch.object(verifier, 'api', return_value={'check_runs': checks}):
            with self.assertRaisesRegex(verifier.Rejected, 'check-not-success'):
                verifier.verify_checks(self.main)

    def test_required_check_cannot_be_absent(self):
        with patch.object(verifier, 'api', return_value={'check_runs': []}):
            with self.assertRaisesRegex(verifier.Rejected, 'required-check-missing'):
                verifier.verify_checks(self.main)

    def test_stale_approval_is_rejected(self):
        reviews = [{'user': {'login': 'reviewer'}, 'state': 'APPROVED', 'commit_id': self.source}]
        with patch.object(verifier, 'pages', return_value=reviews):
            with self.assertRaisesRegex(verifier.Rejected, 'missing-independent'):
                verifier.verify_reviews(96, self.main, 'author')

    def test_unresolved_thread_on_second_page_is_rejected(self):
        def response(resolved, more, cursor):
            return json.dumps({'data': {'repository': {'pullRequest': {'reviewThreads': {
                'nodes': [{'isResolved': resolved}],
                'pageInfo': {'hasNextPage': more, 'endCursor': cursor},
            }}}}}).encode()
        with patch.object(verifier.subprocess, 'check_output', side_effect=[
                response(True, True, 'cursor1'), response(False, False, None)]):
            with self.assertRaisesRegex(verifier.Rejected, 'unresolved-or-invalid-thread'):
                verifier.verify_threads(96)

    def test_git_replacement_does_not_change_reviewed_bytes(self):
        self.write('app.py', 'different fixture data\n')
        replacement = self.commit()
        self.git('replace', self.source, replacement)
        self.assertEqual(verifier.make_policy(self.root, self.source), self.policy)

    def test_candidate_file_deletion_rejected(self):
        (self.root / 'app.py').unlink()
        with self.assertRaisesRegex(verifier.Rejected, 'unreviewed-source-change'):
            verifier.verify_source(self.root, self.main, self.commit(), self.policy)
