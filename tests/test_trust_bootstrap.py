"""Trusted-base snapshot checks: candidate bytes are always data."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('trust_bootstrap', ROOT / '.github/trust-root/verify.py')
TRUST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRUST)


def snapshot(files):
    blobs = {}
    entries = []
    for path, content in files.items():
        oid = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
        blobs[oid] = content
        entries.append(dict(path=path, mode='100644', type='blob', sha=oid))
    return TRUST.manifest(entries, blobs.__getitem__)


class TrustBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.base = snapshot({'.github/trust-root/verify.py': b'trusted',
                              '.github/workflows/trust-bootstrap.yml': b'base workflow',
                              'scripts/check.py': b'old'})
        self.candidate = snapshot({'.github/trust-root/verify.py': b'trusted',
                                   '.github/workflows/trust-bootstrap.yml': b'base workflow',
                                   'scripts/check.py': b'raise RuntimeError("never execute")'})
        self.approved = TRUST.source_only(self.candidate)
        self.policy = dict(schema_version=1, repository=TRUST.REPOSITORY,
                           protected_branch='main', required_check_context='keycloak-independent-source-authority',
                           required_check_app_id=123, approved_manifest_sha256=TRUST.digest(self.approved))

    def verify(self):
        return TRUST.verify(self.policy, self.base, self.candidate, self.approved)

    def test_matching_snapshot_is_non_authorizing_observation(self):
        result = self.verify()
        self.assertEqual(result['source_observation'], 'PASS')
        self.assertFalse(result['merge_authorized'])

    def test_unconfigured_policy_blocks(self):
        for field in ('required_check_app_id', 'approved_manifest_sha256'):
            with self.subTest(field=field):
                policy = dict(self.policy, **{field: None})
                with self.assertRaises(TRUST.Rejected):
                    TRUST.verify(policy, self.base, self.candidate, self.approved)

    def test_github_actions_is_not_independent_authority(self):
        self.policy["required_check_app_id"] = 15368
        with self.assertRaises(TRUST.Rejected):
            self.verify()

    def test_candidate_cannot_edit_add_or_remove_trust_root(self):
        for operation in ('edit', 'add', 'remove'):
            with self.subTest(operation=operation):
                candidate = copy.deepcopy(self.candidate)
                if operation == 'edit':
                    candidate['files'][0]['sha256'] = '0' * 64
                elif operation == 'remove':
                    candidate['files'].pop(0)
                else:
                    candidate['files'].append(dict(path='.github/trust-root/new.py', mode='100644', sha256='0'*64))
                with self.assertRaises(TRUST.Rejected):
                    TRUST.verify(self.policy, self.base, candidate, self.approved)

    def test_unlisted_stale_modified_and_mode_changed_source_blocks(self):
        for operation in ('add', 'remove', 'edit', 'mode'):
            with self.subTest(operation=operation):
                candidate = copy.deepcopy(self.candidate)
                if operation == 'add':
                    candidate['files'].append(dict(path='unlisted.py', mode='100644', sha256='0'*64))
                elif operation == 'remove':
                    candidate['files'].pop()
                elif operation == 'edit':
                    candidate['files'][-1]['sha256'] = '0' * 64
                else:
                    candidate['files'][-1]['mode'] = '100755'
                with self.assertRaises(TRUST.Rejected):
                    TRUST.verify(self.policy, self.base, candidate, self.approved)

    def test_approved_manifest_digest_is_bound(self):
        self.policy['approved_manifest_sha256'] = '0' * 64
        with self.assertRaises(TRUST.Rejected):
            self.verify()

    def test_paths_cannot_escape(self):
        for path in ('../x', '/x', 'a/../x', 'a//x', './x', 'a\\x', '.git/config', 'a\nx'):
            with self.subTest(path=path), self.assertRaises(TRUST.Rejected):
                TRUST.safe_path(path)

    def test_special_files_and_duplicate_paths_rejected(self):
        content = b'x'
        oid = hashlib.sha1(b'blob 1\0x').hexdigest()
        entry = dict(path='x', mode='100644', type='blob', sha=oid)
        for mode, kind in (('120000', 'blob'), ('160000', 'commit')):
            with self.subTest(mode=mode), self.assertRaises(TRUST.Rejected):
                TRUST.manifest([dict(entry, mode=mode, type=kind)], lambda _: content)
        with self.assertRaises(TRUST.Rejected):
            TRUST.manifest([entry, entry], lambda _: content)

    def test_blob_identity_and_size_verified(self):
        entry = dict(path='x', mode='100644', type='blob', sha='0' * 40)
        with self.assertRaises(TRUST.Rejected):
            TRUST.manifest([entry], lambda _: b'x')
        with self.assertRaises(TRUST.Rejected):
            TRUST.manifest([entry], lambda _: b'x' * (TRUST.MAX_BLOB + 1))

    def test_manifest_order_is_deterministic(self):
        self.assertEqual(snapshot({'b': b'2', 'a': b'1'}), snapshot({'a': b'1', 'b': b'2'}))

    def test_approved_duplicate_and_unsorted_paths_rejected(self):
        for files in ([self.approved['files'][0]] * 2,
                      [dict(self.approved['files'][0], path='z'), self.approved['files'][0]]):
            with self.subTest(files=files), self.assertRaises(TRUST.Rejected):
                TRUST.validate_snapshot(dict(self.approved, files=files))


if __name__ == '__main__':
    unittest.main()
