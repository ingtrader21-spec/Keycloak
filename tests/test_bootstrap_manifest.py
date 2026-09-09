import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.bootstrap_manifest import GitSource, ManifestError, POLICY_PATH, main, propose, seal, validate_manifest


class BootstrapManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q")
        (self.root / "scripts").mkdir()
        (self.root / "config/bootstrap").mkdir(parents=True)
        (self.root / "scripts/check.py").write_text("original\n")
        self.policy = seal([{"path": "scripts/check.py", "sha256": hashlib.sha256(b"original\n").hexdigest()}])
        (self.root / POLICY_PATH).write_text(json.dumps(self.policy))
        self.policy_sha = self.commit()
        (self.root / "scripts/check.py").write_text("changed\n")
        self.source_sha = self.commit()
        self.source = GitSource(self.root)

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.DEVNULL).decode().strip()

    def commit(self):
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def test_proposal_is_deterministic_and_bound_to_exact_source(self):
        one = propose(self.source, self.policy_sha, self.source_sha)
        (self.root / "scripts/check.py").write_text("uncommitted changes must not be read")
        self.assertEqual(one, propose(self.source, self.policy_sha, self.source_sha))
        self.assertEqual(one["reviewed_source_sha"], self.source_sha)
        self.assertEqual(one["authorization"], "PENDING_INDEPENDENT_REVIEW")
        self.assertEqual(len(one["changes"]), 1)
        self.assertEqual(one["manifest"]["files"][0]["sha256"], hashlib.sha256(b"changed\n").hexdigest())
        validate_manifest(one["manifest"])

    def test_all_proposal_object_reads_disable_replacements(self):
        execute = subprocess.check_output
        commands = []

        def checked_read(command, **kwargs):
            self.assertEqual(command[:2], ["git", "--no-replace-objects"])
            commands.append(command)
            return execute(command, **kwargs)

        with patch("scripts.bootstrap_manifest.subprocess.check_output", side_effect=checked_read):
            proposal = propose(self.source, self.policy_sha, self.source_sha)
        self.assertTrue(any("ls-tree" in command for command in commands))
        self.assertTrue(any("cat-file" in command for command in commands))
        self.assertEqual(proposal["reviewed_source_sha"], self.source_sha)
        self.assertEqual(proposal["manifest"]["files"][0]["sha256"],
                         hashlib.sha256(b"changed\n").hexdigest())

    def test_unchanged_source_has_no_changes(self):
        self.assertEqual(propose(self.source, self.policy_sha, self.policy_sha)["changes"], [])

    def test_missing_source_is_rejected(self):
        (self.root / "scripts/check.py").unlink()
        with self.assertRaises(ManifestError):
            propose(self.source, self.policy_sha, self.commit())

    def test_symlink_is_rejected_without_reading_its_target(self):
        path = self.root / "scripts/check.py"
        path.unlink()
        path.symlink_to("/etc/passwd")
        with self.assertRaises(ManifestError):
            propose(self.source, self.policy_sha, self.commit())

    def test_branch_name_and_abbreviated_sha_are_rejected(self):
        for ref in ("HEAD", self.source_sha[:7], "-bad"):
            with self.subTest(ref=ref), self.assertRaises(ManifestError):
                propose(self.source, self.policy_sha, ref)

    def test_non_commit_object_is_rejected(self):
        blob = self.git("rev-parse", self.source_sha + ":scripts/check.py")
        with self.assertRaises(ManifestError):
            self.source.require_commit(blob)

    def test_path_escapes_and_noncanonical_paths_are_rejected(self):
        for path in ("../file", "/file", "a/../b", "a//b", "./file", "a\\b", ".git/config", "a\nb", ""):
            policy = seal([{"path": path, "sha256": "0" * 64}])
            with self.subTest(path=path), self.assertRaises(ManifestError):
                validate_manifest(policy)

    def test_duplicate_and_unsorted_paths_are_rejected(self):
        entry = self.policy["files"][0]
        for entries in ([entry, entry], [dict(entry, path="z.py"), entry]):
            with self.subTest(entries=entries), self.assertRaises(ManifestError):
                validate_manifest(seal(entries))

    def test_invalid_digest_types_and_formats_are_rejected(self):
        for digest in (None, 123, "z" * 64, "A" * 64, "0" * 63):
            with self.subTest(digest=digest), self.assertRaises(ManifestError):
                validate_manifest(seal([{"path": "a.py", "sha256": digest}]))

    def test_manifest_digest_is_checked(self):
        policy = copy.deepcopy(self.policy)
        policy["manifest_sha256"] = "0" * 64
        with self.assertRaises(ManifestError):
            validate_manifest(policy)

    def test_cli_cannot_overwrite_active_policy(self):
        path = self.root / POLICY_PATH
        before = path.read_bytes()
        self.assertEqual(main(["--repository", str(self.root), "--policy-sha", self.policy_sha,
                               "--source-sha", self.source_sha, "--output", str(path)]), 1)
        self.assertEqual(path.read_bytes(), before)

    def test_cli_does_not_overwrite_existing_proposal(self):
        path = self.root / "proposal.json"
        path.write_text("reviewed content")
        self.assertEqual(main(["--repository", str(self.root), "--policy-sha", self.policy_sha,
                               "--source-sha", self.source_sha, "--output", str(path)]), 1)
        self.assertEqual(path.read_text(), "reviewed content")


if __name__ == "__main__":
    unittest.main()
