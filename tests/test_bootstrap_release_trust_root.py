import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.bootstrap_release_trust_root import load_manifest


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


if __name__ == "__main__":
    unittest.main()
