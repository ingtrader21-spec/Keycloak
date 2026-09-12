import hashlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ManifestDigestProbeTests(unittest.TestCase):
    def test_emit_validate_workflows_sha256(self):
        digest = hashlib.sha256((ROOT / "scripts/validate-workflows.py").read_bytes()).hexdigest()
        print(f"VALIDATE_WORKFLOWS_SHA256={digest}")
        self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
