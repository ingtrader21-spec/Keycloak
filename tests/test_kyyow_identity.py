import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class KyyowIdentityTests(unittest.TestCase):
    def test_contract_is_fail_closed(self):
        result = subprocess.run(
            ["python3", "scripts/validate-kyyow-identity.py"], cwd=ROOT,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("KYYOW_IDENTITY_CONTRACT=PASS", result.stdout)

if __name__ == "__main__":
    unittest.main()
