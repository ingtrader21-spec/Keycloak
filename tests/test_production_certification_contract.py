import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ProductionContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for path in ("scripts/validate-production-certification.py", "scripts/certify-kong.sh",
                     "scripts/apply-plan.sh", ".github/workflows/deploy.yml",
                     "config/certification/service-identity-matrix.json",
                     "config/github/production-environment.json",
                     "config/contracts/machine-secret-destinations.json",
                     "config/endpoints/codestra.json", "config/endpoints/codestra-staging.json"):
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, destination)

    def run_validator(self):
        return subprocess.run([sys.executable, "-O", str(self.root / "scripts/validate-production-certification.py")],
                              text=True, capture_output=True)

    def test_valid_contract_under_optimized_python(self):
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PRODUCTION_MUTATION_ALLOWED=NO", result.stdout)

    def test_enabling_production_does_not_bypass_optimized_validation(self):
        path = self.root / "config/certification/service-identity-matrix.json"
        data = json.loads(path.read_text())
        data["productionMutationAllowed"] = True
        path.write_text(json.dumps(data))
        self.assertNotEqual(self.run_validator().returncode, 0)

    def test_distinct_but_noncanonical_issuer_is_rejected(self):
        path = self.root / "config/certification/service-identity-matrix.json"
        data = json.loads(path.read_text())
        data["stagingIssuer"] = "https://other.invalid/realms/codestra"
        path.write_text(json.dumps(data))
        self.assertNotEqual(self.run_validator().returncode, 0)

    def test_direct_production_apply_stops_before_validation_or_auth(self):
        # No credentials or runtime are present. Structurally valid input paths
        # must reach the production stop flag before any validation/authentication.
        plan = self.root / "plan.json"
        review = self.root / "review.json"
        plan.write_text("{}")
        review.write_text("{}")
        result = subprocess.run([
            "bash", str(ROOT / "scripts/apply-plan.sh"), "--plan", str(plan),
            "--expected-plan-sha", "a" * 64, "--review", str(review),
            "--expected-review-sha", "b" * 64, "--expected-deploy-sha", "c" * 40,
            "--recovery-dir", str(self.root / "recovery"),
        ], env={"DEPLOY_ENVIRONMENT": "production", "PATH": "/usr/bin:/bin"}, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("production_mutation_not_authorized_by_certification_contract", result.stderr)
        self.assertNotIn("VALIDATION=", result.stdout)
        self.assertFalse((self.root / "recovery").exists())


if __name__ == "__main__":
    unittest.main()
