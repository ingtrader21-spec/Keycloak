import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('kyyow_identity', ROOT / 'scripts/validate-kyyow-identity.py')
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


def leaves(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaves(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from leaves(child, path + (index,))
    else:
        yield path, value


class KyyowIdentityTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads((ROOT / 'contracts/kyyow-saas-identity-v1.json').read_text())

    def test_contract_is_fail_closed(self):
        POLICY.validate(self.contract)

    def test_every_declared_policy_value_is_enforced(self):
        for path, value in leaves(self.contract):
            with self.subTest(path=path):
                changed = copy.deepcopy(self.contract)
                parent = changed
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = not value if isinstance(value, bool) else 301 if isinstance(value, int) else 'unapproved'
                with self.assertRaises(ValueError):
                    POLICY.validate(changed)

    def test_missing_unknown_and_wrong_types_are_rejected(self):
        for field in self.contract:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.contract)
                del changed[field]
                with self.assertRaises(ValueError):
                    POLICY.validate(changed)
        self.contract['security']['undeclared'] = False
        with self.assertRaises(ValueError):
            POLICY.validate(self.contract)

    def test_token_lifetime_bounds_and_boolean_types(self):
        for key in ('access_token_lifespan_seconds', 'service_token_lifespan_seconds'):
            for value in (0, -1, 301, True, '300', 300.0):
                with self.subTest(key=key, value=value):
                    changed = copy.deepcopy(self.contract)
                    changed['token_policy'][key] = value
                    with self.assertRaises(ValueError):
                        POLICY.validate(changed)
            changed = copy.deepcopy(self.contract)
            changed['token_policy'][key] = 60
            POLICY.validate(changed)

    def test_optimized_python_keeps_validation_enabled(self):
        for flag in ([], ['-O'], ['-OO']):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'contract.json'
                changed = copy.deepcopy(self.contract)
                changed['security']['deployment_authorized'] = True
                path.write_text(json.dumps(changed))
                result = subprocess.run([sys.executable, *flag, str(ROOT / 'scripts/validate-kyyow-identity.py'), '--contract', str(path)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('KYYOW_IDENTITY_CONTRACT=FAIL', result.stderr)
                self.assertNotIn('KYYOW_IDENTITY_CONTRACT=PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
