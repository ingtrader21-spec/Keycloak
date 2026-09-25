"""MCR denial tests: removing any boundary must break these checks."""
import copy
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class McrIdentityTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / 'scripts/validate_mcr_identity.py').exists(),
                        'MCR identity validator is required')
        self.policy = importlib.import_module('scripts.validate_mcr_identity')
        self.contract = self.policy.load_json(self.policy.CONTRACT_PATH)
        self.matrix = self.policy.load_json(self.policy.MATRIX_PATH)

    def test_contract_and_matrix(self):
        self.policy.validate_contract(self.contract)
        report = self.policy.certify_matrix(self.contract, self.matrix)
        self.assertGreaterEqual(report['negativeCases'], 25)
        self.assertEqual(report['positiveCases'], 3)

    def test_all_policy_leaves_are_pinned(self):
        def leaves(node, path=()):
            if isinstance(node, dict):
                for key, value in node.items():
                    yield from leaves(value, path + (key,))
            elif isinstance(node, list):
                for key, value in enumerate(node):
                    yield from leaves(value, path + (key,))
            else:
                yield path, node
        for path, value in leaves(self.contract):
            with self.subTest(path=path):
                changed = copy.deepcopy(self.contract)
                parent = changed
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = not value if type(value) is bool else 'unapproved'
                with self.assertRaises(ValueError):
                    self.policy.validate_contract(changed)

    def test_no_missing_claim_can_authorize(self):
        for name, fixture in self.matrix['fixtures'].items():
            for claim in self.contract['requiredClaims']:
                with self.subTest(fixture=name, claim=claim):
                    changed = copy.deepcopy(fixture)
                    del changed['claims'][claim]
                    self.assertTrue(self.policy.evaluate(self.contract, changed))

    def test_malformed_inputs_reject_without_crashing(self):
        fixture = self.matrix['fixtures']['humanReplay']
        for value in (None, [], '', True, 1):
            self.assertTrue(self.policy.evaluate(self.contract, value))
            for field in fixture:
                if type(value) is type(fixture[field]) and value == fixture[field]:
                    continue
                changed = copy.deepcopy(fixture)
                changed[field] = value
                with self.subTest(field=field, value=value):
                    self.assertTrue(self.policy.evaluate(self.contract, changed))

    def test_matrix_cannot_drop_or_duplicate_cases(self):
        for mutate in (lambda m: m['cases'].pop(),
                       lambda m: m['cases'].append(m['cases'][0]),
                       lambda m: m['cases'][0].update(expect='REJECT')):
            changed = copy.deepcopy(self.matrix)
            mutate(changed)
            with self.assertRaises(ValueError):
                self.policy.certify_matrix(self.contract, changed)

    def test_empty_registry_and_unknown_operation_deny(self):
        for field, value in [('bindings', []), ('operation', 'unknown')]:
            fixture = copy.deepcopy(self.matrix['fixtures']['humanReplay'])
            fixture[field] = value
            self.assertTrue(self.policy.evaluate(self.contract, fixture))

    def test_human_tenant_source_and_family_alias_azp_deny(self):
        fixture = copy.deepcopy(self.matrix['fixtures']['humanReplay'])
        fixture['bindings'][0]['tenantBinding'] = 'request-header'
        self.assertIn('tenant', self.policy.evaluate(self.contract, fixture))
        fixture = copy.deepcopy(self.matrix['fixtures']['humanReplay'])
        fixture['claims']['azp'] = 'platform-command-family'
        fixture['bindings'][0]['azp'] = 'platform-command-family'
        self.assertIn('azp', self.policy.evaluate(self.contract, fixture))

    def test_replay_target_tenant_must_match(self):
        fixture = copy.deepcopy(self.matrix['fixtures']['humanReplay'])
        fixture['operationTenant'] = 'OTHER_TENANT'
        self.assertIn('tenant', self.policy.evaluate(self.contract, fixture))

    def test_cli_rejects_policy_changes_even_when_optimized(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'contract.json'
            changed = copy.deepcopy(self.contract)
            changed['runtimeApplyAuthorized'] = True
            path.write_text(json.dumps(changed))
            for flag in ([], ['-O'], ['-OO']):
                result = subprocess.run([sys.executable, *flag,
                    str(ROOT / 'scripts/validate_mcr_identity.py'), '--contract', str(path)],
                    capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('MCR_IDENTITY_CONTRACT=FAIL', result.stdout)

    def test_duplicate_json_fields_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'duplicate.json'
            path.write_text('{"enabled": false, "enabled": true}')
            with self.assertRaises(ValueError):
                self.policy.load_json(path)

    def test_unknown_contract_fields_deny(self):
        self.contract['activation'] = True
        with self.assertRaises(ValueError):
            self.policy.validate_contract(self.contract)


if __name__ == '__main__':
    unittest.main()

def test_binding_scopes_and_roles_must_be_string_arrays():
    import copy, json
    from pathlib import Path
    from scripts import validate_mcr_identity as mcr

    root = Path(__file__).resolve().parents[1]
    contract = json.loads((root / "contracts/mcr-identity-v1.json").read_text())
    matrix = json.loads((root / "config/certification/mcr-token-matrix.v1.json").read_text())
    fixture = copy.deepcopy(matrix["positive"][0])

    for field, value in (
        ("scopes", {"platform.command.replay": False}),
        ("roles", {"platform-operator": False}),
    ):
        changed = copy.deepcopy(fixture)
        changed["bindings"][0][field] = value
        assert mcr.evaluate(contract, changed)
