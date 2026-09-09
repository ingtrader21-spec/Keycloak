"""Check real aggregate shell logic for all terminal dependency combinations."""
import itertools
import os
from pathlib import Path
import subprocess
import unittest
import yaml


class AggregateTests(unittest.TestCase):
    def test_only_applicable_successes_pass(self):
        root = Path(__file__).resolve().parents[2]
        workflow = yaml.safe_load((root / '.github/workflows/validate.yml').read_text())
        script = workflow['jobs']['validate']['steps'][0]['run']
        states = ['success', 'failure', 'cancelled', 'skipped']
        for event in ['pull_request', 'push', 'workflow_dispatch']:
            for source, merge in itertools.product(states, repeat=2):
                expected = source == 'success' and (
                    event == 'pull_request' and merge == 'success' or
                    event == 'push' and merge == 'skipped')
                with self.subTest(event=event, source=source, merge=merge):
                    result = subprocess.run(['bash', '-c', script], env={
                        **os.environ, 'EVENT_NAME': event, 'SOURCE_RESULT': source,
                        'MERGE_RESULT': merge,
                    }, capture_output=True)
                    self.assertEqual(result.returncode == 0, expected)
