"""Negative controls for M0 evidence handling, using the retained baseline reports."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from repack.rebuild import ROOT, PrerequisiteError, execute, report, report_reference, sha256, write_json
from scripts.acceptance import gate_m0, launch_query, read_events


class EvidenceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        baseline = ROOT / '.work/evidence/T-A00.json'
        if not baseline.exists():
            raise unittest.SkipTest('Run the real M0 baseline first')
        cls.baseline = json.loads(baseline.read_text())
        if cls.baseline['verification'] != 'passed':
            raise unittest.SkipTest('A successful observed baseline is required')
        cls.token = cls.baseline['comparisons'][0]['token']
        cls.raw = (Path(cls.baseline['logs'][0]) / 'own-query-0-logcat.stdout.log').read_text()

    def test_stale_token_cannot_satisfy_query(self):
        self.assertEqual(len(read_events(self.raw, self.token)), 1)
        self.assertEqual(read_events(self.raw, 'different-fresh-run'), [])

    def test_missing_event_field_is_rejected(self):
        value = copy.deepcopy(read_events(self.raw, self.token)[0])
        del value['flags']
        with self.assertRaisesRegex(RuntimeError, 'v1 event schema'):
            read_events('REPACK_FIXTURE: ' + json.dumps(value), self.token)

    def test_tampered_summary_cannot_satisfy_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ('M0-host', 'M0-device', 'M0-build', 'T-A00'):
                shutil.copyfile(ROOT / '.work/evidence' / (name + '.json'), directory / (name + '.json'))
            path = directory / 'M0-host.json'
            changed = json.loads(path.read_text())
            changed['tools']['javac']['version_output'] = 'tampered-index'
            write_json(path, changed)
            result = {'verification': 'not-run'}
            with self.assertRaisesRegex(RuntimeError, 'summary differs'):
                gate_m0(result, directory, SimpleNamespace(reports=directory))

    def test_timeout_retains_output_and_failure_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            done = execute([sys.executable, '-c', 'import time; print("started", flush=True); time.sleep(2)'],
                           directory, 'timeout-control', timeout=0.5, check=False)
            self.assertEqual(done.returncode, 124)
            self.assertIn('started', (directory / 'timeout-control.stdout.log').read_text())
            self.assertTrue(json.loads((directory / 'timeout-control.command.json').read_text())['timed_out'])

    def test_gate_reference_survives_summary_rotation(self):
        original_index = ROOT / '.work/evidence/M0-host.json'
        original = json.loads(original_index.read_text())
        frozen = report_reference(original_index)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            index = directory / 'host.json'
            write_json(index, original)
            self.assertEqual(report_reference(index)['path'], frozen['path'])
            replacement = copy.deepcopy(original)
            replacement['run_id'] = 'replacement-run'
            replacement['evidence_refs'] = []
            raw = directory / 'new-immutable.json'
            write_json(raw, replacement)
            replacement['evidence_refs'] = [str(raw)]
            write_json(index, replacement)
            self.assertNotEqual(report_reference(index)['path'], frozen['path'])
            self.assertEqual(sha256(Path(frozen['path'])), frozen['sha256'])

    def query_recreation(self, conflict=False):
        event = copy.deepcopy(read_events(self.raw, self.token)[0])
        second = copy.deepcopy(event)
        if conflict:
            second['actual_signer_sha256'] = ['0' * 64]
        logs = '\n'.join('REPACK_FIXTURE: ' + json.dumps(x) for x in (event, second))
        def fake_shell(lock, evidence, label, serial, args, **kwargs):
            value = logs if label.endswith('-logs') else str(event['pid']) if label.endswith('-pid') else ''
            return subprocess.CompletedProcess(args, 0, value, '')
        with tempfile.TemporaryDirectory() as temporary, patch('scripts.acceptance.shell', side_effect=fake_shell):
            artifact = {'package': event['process']}
            observed, _, _, _ = launch_query(artifact, 'fixture-serial', self.token, event['case_id'],
                    event['expected_signer_sha256'], event['package'], event['query_path'], {}, Path(temporary), 'recreation')
            evidence = json.loads((Path(temporary) / 'recreation-query-observation.json').read_text())
            self.assertEqual(evidence['identical_observation_count'], 2)
            self.assertEqual(observed, event)

    def test_identical_activity_recreation_is_recorded(self):
        self.query_recreation()

    def test_conflicting_activity_recreation_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'missing or ambiguous'):
            self.query_recreation(conflict=True)


if __name__ == '__main__':
    unittest.main()
