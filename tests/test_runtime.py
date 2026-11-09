"""Recorded TLS evidence needs a matching process response and bounded artifact/action contract."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from repack.runtime import assess, read_packet, validate_packet
from repack.report import render_review
from scripts.verification_cases import bundle


class RuntimeControls(unittest.TestCase):
    def setUp(self):
        self.packet = {'schema_version': 1, 'adapter': 'fixture-https-v1', 'serial': 'fixture-serial',
            'package': 'dev.repack.fixture.identity', 'artifact_sha256': 'a' * 64, 'token': 'controlled-fresh-token',
            'process': {'pid': 123, 'name': 'dev.repack.fixture.identity'},
            'action': {'name': 'controlled-fixture-HTTPS', 'trigger': 'adb-am-broadcast',
                'component': 'dev.repack.fixture.identity/dev.repack.fixture.common.NetworkReceiver', 'start_epoch_s': 100., 'end_epoch_s': 110.},
            'endpoint': {'scheme': 'https', 'host': '127.0.0.1', 'port': 18443, 'method': 'GET', 'path': '/repack/controlled-fresh-token'},
            'references': {'proxy_log': {'path': 'proxy.jsonl', 'sha256': 'b' * 64}, 'app_log': {'path': 'app.log', 'sha256': 'c' * 64}}}
        self.traffic = {'kind': 'http', 'timestamp_start': 105., 'tls': True, **self.packet['endpoint']}
        self.event = {'schema_version': 1, 'run_id': self.packet['token'], 'pid': 123, 'process': self.packet['package'],
            'package': self.packet['package'], 'event': 'response', 'comparison': 'passed',
            'response_marker': json.dumps({'token': self.packet['token'], 'via': 'proxy'})}

    def test_only_paired_tls_and_response_can_pass(self):
        self.assertEqual(assess(self.packet, [self.traffic], [self.event])['runtime_verification'], 'passed')
        for traffic, events in [([], [self.event]), ([self.traffic], []), ([], [])]:
            self.assertNotEqual(assess(self.packet, traffic, events)['runtime_verification'], 'passed')

    def test_connect_cleartext_wrong_endpoint_and_stale_requests_never_pass(self):
        for update in [{'kind': 'connect'}, {'tls': False}, {'tls': 'true'}, {'host': 'unrelated.example'},
                {'port': 443}, {'method': 'POST'}, {'timestamp_start': 99.}, {'timestamp_start': float('nan')}]:
            with self.subTest(update=update):
                self.assertNotEqual(assess(self.packet, [{**self.traffic, **update}], [self.event])['runtime_verification'], 'passed')

    def test_claimed_comparison_field_does_not_replace_response_or_pid(self):
        for update in [{'response_marker': '{}'}, {'pid': 124}, {'pid': True}, {'package': 'other.app'}, {'schema_version': True}]:
            with self.subTest(update=update):
                self.assertNotEqual(assess(self.packet, [self.traffic], [{**self.event, **update}])['runtime_verification'], 'passed')

    def test_conflicting_observations_fail_but_identical_duplicates_are_counted(self):
        result = assess(self.packet, [self.traffic], [self.event, self.event])
        self.assertEqual(result['runtime_verification'], 'passed'); self.assertEqual(result['observations']['correlated_app_events'], 2)
        conflict = {**self.event, 'response_marker': '{}'}
        self.assertEqual(assess(self.packet, [self.traffic], [self.event, conflict])['runtime_verification'], 'failed')

    def test_manual_capture_never_auto_attributes_a_response(self):
        packet = copy.deepcopy(self.packet); packet['adapter'] = 'manual-https-v1'; packet['action']['trigger'] = 'manual'
        self.assertEqual(assess(packet, [self.traffic], [self.event])['runtime_verification'], 'inconclusive')

    def test_invalid_capture_window_and_real_app_fixture_claim_are_refused(self):
        for update in [{'start_epoch_s': True}, {'end_epoch_s': 10000.}, {'start_epoch_s': float('nan')}]:
            packet = copy.deepcopy(self.packet); packet['action'].update(update)
            with self.assertRaises(ValueError): validate_packet(packet)
        packet = copy.deepcopy(self.packet); packet['package'] = packet['process']['name'] = 'real.target'
        with self.assertRaises(ValueError): validate_packet(packet)

    def test_hash_modified_reference_and_escape_cannot_satisfy_packet(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = bundle(Path(temporary) / 'packet', self.packet, [self.traffic], 'REPACK_FIXTURE: ' + json.dumps(self.event))
            packet, traffic, app = read_packet(path)
            self.assertEqual(assess(packet, traffic, app)['runtime_verification'], 'passed')
            (path.parent / 'proxy.jsonl').write_text('{}\n')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'): read_packet(path)
            packet['references']['proxy_log']['path'] = '../outside'
            path.write_text(json.dumps(packet))
            with self.assertRaisesRegex(ValueError, 'escapes'): read_packet(path)

    def test_review_omits_payload_and_cannot_overwrite_existing_file(self):
        result = assess(self.packet, [self.traffic], [self.event]); result['private_payload'] = 'PRIVATE-BODY-SECRET'
        result['artifact_manifest'] = '/operator/artifact.json'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'review.md'; render_review(result, path)
            self.assertNotIn('PRIVATE-BODY-SECRET', path.read_text()); self.assertNotIn(self.packet['token'], path.read_text())
            with self.assertRaises(FileExistsError): render_review(result, path)


if __name__ == '__main__': unittest.main()
