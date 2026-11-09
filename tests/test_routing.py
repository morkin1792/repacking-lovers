"""Routing boundaries: configuration, independent evidence, and mapping ownership."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from repack.rebuild import PrerequisiteError
from repack.shim import parse_proxy
from repack.verify import owned_reverse, reverse_service
from scripts.routing_cases import compare_response


class RoutingControls(unittest.TestCase):
    def test_endpoints_normalize_and_reject_ambiguous_or_unsafe_values(self):
        self.assertEqual(parse_proxy('LOCALHOST:08080'), {'host': 'localhost', 'port': 8080})
        self.assertEqual(parse_proxy('[2001:0db8::1]:443'), {'host': '2001:db8::1', 'port': 443})
        for value in ('', 'host', 'host:0', 'host:65536', 'http://host:80', 'host:80/path',
                      'host:80?query', 'host:80#fragment', 'u@host:80', 'bad host:80', 'host:80\n',
                      '::1:80', '[fe80::1%eth0]:80', '-host:80', 'a..b:80', '999.1.1.1:80'):
            with self.subTest(value=value), self.assertRaises(ValueError): parse_proxy(value)

    def test_matching_app_echo_without_independent_proxy_request_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'requests.jsonl'
            config = {'run_id': 'controlled-token'}
            event = {'event': 'response', 'comparison': 'passed',
                     'response_marker': json.dumps({'token': config['run_id'], 'via': 'proxy'})}
            with self.assertRaises(RuntimeError): compare_response({'comparisons': []}, config, event, path, 'proxy')
            path.write_text(json.dumps({'token': config['run_id'], 'tls': False}) + '\n')
            with self.assertRaises(RuntimeError): compare_response({'comparisons': []}, config, event, path, 'proxy', tls=True)
            result = {'comparisons': []}; compare_response(result, config, event, path, 'proxy')
            self.assertEqual(len(result['comparisons']), 1)

    def test_existing_mapping_refused_before_mutation(self):
        with tempfile.TemporaryDirectory() as folder, patch('repack.verify.adb', return_value=
                subprocess.CompletedProcess([], 0, 'UsbFfs tcp:8080 tcp:9999\n', '')), \
                patch('repack.verify.reverse_service') as service:
            with self.assertRaises(PrerequisiteError):
                with owned_reverse({}, 'serial', 8080, '127.0.0.1', 8080, Path(folder), 'case', [], []): pass
            service.assert_not_called()

    def test_cleanup_does_not_remove_replacement_mapping(self):
        replies = ['', 'UsbFfs tcp:8080 tcp:operator:9999\n']
        with tempfile.TemporaryDirectory() as folder, patch('repack.verify.adb', side_effect=
                [subprocess.CompletedProcess([], 0, value, '') for value in replies]), \
                patch('repack.verify.shell', return_value=subprocess.CompletedProcess([], 0, 'LISTEN 0 0 127.0.0.1:8080 *:*\n', '')), \
                patch('repack.verify.reverse_service', return_value='8080') as service:
            cleanup = []
            with owned_reverse({}, 'serial', 8080, '127.0.0.1', 8080, Path(folder), 'case', [], cleanup): pass
            self.assertEqual(service.call_count, 1)
            self.assertEqual(cleanup[0]['verification'], 'skipped')

    def test_smart_socket_handles_fragmented_protocol_and_keeps_explicit_destination(self):
        class Connection:
            def __init__(self): self.buffer = b'OKAYOKAYOKAY00048080'; self.sent = []
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def sendall(self, data): self.sent.append(data)
            def recv(self, count):
                result = self.buffer[:1]; self.buffer = self.buffer[1:]; return result
        connection = Connection()
        with tempfile.TemporaryDirectory() as folder, patch('repack.verify.environment', return_value={
                'ADB_SERVER_SOCKET': 'tcp:127.0.0.1:5037'}), \
                patch('repack.verify.socket.create_connection', return_value=connection):
            response = reverse_service({}, 'serial', 'forward:norebind:tcp:localhost:8080;tcp:10.20.30.2:8080',
                                       Path(folder), 'case')
            self.assertEqual(response, '8080')
            self.assertIn(b'tcp:10.20.30.2:8080', connection.sent[-1])
            self.assertEqual(json.loads((Path(folder) / 'case-smart-socket.json').read_text())['verification'], 'passed')

    def test_server_loss_records_pending_cleanup_without_masking_request_error(self):
        with tempfile.TemporaryDirectory() as folder, patch('repack.verify.adb', side_effect=[
                subprocess.CompletedProcess([], 0, '', ''), PrerequisiteError('server gone')]), \
                patch('repack.verify.shell', return_value=subprocess.CompletedProcess([], 0, 'LISTEN 0 0 127.0.0.1:8080 *:*\n', '')), \
                patch('repack.verify.reverse_service', return_value='8080'):
            cleanup = []
            with self.assertRaisesRegex(RuntimeError, 'original request error'):
                with owned_reverse({}, 'serial', 8080, '127.0.0.1', 8080, Path(folder), 'case', [], cleanup):
                    raise RuntimeError('original request error')
            self.assertTrue(cleanup[0]['pending'])
            self.assertEqual(cleanup[0]['verification'], 'inconclusive')


if __name__ == '__main__': unittest.main()
