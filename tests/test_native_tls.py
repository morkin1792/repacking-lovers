"""Real AOT snapshot headers must bind both VM and isolate to the known engine."""
from pathlib import Path
import struct
import unittest

from repack.native_tls import aot_snapshots, dependencies, patch_engine, NativeTlsUnsupported
from repack.rebuild import ROOT


class NativeTlsControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / '.work/flutter-native-fixture/build/native-bundle/arm64-v8a/app.so'
        if not path.is_file(): raise unittest.SkipTest('Build the known Flutter AOT fixture first')
        cls.app = path.read_bytes(); cls.pin = dependencies(); cls.expected = cls.pin['snapshot_hash']

    def test_real_vm_and_isolate_headers(self):
        result = aot_snapshots(self.app, self.expected)
        self.assertEqual(set(result), {'_kDartVmSnapshotData', '_kDartIsolateSnapshotData'})
        self.assertNotEqual(*[r['file_offset'] for r in result.values()])

    def test_forged_appended_marker_cannot_mask_wrong_header(self):
        for row in aot_snapshots(self.app, self.expected).values():
            edited = bytearray(self.app); offset = row['file_offset']
            edited[offset + 20:offset + 52] = b'0' * 32
            with self.assertRaisesRegex(NativeTlsUnsupported, 'header/hash'):
                aot_snapshots(bytes(edited) + self.expected.encode(), self.expected)

    def test_wrong_snapshot_kind_and_magic_refused(self):
        position = next(iter(aot_snapshots(self.app, self.expected).values()))['file_offset']
        for offset, payload in [(position, b'xxxx'), (position + 12, struct.pack('<Q', 2))]:
            edited = bytearray(self.app); edited[offset:offset + len(payload)] = payload
            with self.assertRaises(NativeTlsUnsupported): aot_snapshots(bytes(edited), self.expected)

    def test_wrong_architecture_and_truncated_tables_refused(self):
        for data in [self.app[:40], self.app[:600], self.app[:18] + b'\x28\0' + self.app[20:]]:
            with self.assertRaises(NativeTlsUnsupported): aot_snapshots(data, self.expected)

    def test_function_names_do_not_choose_return_convention(self):
        with self.assertRaisesRegex(NativeTlsUnsupported, 'boolean chain'):
            patch_engine(b'unknown', 'arm64-v8a', self.app, function='SSL_get_verify_result')

    def test_engine_hash_not_snapshot_substring_selects_build(self):
        with self.assertRaisesRegex(NativeTlsUnsupported, 'Unknown Flutter engine'):
            patch_engine(b'unknown' + self.expected.encode(), 'arm64-v8a', self.app)


if __name__ == '__main__': unittest.main()
