"""Keep verified distribution stamps separate from platform signing identity."""
import hashlib
from pathlib import Path
import ssl
from subprocess import CompletedProcess
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from repack.recon import signing_metadata
from repack.rebuild import copy_archive


class SigningMetadataControls(unittest.TestCase):
    def output(self, stamp=True, bad=False):
        certificate = b'APK signer DER control'
        digest = hashlib.sha256(certificate).hexdigest() if not bad else '0' * 64
        text = ('Verified using v2 scheme (APK Signature Scheme v2): true\n'
                'Verified using v3 scheme (APK Signature Scheme v3): false\n'
                'Signer #1 certificate SHA-256 digest: ' + digest + '\n' + ssl.DER_cert_to_PEM_cert(certificate))
        if stamp:
            text += ('Source Stamp Signer certificate DN: CN=Distribution\n'
                     'Source Stamp Signer certificate SHA-256 digest: ' + hashlib.sha256(b'stamp').hexdigest()
                     + '\n' + ssl.DER_cert_to_PEM_cert(b'stamp'))
        return text, hashlib.sha256(certificate).hexdigest()

    def inspect(self, text, directory):
        with patch('repack.recon.execute', side_effect=[
                CompletedProcess([], 0, text, ''), CompletedProcess([], 0, text, ''),
                CompletedProcess([], 1, '', 'The provided APK does not contain a valid V3 nor V3.1 signature block.')]), \
                patch('repack.recon.tool', return_value='apksigner'), patch('repack.recon.environment', return_value={}):
            return signing_metadata(Path('control.apk'), 30, {}, Path(directory))

    def test_source_stamp_is_excluded_from_all_signer_sets(self):
        for stamp in (False, True):
            with self.subTest(stamp=stamp), tempfile.TemporaryDirectory() as directory:
                text, expected = self.output(stamp)
                value = self.inspect(text, directory)
                self.assertEqual(value['signer_sha256'], [expected])
                self.assertEqual(value['verified_api_range_signer_sha256'], [expected])
                self.assertEqual(len(value['certificates']), 1)

    def test_stamp_does_not_hide_mismatched_signer_pem(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, 'ambiguous'):
                self.inspect(self.output(True, True)[0], directory)

    def test_repack_removes_obsolete_stamp_and_preserves_opaque_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source.apk'; target = Path(directory) / 'target.apk'
            with zipfile.ZipFile(source, 'w') as archive:
                archive.writestr('stamp-cert-sha256', b'obsolete stamp')
                archive.writestr('META-INF/services/provider', b'provider')
                archive.writestr('classes.dex', b'original dex')
            preserved = copy_archive(source, target)
            with zipfile.ZipFile(target) as archive:
                self.assertNotIn('stamp-cert-sha256', archive.namelist())
                self.assertEqual(archive.read('META-INF/services/provider'), b'provider')
                self.assertEqual(archive.read('classes.dex'), b'original dex')
            self.assertEqual({row['entry'] for row in preserved}, {'META-INF/services/provider', 'classes.dex'})


if __name__ == '__main__': unittest.main()
