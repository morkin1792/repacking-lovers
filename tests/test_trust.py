"""Trust-policy preservation controls independent of on-device HTTPS acceptance."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

from repack.rebuild import ROOT
from repack.trust import ANDROID, add_trust_anchor, public_ca, rebuild_resources
from scripts.trust_cases import count_stages


class TrustPolicyControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca = ROOT / '.work/keys/mitmproxy/mitmproxy-ca-cert.pem'
        if not cls.ca.exists(): raise unittest.SkipTest('Generate the owned proxy CA first')

    def fixture(self, root, *, reference='@xml/policy', cleartext=None):
        application = {'android:networkSecurityConfig': reference} if reference else {}
        if cleartext is not None: application['android:usesCleartextTraffic'] = cleartext
        attributes = ' '.join(key + '="' + value + '"' for key, value in application.items())
        (root / 'AndroidManifest.xml').write_text('<manifest xmlns:android="' + ANDROID[1:-1] + '"><application ' + attributes + '/></manifest>')

    def test_explicit_nested_sets_and_qualified_variants_keep_original_policy(self):
        xml = '''<network-security-config><base-config cleartextTrafficPermitted="false"><trust-anchors><certificates src="system" /></trust-anchors></base-config>
        <domain-config cleartextTrafficPermitted="false"><domain>pinned.repack.test</domain><trust-anchors><certificates src="@raw/private_ca" /></trust-anchors>
        <pin-set expiration="2035-01-01"><pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin></pin-set>
        <domain-config><domain>deep.pinned.repack.test</domain><trust-anchors><certificates src="@raw/other_ca" /></trust-anchors></domain-config>
        </domain-config></network-security-config>'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.fixture(root)
            for directory in ('xml', 'xml-v30'):
                path = root / 'res' / directory; path.mkdir(parents=True); (path / 'policy.xml').write_text(xml)
            (root / 'res/raw-v30').mkdir(); (root / 'res/raw-v30/repack_ca.pem').write_text('collision')
            result = add_trust_anchor(root, self.ca, 35)
            self.assertEqual(result['ca_resource'], '@raw/repack_ca_')
            self.assertEqual(len(result['policies']), 2)
            before = ET.fromstring(xml)
            for policy in result['policies']:
                after = ET.fromstring(policy['modified_xml'])
                for anchors in after.iter('trust-anchors'):
                    injected = anchors.findall("certificates[@src='@raw/repack_ca_']")
                    self.assertEqual(len(injected), 1); self.assertEqual(injected[0].get('overridePins'), 'true')
                    anchors.remove(injected[0])
                self.assertEqual(ET.tostring(before), ET.tostring(after))

    def test_absent_policy_preserves_manifest_cleartext_and_legacy_defaults(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.fixture(root, reference=None, cleartext='false')
            result = add_trust_anchor(root, self.ca, 23)
            base = ET.fromstring(result['policies'][0]['modified_xml']).find('base-config')
            self.assertEqual(base.get('cleartextTrafficPermitted'), 'false')
            self.assertEqual([item.get('src') for item in base.find('trust-anchors')],
                             ['system', 'user', result['ca_resource']])

    def test_mixed_private_material_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'invalid.pem'
            path.write_text(self.ca.read_text() + '\n-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n')
            with self.assertRaisesRegex(ValueError, 'public PEM'): public_ca(path)

    def test_zero_denominator_does_not_report_a_pass_rate(self):
        row = {'stages': {stage: 'not-run' for stage in ('rebuild', 'insertion', 'install', 'launch', 'https')}}
        counts = count_stages([row])
        self.assertIsNone(counts['https']['pass_rate']); self.assertEqual(counts['https']['attempted'], 0)
        row['stages']['rebuild'] = 'passed'
        failed = copy.deepcopy(row); failed['stages']['rebuild'] = 'failed'
        self.assertEqual(count_stages([row, failed])['rebuild']['pass_rate'], 0.5)

    def test_pem_envelope_without_x509_certificate_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'not-a-certificate.pem'
            path.write_text('-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n')
            with self.assertRaisesRegex(ValueError, 'X.509'): public_ca(path)

    def test_resource_rebuild_preserves_opaque_payloads_and_refuses_changed_dex(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); original = root / 'original.apk'
            with zipfile.ZipFile(original, 'w') as archive:
                archive.writestr('classes.dex', b'original dex', compress_type=zipfile.ZIP_STORED)
                archive.writestr('lib/arm64-v8a/original.so', b'native bytes', compress_type=zipfile.ZIP_STORED)
                archive.writestr('META-INF/services/preserved', b'provider name')
                archive.writestr('META-INF/CERT.RSA', b'obsolete signature')
                archive.writestr('resources.arsc', b'old resources')
            changed = [False]
            def build(argv, *args, **kwargs):
                destination = Path(argv[argv.index('--output') + 1])
                with zipfile.ZipFile(destination, 'w') as archive:
                    archive.writestr('classes.dex', b'changed' if changed[0] else b'original dex')
                    archive.writestr('resources.arsc', b'new resources', compress_type=zipfile.ZIP_DEFLATED)
                    archive.writestr('AndroidManifest.xml', b'new manifest')
            with patch('repack.trust.resource_engine', return_value={'path': 'apktool', 'framework_path': 'private-cache', 'compiler': {'path': 'patched-aapt2'}}), \
                    patch('repack.trust.execute', side_effect=build), patch('repack.trust.tool', return_value='tool'), \
                    patch('repack.trust.environment', return_value={}), \
                    patch('repack.trust.resource_ids', return_value={'0x7f010000': 'xml/existing'}):
                result = rebuild_resources(original, root / 'decoded', root / 'output.apk', {}, root)
                with zipfile.ZipFile(result['unsigned_apk']) as archive:
                    self.assertEqual(archive.read('META-INF/services/preserved'), b'provider name')
                    self.assertEqual(archive.read('lib/arm64-v8a/original.so'), b'native bytes')
                    self.assertEqual(archive.getinfo('lib/arm64-v8a/original.so').compress_type, zipfile.ZIP_STORED)
                    self.assertEqual(archive.getinfo('resources.arsc').compress_type, zipfile.ZIP_STORED)
                    self.assertNotIn('META-INF/CERT.RSA', archive.namelist())
                changed[0] = True
                with self.assertRaisesRegex(RuntimeError, 'Raw DEX changed'):
                    rebuild_resources(original, root / 'decoded', root / 'changed.apk', {}, root)
                changed[0] = False
                with patch('repack.trust.resource_ids', side_effect=[{'0x7f010000': 'xml/existing'}, {'0x7f010001': 'xml/existing'}]):
                    with self.assertRaisesRegex(RuntimeError, 'ID/name bindings'):
                        rebuild_resources(original, root / 'decoded', root / 'remapped.apk', {}, root)


if __name__ == '__main__': unittest.main()
