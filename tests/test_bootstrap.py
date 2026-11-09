"""Host structural checks for bootstrap artifacts; device gates remain separate."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from repack.rebuild import ROOT, ensure_keys, execute, load_lock, report, sha256, tool, write_json
from repack.shim import FACTORY, build_bootstrap
from scripts.acceptance import make_factory_control


class BootstrapHostControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        index = ROOT / '.work/evidence/M0-build.json'
        if not index.exists():
            raise unittest.SkipTest('Build the owned fixtures first')
        baseline = json.loads(index.read_text())
        if baseline['verification'] != 'passed':
            raise unittest.SkipTest('A verified fixture build is required')
        cls.result, cls.evidence = report('BOOTSTRAP-host')
        cls.result['test_source_sha256'] = sha256(Path(__file__))
        cls.lock = load_lock()
        cls.keys = ensure_keys(cls.lock, cls.evidence)
        own = next(x for x in baseline['outputs'] if x['id'] == 'app-own')
        core = next(x for x in baseline['outputs'] if x['id'] == 'app-androidx')
        cls.originals = {'own-final': own, 'androidx': core}
        for name, factory in [('platform-default', None),
                              ('custom-loader', 'dev.repack.fixture.common.LoaderFactory'),
                              ('exception', 'dev.repack.fixture.common.ThrowFactory')]:
            cls.originals[name] = make_factory_control(own, factory, cls.keys['original'], cls.lock,
                    cls.evidence / (name + '-original'), cls.evidence / (name + '-original-logs'))
        cls.artifacts = {}
        for name, original in cls.originals.items():
            part = cls.evidence / name
            part.mkdir()
            cls.artifacts[name] = build_bootstrap(Path(original['apk']), part / 'output', cls.keys['repack'], cls.lock, part)

    @classmethod
    def tearDownClass(cls):
        cls.result.update(verification='passed' if len(cls.result['comparisons']) == 4 else 'failed',
                          outputs=list(cls.artifacts.values()), logs=[str(cls.evidence)],
                          scope='Host archive/manifest checks only; no device acceptance')
        write_json(cls.evidence / 'report.json', cls.result)
        cls.result['evidence_refs'] = [str(cls.evidence / 'report.json')]
        write_json(ROOT / '.work/evidence/BOOTSTRAP-host.json', cls.result)

    def test_original_dex_and_resources_are_preserved(self):
        for name, artifact in self.artifacts.items():
            with zipfile.ZipFile(self.originals[name]['apk']) as original, zipfile.ZipFile(artifact['apk']) as patched:
                for entry in original.infolist():
                    if entry.filename == 'AndroidManifest.xml' or entry.filename.startswith('META-INF/'):
                        continue
                    self.assertEqual(original.read(entry.filename), patched.read(entry.filename), entry.filename)
                    self.assertEqual(entry.compress_type, patched.getinfo(entry.filename).compress_type)
                self.assertIn(artifact['appended_dex'], patched.namelist())
        self.result['comparisons'].append({'preserved_payloads_and_storage': True, 'result': 'passed'})

    def test_other_manifest_attributes_are_preserved(self):
        for name, artifact in self.artifacts.items():
            outputs = []
            for kind, apk in [('original', self.originals[name]['apk']), ('patched', artifact['apk'])]:
                text = execute([tool(self.lock, 'aapt2'), 'dump', 'xmltree', apk, '--file', 'AndroidManifest.xml'],
                               self.evidence, name + '-' + kind + '-manifest').stdout
                outputs.append([line for line in text.splitlines() if 'appComponentFactory' not in line])
                if kind == 'patched':
                    self.assertIn(FACTORY, text)
            self.assertEqual(outputs[0], outputs[1], name)
        self.result['comparisons'].append({'only_factory_attribute_changed': True, 'result': 'passed'})

    def test_prepatched_input_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'Previously patched'):
            build_bootstrap(Path(self.artifacts['own-final']['apk']), self.evidence / 'double-patch',
                            self.keys['repack'], self.lock, self.evidence)
        self.result['comparisons'].append({'prepatched_refused': True, 'result': 'passed'})

    def test_noncontiguous_dex_inventory_is_refused(self):
        source = Path(self.originals['own-final']['apk'])
        malformed = self.evidence / 'missing-dex-index.apk'
        with zipfile.ZipFile(source) as original, zipfile.ZipFile(malformed, 'w') as target:
            dex_data = original.read('classes.dex')
            for item in original.infolist():
                target.writestr(item, original.read(item.filename))
            target.writestr('classes3.dex', dex_data)
        with self.assertRaisesRegex(RuntimeError, 'contiguous'):
            build_bootstrap(malformed, self.evidence / 'missing-index-output', self.keys['repack'], self.lock, self.evidence)
        self.result['comparisons'].append({'missing_dex_index_refused': True, 'result': 'passed'})


if __name__ == '__main__':
    unittest.main()
