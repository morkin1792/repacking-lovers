"""Container path, targeting and provenance refusals must precede APK processing."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from repack.containers import (ContainerUnsupported, archive_inventory, select_container,
    validate_snapshot, validate_spec, validate_xapk)
from repack.rebuild import PrerequisiteError, sha256


SPEC = {'sdkVersion': 30, 'screenDensity': 390, 'supportedAbis': ['arm64-v8a'], 'supportedLocales': ['en-US']}


class ContainerControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.spec = self.root / 'spec.json'; self.spec.write_text(json.dumps(SPEC))

    def archive(self, entries):
        path = self.root / 'input.xapk'
        with zipfile.ZipFile(path, 'w') as output:
            for name, value in entries: output.writestr(name, value)
        return path

    def test_archive_path_and_symlink_refusals(self):
        for name in ('../outside', '/absolute', 'dir/../file', 'dir//file', 'a\\b', 'C:drive'):
            path = self.archive([(name, b'bad')])
            with zipfile.ZipFile(path) as source, self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Unsafe'):
                archive_inventory(source)
        path = self.root / 'symlink.zip'
        item = zipfile.ZipInfo('link'); item.create_system = 3; item.external_attr = 0o120777 << 16
        with zipfile.ZipFile(path, 'w') as output: output.writestr(item, '../outside')
        with zipfile.ZipFile(path) as source, self.assertRaisesRegex(ValueError, 'Unsafe'): archive_inventory(source)

    def test_duplicate_member_refused(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore'); path = self.archive([('a.apk', b'one'), ('a.apk', b'two')])
        with zipfile.ZipFile(path) as source, self.assertRaisesRegex(ValueError, 'duplicate'): archive_inventory(source)

    def test_missing_or_conflicting_target_refused(self):
        path = self.archive([('manifest.json', b'{}')])
        for index, (serial, spec) in enumerate([(None, None), ('serial', self.spec)]):
            with self.assertRaisesRegex(PrerequisiteError, 'exactly one'):
                select_container(path, serial, spec, {}, self.root / str(index))

    def test_bad_spec_not_silently_defaulted(self):
        for update in ({'sdkVersion': True}, {'screenDensity': 0}, {'supportedAbis': []}, {'supportedLocales': ['en', 'en']}):
            with self.subTest(update=update), self.assertRaises(ValueError): validate_spec({**SPEC, **update})

    def test_expansion_refused_before_device_probe(self):
        path = self.archive([('main.obb', b'not supported')])
        with self.assertRaisesRegex(ContainerUnsupported, 'Expansion'):
            select_container(path, 'serial', None, {}, self.root / 'expansion')

    def test_exact_selected_bytes_and_input_mutation(self):
        metadata = {'xapk_version': 2, 'package_name': 'fixture.app', 'version_code': 1,
                    'split_apks': [{'file': 'base.apk', 'id': 'base'}]}
        path = self.archive([('manifest.json', json.dumps(metadata)), ('base.apk', b'exact-original')])
        result = select_container(path, None, self.spec, {}, self.root / 'selection')
        self.assertEqual(Path(result['selected'][0]['apk']).read_bytes(), b'exact-original')
        self.assertEqual(result['sha256'], sha256(path))
        self.spec.write_text(json.dumps({**SPEC, 'sdkVersion': 35}))
        with self.assertRaisesRegex(PrerequisiteError, 'spec changed'): validate_snapshot(result)
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(PrerequisiteError, 'container changed'): validate_snapshot(result)

    def test_duplicate_metadata_keys_refused(self):
        path = self.archive([('manifest.json', b'{"xapk_version":2,"xapk_version":1}')])
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON key'):
            select_container(path, None, self.spec, {}, self.root / 'duplicate-metadata')

    def test_manifest_identity_and_multi_abi_refusals(self):
        row = {'package': 'fixture.app', 'version_code': 1, 'split': None, 'abis': ['arm64-v8a']}
        container = {'xapk_metadata': {'package_name': 'fixture.app', 'version_code': 1,
                     'split_apks': [{'file': 'base.apk', 'id': 'base'}]}, 'selected': [{'path': 'base.apk'}]}
        validate_xapk(container, [row])
        for key, value in [('package', 'other.app'), ('version_code', 2), ('split', 'wrong')]:
            changed = {**row, key: value}
            with self.subTest(key=key), self.assertRaises((ValueError, StopIteration)):
                validate_xapk(container, [changed])
        with self.assertRaisesRegex(ContainerUnsupported, 'Multi-ABI'):
            validate_xapk(container, [{**row, 'abis': ['arm64-v8a', 'x86_64']}])


if __name__ == '__main__': unittest.main()
