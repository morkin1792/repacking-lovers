"""Gadget dependency and scope guards cannot turn an unknown app into the owned case."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from repack.gadget import dependencies, plan, GadgetUnsupported
from repack.rebuild import PrerequisiteError


class GadgetControls(unittest.TestCase):
    def test_unknown_app_or_cell_does_not_load_optional_dependency(self):
        base = {'package': 'dev.repack.fixture.identity', 'api': 30, 'effective_abi': 'arm64-v8a'}
        for update in ({'package': 'another.app'}, {'api': 34}, {'api': None}, {'effective_abi': 'armeabi-v7a'}):
            with self.subTest(update=update), patch('repack.gadget.dependencies') as optional:
                with self.assertRaises(GadgetUnsupported): plan({**base, **update}, 'raw-apk-fixture')
                optional.assert_not_called()

    def test_unknown_mode_does_not_load_optional_dependency(self):
        with patch('repack.gadget.dependencies') as optional:
            with self.assertRaises(GadgetUnsupported): plan({}, 'automatic')
            optional.assert_not_called()

    def test_same_named_different_native_library_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'base.apk'
            with zipfile.ZipFile(path, 'w') as out: out.writestr('lib/arm64-v8a/librepack_gadget_fixture.so', b'different native build')
            source = {'package': 'dev.repack.fixture.identity', 'api': 30, 'effective_abi': 'arm64-v8a', 'members': [{'apk': str(path)}]}
            with self.assertRaisesRegex(GadgetUnsupported, 'changed'): plan(source, 'raw-apk-fixture')

    def test_modified_optional_input_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'config').mkdir(); file = root / 'input'; file.write_bytes(b'changed')
            row = {'path': 'input', 'sha256': hashlib.sha256(b'original').hexdigest()}
            (root / 'config/gadget-dependency.json').write_text(json.dumps({'library': row, 'license': row, 'script': row}))
            with patch('repack.gadget.ROOT', root), self.assertRaisesRegex(PrerequisiteError, 'changed'): dependencies()


if __name__ == '__main__': unittest.main()
