"""Portable schema/hash/marker controls using an actual signed public artifact."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from repack.rebuild import ROOT
from repack.report import load_artifact


class ArtifactControls(unittest.TestCase):
    def setUp(self):
        source = ROOT / '.work/outputs/public-first/trust.artifact.json'
        if not source.exists(): self.skipTest('Build a public trust-only artifact first')
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.folder = self.root / 'artifact'; self.folder.mkdir()
        self.document = json.loads(source.read_text()); self.path = self.folder / 'manifest.json'
        for member in self.document['outputs']: shutil.copyfile(source.parent / member['path'], self.folder / member['path'])

    def save(self, document=None):
        self.path.write_text(json.dumps(self.document if document is None else document)); return self.path

    def test_valid_portable_artifact(self):
        document, artifact = load_artifact(self.save())
        self.assertEqual(document['package'], artifact['package'])

    def test_changed_output_fails_hash_check(self):
        apk = self.folder / self.document['outputs'][0]['path']
        apk.write_bytes(apk.read_bytes() + b'changed')
        with self.assertRaisesRegex(RuntimeError, 'hash mismatch'): load_artifact(self.save())

    def test_modified_semantic_endpoint_fails_signed_marker(self):
        self.document['semantic']['configuration']['proxy'] = {'host': 'changed.example', 'port': 8080}
        with self.assertRaisesRegex(RuntimeError, 'signed base marker'): load_artifact(self.save())

    def test_path_escape_is_rejected(self):
        self.document['outputs'][0]['path'] = '../outside.apk'
        with self.assertRaisesRegex(ValueError, 'escapes'): load_artifact(self.save())

    def test_caller_supplied_runtime_pass_is_not_evidence(self):
        self.document['verification'] = self.document['runtime_verification'] = 'passed'
        with self.assertRaisesRegex(ValueError, 'measured reports'): load_artifact(self.save())

    def test_duplicate_json_key_is_rejected(self):
        text = json.dumps(self.document); self.path.write_text('{"schema_version": 1,' + text[1:])
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON key'): load_artifact(self.path)

    def test_json_boolean_does_not_equal_a_version_integer(self):
        self.document['version_code'] = True
        with self.assertRaisesRegex(ValueError, 'Invalid artifact version'): load_artifact(self.save())


if __name__ == '__main__': unittest.main()
