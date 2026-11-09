"""Evidence aliases must not split one report; stale/tampered reports stay rejected."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from repack.rebuild import ROOT, PrerequisiteError, sha256, source_hash
from scripts.release_cases import packet


class ReleaseEvidenceControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.work')
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def report(self, **values):
        data = {'verification': 'passed', 'gate_progress': 'accepted', 'source_sha256': source_hash(), **values}
        immutable = self.folder / 'immutable.json'; immutable.write_text(json.dumps(data))
        index = self.folder / 'index.json'
        index.write_text(json.dumps({**data, 'evidence_refs': [str(immutable)]}))
        return index

    def test_absolute_and_relative_aliases_join_the_same_report(self):
        index = self.report()
        absolute = packet(index)[1]
        relative = packet(Path(os.path.relpath(index)))[1]
        self.assertEqual(absolute, relative)
        self.assertEqual(absolute['index'], str(index.resolve()))

    def test_passed_report_with_stale_source_is_refused(self):
        with self.assertRaisesRegex(PrerequisiteError, 'source is stale'):
            packet(self.report(source_sha256='0' * 64))

    def test_changed_immutable_child_is_refused(self):
        child = self.folder / 'child.json'; child.write_text('{"verification":"passed"}')
        index = self.report(children={'child': {'path': str(child), 'sha256': sha256(child)}})
        child.write_text('{"verification":"failed"}')
        with self.assertRaisesRegex(RuntimeError, 'Changed child evidence'):
            packet(index)


if __name__ == '__main__':
    unittest.main()
