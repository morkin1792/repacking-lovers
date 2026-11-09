"""Real Android30 --uid output must preserve shared-UID replacement refusal."""
import unittest
from repack.verify import uid_packages
from repack.rebuild import PrerequisiteError


class InstalledUidControls(unittest.TestCase):
    def test_recorded_android30_output_with_uid_suffix(self):
        self.assertEqual(uid_packages('package:br.com.midway uid:10243\n', 10243), ['br.com.midway'])

    def test_legacy_output_without_uid_suffix(self):
        self.assertEqual(uid_packages('package:br.com.midway\n', 10243), ['br.com.midway'])

    def test_sibling_packages_are_not_collapsed(self):
        result = uid_packages('package:br.com.midway uid:10243\npackage:another.app uid:10243\n', 10243)
        self.assertNotEqual(result, ['br.com.midway']); self.assertEqual(len(result), 2)

    def test_wrong_uid_or_unknown_suffix_is_refused(self):
        for output in ('package:br.com.midway uid:999\n', 'package:br.com.midway other:10243\n', 'package:\n'):
            with self.subTest(output=output), self.assertRaises(PrerequisiteError): uid_packages(output, 10243)


if __name__ == '__main__': unittest.main()
