"""Malformed selected sets must fail before any device mutation is reachable."""
import copy
import unittest
from repack.recon import validate_selected
from repack.rebuild import PrerequisiteError


class SelectedSetControls(unittest.TestCase):
    def setUp(self):
        base = {'apk': 'base.apk', 'package': 'dev.repack.fixture.identity', 'version_code': 1, 'split': None,
                'signing': {'signer_sha256': ['one'], 'verified_api_range_signer_sha256': ['one']}, 'abis': [],
                'min_sdk': 28, 'target_sdk': 35, 'requiredSplitTypes': 'base__abi', 'splitTypes': '', 'uses_split': []}
        feature = {**copy.deepcopy(base), 'apk': 'feature.apk', 'split': 'feature.core', 'isFeatureSplit': True, 'requiredSplitTypes': ''}
        config = {**copy.deepcopy(base), 'apk': 'arm64.apk', 'split': 'config.arm64', 'configForSplit': 'feature.core',
                  'requiredSplitTypes': '', 'splitTypes': 'base__abi', 'abis': ['arm64-v8a']}
        self.members = [base, feature, config]

    def test_valid_selected_set(self):
        value = validate_selected(self.members, 30, 'arm64-v8a')
        self.assertEqual(value['required_split_types'], ['base__abi'])
        self.assertEqual(value['dependencies']['config.arm64'], ['feature.core', 'base'])

    def test_missing_base_feature_or_required_type(self):
        for subset in (self.members[1:], self.members[:2], [self.members[0], self.members[2]]):
            with self.assertRaises(RuntimeError): validate_selected(subset, 30, 'arm64-v8a')

    def test_conflicting_ids_package_version_signer(self):
        for key, bad in [('split', None), ('package', 'different.app'), ('version_code', 2),
                         ('signing', {'signer_sha256': ['different'], 'verified_api_range_signer_sha256': ['different']})]:
            values = copy.deepcopy(self.members); values[1][key] = bad
            with self.subTest(key=key), self.assertRaises(RuntimeError): validate_selected(values, 30, 'arm64-v8a')

    def test_dependency_cycle_and_nonfeature_target(self):
        values = copy.deepcopy(self.members); values[0]['uses_split'] = ['feature.core']
        with self.assertRaisesRegex(RuntimeError, 'Cyclic'): validate_selected(values, 30, 'arm64-v8a')
        values = copy.deepcopy(self.members); values[1]['isFeatureSplit'] = False
        with self.assertRaisesRegex(RuntimeError, 'not a feature'): validate_selected(values, 30, 'arm64-v8a')

    def test_device_sdk_abi_mismatch(self):
        for api, abi in [(27, 'arm64-v8a'), (30, 'x86_64')]:
            with self.assertRaises(PrerequisiteError): validate_selected(self.members, api, abi)

    def test_32bit_input_on_64bit_phone_keeps_its_abi(self):
        values = copy.deepcopy(self.members); values[2]['abis'] = ['armeabi-v7a']
        selected = validate_selected(values, 30, ['arm64-v8a', 'armeabi-v7a'])
        self.assertEqual(selected['effective_abi'], 'armeabi-v7a')


if __name__ == '__main__': unittest.main()
