"""Negative controls for joining independent public and Binder list observations."""
import copy
import json
import unittest

from scripts.contract_cases import list_oracles


class ListOracleControls(unittest.TestCase):
    def setUp(self):
        self.configs = [{'id': 'list', 'operation': 'list-installed', 'flags': 0x8000000}]
        self.events = {'list': {'response_marker': json.dumps({'list_count': 2, 'list_order_sha256': 'observed-order'})}}
        self.shim = [{'details': {'operation': 'getInstalledPackages', 'list_flags': 0x8000000,
                                 'self_entries_changed': 1, 'list_count': 2, 'list_order_sha256': 'observed-order'}}]

    def test_matching_independent_observations(self):
        list_oracles(self.configs, self.events, self.shim)

    def test_missing_or_different_flags_cannot_count_as_coverage(self):
        with self.assertRaises(RuntimeError): list_oracles(self.configs, self.events, [])
        altered = copy.deepcopy(self.shim); altered[0]['details']['list_flags'] = 0x40
        with self.assertRaises(RuntimeError): list_oracles(self.configs, self.events, altered)

    def test_changed_order_count_or_self_rewrite_is_rejected(self):
        for key, bad in [('list_order_sha256', 'different'), ('list_count', 3), ('self_entries_changed', 0)]:
            with self.subTest(key=key):
                altered = copy.deepcopy(self.shim); altered[0]['details'][key] = bad
                with self.assertRaises(RuntimeError): list_oracles(self.configs, self.events, altered)


if __name__ == '__main__': unittest.main()
