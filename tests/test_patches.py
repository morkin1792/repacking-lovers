"""Conservative-match controls; runtime shadow selection is measured by T-U30/31."""
import unittest

from repack.patches import find_candidates


def method(descriptor, *, strings=(), references=(), flags=1, implementation='present'):
    return {'descriptor': descriptor, 'strings': list(strings), 'references': list(references),
            'access_flags': flags, 'implementation': implementation}


def cls(name, methods, *, parent='Ljava/lang/Object;', interfaces=(), fields=()):
    return {'descriptor': name, 'superclass': parent, 'interfaces': list(interfaces), 'field_types': list(fields),
            'access_flags': 1, 'methods': methods, 'dex': 'classes.dex'}


class PinningMatchControls(unittest.TestCase):
    def test_renamed_okhttp_multiline_failure_requires_descriptor_field_and_exception(self):
        candidate = cls('La/b;', [method('a(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V',
            strings=['Certificate pinning failure!\n  Peer certificate chain:'],
            references=['Ljavax/net/ssl/SSLPeerUnverifiedException;'])], fields=['Ljava/util/Set;'])
        inventory = {'classes': {'La/b;': candidate}, 'duplicate_classes': []}
        self.assertEqual(len(find_candidates(inventory)['accepted']), 1)
        candidate['field_types'] = []
        self.assertFalse(find_candidates(inventory)['accepted'])
        candidate['field_types'] = ['Ljava/util/Set;']
        candidate['methods'][0]['references'] = []
        self.assertFalse(find_candidates(inventory)['accepted'])

    def test_inherited_implementation_owner_need_not_declare_interface(self):
        name = 'verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z'
        base = cls('Lbase;', [method(name, strings=['Fixture hostname pin mismatch'], references=[
            'Ljavax/net/ssl/SSLSession;->getPeerCertificates()[Ljava/security/cert/Certificate;'])])
        child = cls('Lchild;', [], parent='Lbase;', interfaces=['Ljavax/net/ssl/HostnameVerifier;'])
        result = find_candidates({'classes': {'Lbase;': base, 'Lchild;': child}, 'duplicate_classes': []})
        self.assertEqual([(item['class'], item['method'], item['hierarchy_evidence']) for item in result['accepted']],
                         [('Lbase;', name, ['Lchild;'])])
        child['interfaces'] = []
        self.assertFalse(find_candidates({'classes': {'Lbase;': base, 'Lchild;': child}, 'duplicate_classes': []})['accepted'])

    def test_native_abstract_static_duplicate_and_wrong_return_never_patch(self):
        name = 'checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V'
        for flags, implementation, duplicate, descriptor in [
                (0x101, 'absent', False, name), (0x401, 'absent', False, name), (9, 'present', False, name),
                (1, 'present', True, name), (1, 'present', False, name[:-1] + 'Ljava/lang/String;')]:
            candidate = cls('Ltrust;', [method(descriptor, flags=flags, implementation=implementation,
                strings=['certificate pin mismatch'], references=['Ljava/security/cert/CertificateException;'])],
                interfaces=['Ljavax/net/ssl/X509TrustManager;'])
            with self.subTest(flags=flags, duplicate=duplicate, descriptor=descriptor):
                result = find_candidates({'classes': {'Ltrust;': candidate}, 'duplicate_classes': ['Ltrust;'] if duplicate else []})
                self.assertFalse(result['accepted']); self.assertEqual(len(result['rejected']), 1)

    def test_same_failure_string_in_unrelated_method_is_insufficient(self):
        candidate = cls('Lunrelated;', [method('evaluate(Ljava/lang/String;Ljava/util/List;)V',
                                              strings=['Certificate pinning failure!'])])
        result = find_candidates({'classes': {'Lunrelated;': candidate}, 'duplicate_classes': []})
        self.assertFalse(result['accepted']); self.assertTrue(result['rejected'])

    def test_exception_typed_field_is_not_exception_behavior(self):
        candidate = cls('Ltrust;', [method('checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V',
            strings=['certificate pin mismatch'], references=['Ltrust;->cached:Ljava/security/cert/CertificateException;'])],
            interfaces=['Ljavax/net/ssl/X509TrustManager;'])
        self.assertFalse(find_candidates({'classes': {'Ltrust;': candidate}, 'duplicate_classes': []})['accepted'])


if __name__ == '__main__': unittest.main()
