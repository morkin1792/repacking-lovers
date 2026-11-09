import unittest
from repack.patches import find_candidates
from repack.pin_families import CHROMIUM_OWNER, CHROMIUM_RESULT
from test_pinning_extensions import cls, method


def chromium():
    suffix = '([[BLjava/lang/String;Ljava/lang/String;)' + CHROMIUM_RESULT
    inner = cls('Lorg/chromium/net/X509Util;', [
        method('verifyServerCertificates' + suffix, flags=9),
        method('addTestRootCertificate([B)V', refs=['Ljava/security/KeyStore;->setCertificateEntry(Ljava/lang/String;Ljava/security/cert/Certificate;)V'], flags=9)])
    outer = cls(CHROMIUM_OWNER, [method('verifyServerCertificates' + suffix,
        refs=[inner['descriptor'] + '->verifyServerCertificates' + suffix], flags=9)])
    return {'classes': {c['descriptor']: c for c in (outer, inner)}, 'duplicate_classes': []}


class AdditionalJavaControls(unittest.TestCase):
    def test_chromium_requires_owned_real_verifier_and_explicit_anchor(self):
        inventory = chromium()
        self.assertFalse(find_candidates(inventory)['accepted'])
        accepted = find_candidates(inventory, chromium_anchor=True)['accepted']
        self.assertEqual([(r['kind'],r['replacement']) for r in accepted], [('chromium-owned-verifier', 'chromium-anchor')])
        del inventory['classes']['Lorg/chromium/net/X509Util;']
        self.assertFalse(find_candidates(inventory, chromium_anchor=True)['accepted'])

    def test_chromium_rejects_ambiguous_private_or_missing_anchor(self):
        for change in ('private', 'missing-anchor', 'no-keystore', 'instance-inner', 'native-inner'):
            inventory = chromium(); inner = inventory['classes']['Lorg/chromium/net/X509Util;']
            if change == 'private': inner['access_flags'] = 0
            elif change == 'missing-anchor': inner['methods'].pop()
            elif change == 'no-keystore': inner['methods'][1]['references'] = []
            elif change == 'instance-inner': inner['methods'][0]['access_flags'] = 1
            else: inner['methods'][0].update(access_flags=0x109, implementation='absent')
            self.assertFalse(find_candidates(inventory, chromium_anchor=True)['accepted'], change)

    def test_standard_hostname_relaxation_is_explicit(self):
        verifier = cls('Lokhttp3/internal/tls/OkHostnameVerifier;', [method(
            'verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z', refs=['Ljavax/net/ssl/SSLSession;->getPeerCertificates()[Ljava/security/cert/Certificate;'])])
        inventory = {'classes': {verifier['descriptor']: verifier}, 'duplicate_classes': []}
        self.assertFalse(find_candidates(inventory)['accepted'])
        accepted = find_candidates(inventory, relax_hostname=True)['accepted']
        self.assertEqual(accepted[0]['replacement'], 'return-true')
        verifier['descriptor'] = 'Lbusiness/AuthorizationVerifier;'
        inventory['classes'] = {verifier['descriptor']: verifier}
        self.assertFalse(find_candidates(inventory, relax_hostname=True)['accepted'])

    def test_static_exception_stays_scoped_to_chromium(self):
        verifier = cls('Lokhttp3/internal/tls/OkHostnameVerifier;', [method(
            'verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z', refs=['Ljavax/net/ssl/SSLSession;->getPeerCertificates()[Ljava/security/cert/Certificate;'], flags=9)])
        inventory = {'classes': {verifier['descriptor']: verifier}, 'duplicate_classes': []}
        self.assertFalse(find_candidates(inventory, relax_hostname=True)['accepted'])

    def test_chromium_five_parameter_shape_and_duplicate_helper(self):
        inventory=chromium()
        for item in inventory['classes'].values():
            for m in item['methods']:
                m['descriptor']=m['descriptor'].replace('Ljava/lang/String;)'+CHROMIUM_RESULT,'Ljava/lang/String;[B[B)'+CHROMIUM_RESULT)
                m['references']=[r.replace('Ljava/lang/String;)'+CHROMIUM_RESULT,'Ljava/lang/String;[B[B)'+CHROMIUM_RESULT) for r in m['references']]
        self.assertEqual(find_candidates(inventory,chromium_anchor=True)['accepted'][0]['replacement'],'chromium-anchor')
        inventory['duplicate_classes']=['Lorg/chromium/net/X509Util;']
        self.assertFalse(find_candidates(inventory,chromium_anchor=True)['accepted'])

    def test_static_owned_apache_caller_is_rewritten_only_when_requested(self):
        caller=cls('Lapp/Network;', [method('test()V',flags=9,refs=[
            'Lorg/apache/http/conn/ssl/BrowserCompatHostnameVerifier;->verify(Ljava/lang/String;Ljava/security/cert/X509Certificate;)V'])])
        inventory={'classes':{caller['descriptor']:caller},'duplicate_classes':[]}
        self.assertFalse(find_candidates(inventory)['accepted'])
        self.assertEqual(find_candidates(inventory,relax_hostname=True)['accepted'][0]['replacement'],'hostname-callsite')

    def test_cronet_pin_list_is_scoped_to_the_owned_builder_field(self):
        owner='Lorg/chromium/net/impl/CronetEngineBuilderImpl;'
        builder=cls(owner,[method('publicKeyPins()Ljava/util/List;',refs=[owner+'->mPkps:Ljava/util/List;'])])
        inventory={'classes':{owner:builder},'duplicate_classes':[]}
        self.assertEqual(find_candidates(inventory)['accepted'][0]['replacement'],'return-empty-list')
        builder['methods'][0]['references']=[]
        self.assertFalse(find_candidates(inventory)['accepted'])


if __name__ == '__main__': unittest.main()
