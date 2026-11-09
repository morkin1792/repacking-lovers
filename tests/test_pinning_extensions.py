"""New pinning families: explicit polarity, scoped matching, and DEX semantics."""
import os
import unittest
from repack.patches import find_candidates
from repack.pin_families import (CT_SELECTOR, INTERCEPTOR, CHAIN_REQUEST, CHAIN_PROCEED,
                                 CONSCRYPT_CALLBACK, PLUGINS)


def method(desc, refs=(), strings=(), flags=1, implementation='present'):
    return {'descriptor': desc, 'references': list(refs), 'strings': list(strings),
            'access_flags': flags, 'implementation': implementation}


def cls(owner, methods, parent='Ljava/lang/Object;', interfaces=(), fields=()):
    return {'descriptor': owner, 'methods': methods, 'superclass': parent, 'interfaces': list(interfaces),
            'field_types': list(fields), 'access_flags': 1, 'dex': 'classes.dex'}


def candidates(*classes, duplicates=()):
    return find_candidates({'classes': {c['descriptor']: c for c in classes}, 'duplicate_classes': list(duplicates)})


def ct_base(package='appmattus'):
    owner = f'Lcom/{package}/certificatetransparency/internal/verifier/CertificateTransparencyBase;'
    return cls(owner, [method(CT_SELECTOR, refs=['Ljava/util/Set;->iterator()Ljava/util/Iterator;']),
        method('verifyCertificateTransparency()V', strings=['Certificate transparency policy'],
               refs=[f'Lcom/{package}/certificatetransparency/VerificationResult;'])], fields=['Ljava/util/Set;'])


class ExtendedMatcherControls(unittest.TestCase):
    def test_older_okhttp_enforcement_shapes_survive_renaming(self):
        for suffix, kind in [('Ljava/util/List;', 'okhttp-list-check'), ('[Ljava/security/cert/Certificate;', 'okhttp-array-check')]:
            obj = cls('Lrenamed/pinner;', [method('a(Ljava/lang/String;' + suffix + ')V',
                refs=['Ljavax/net/ssl/SSLPeerUnverifiedException;'], strings=['Certificate pinning failure!'])], fields=['Ljava/util/Set;'])
            accepted = candidates(obj)['accepted']
            self.assertEqual([(r['kind'], r['replacement']) for r in accepted], [(kind, 'return-void')])
            obj['field_types'] = []
            self.assertFalse(candidates(obj)['accepted'])

    def test_ct_selector_is_false_and_interceptor_is_not_redundantly_patched(self):
        for package in ('appmattus', 'babylon'):
            base = ct_base(package)
            interceptor = cls(base['descriptor'].replace('Base;', 'Interceptor;'), [method(INTERCEPTOR,
                refs=[CHAIN_REQUEST, CHAIN_PROCEED, base['descriptor'] + '->verifyCertificateTransparency()V'])],
                parent=base['descriptor'], interfaces=['Lokhttp3/Interceptor;'])
            selected = candidates(base, interceptor)
            self.assertEqual([(r['kind'], r['replacement']) for r in selected['accepted']], [('ct-policy-selector', 'return-false')])
            self.assertEqual(selected['rejected'][0]['reason'], 'covered-by-ct-selector')
            self.assertEqual(selected['rejected'][0]['covered_by'], [base['descriptor']])

    def test_ct_fallback_requires_recognized_ct_and_real_chain_calls(self):
        obj = cls('Lcom/appmattus/certificatetransparency/internal/verifier/CertificateTransparencyInterceptor;',
            [method(INTERCEPTOR, refs=[CHAIN_REQUEST, CHAIN_PROCEED,
                'Lcom/appmattus/certificatetransparency/VerificationResult;'])], interfaces=['Lokhttp3/Interceptor;'])
        self.assertEqual(candidates(obj)['accepted'][0]['replacement'], 'interceptor-proceed')
        for missing in (CHAIN_REQUEST, CHAIN_PROCEED):
            refs = obj['methods'][0]['references']; refs.remove(missing)
            self.assertFalse(candidates(obj)['accepted']); refs.append(missing)
        obj['descriptor'] = 'Lbusiness/AuthorizationInterceptor;'
        self.assertFalse(candidates(obj)['accepted'])

    def test_native_static_duplicate_and_no_code_ct_stay_rejected(self):
        for flags, implementation, duplicate in [(9, 'present', False), (0x101, 'absent', False), (0x401, 'absent', False), (1, 'present', True)]:
            obj = ct_base(); obj['methods'][0].update(access_flags=flags, implementation=implementation)
            self.assertFalse(candidates(obj, duplicates=[obj['descriptor']] if duplicate else [])['accepted'])

    def test_ct_name_without_policy_evidence_is_not_authorization(self):
        obj = ct_base(); obj['field_types'] = []
        self.assertFalse(candidates(obj)['accepted'])

    def test_flutter_helpers_include_java_and_current_kotlin_comparisons(self):
        for owner, desc in PLUGINS.items():
            for compare in ('Ljava/lang/String;->equals(Ljava/lang/Object;)Z', 'Ljava/util/List;->contains(Ljava/lang/Object;)Z'):
                obj = cls(owner, [method(desc, refs=[compare, owner + '->getFingerprint()Ljava/lang/String;']),
                                  method('onMethodCall()V')], interfaces=['Lio/flutter/plugin/common/MethodChannel$MethodCallHandler;'])
                accepted = candidates(obj)['accepted']
                self.assertEqual([(r['method'], r['replacement']) for r in accepted], [(desc, 'return-true')])
                obj['interfaces'] = []
                self.assertFalse(candidates(obj)['accepted'])

    def test_plugin_matching_name_or_callback_alone_is_not_patched(self):
        owner, desc = next(iter(PLUGINS.items()))
        obj = cls(owner, [method(desc)], interfaces=['Lio/flutter/plugin/common/MethodChannel$MethodCallHandler;'])
        self.assertFalse(candidates(obj)['accepted'])

    def test_conscrypt_callback_selects_side_effect_preserving_contract(self):
        for prefix in ('org/conscrypt', 'com/google/android/gms/org/conscrypt'):
            for name, arg in [('ConscryptEngine', 'Ljavax/net/ssl/SSLEngine;'), ('ConscryptFileDescriptorSocket', 'Ljava/net/Socket;')]:
                owner = f'L{prefix}/{name};'
                obj = cls(owner, [method(CONSCRYPT_CALLBACK, refs=[
                    f'L{prefix}/SSLUtils;->decodeX509CertificateChain([[B)[Ljava/security/cert/X509Certificate;',
                    f'L{prefix}/Platform;->checkServerTrusted(Ljavax/net/ssl/X509TrustManager;[Ljava/security/cert/X509Certificate;Ljava/lang/String;{arg})V'])],
                    interfaces=[f'L{prefix}/NativeCrypto$SSLHandshakeCallbacks;'])
                self.assertEqual(candidates(obj)['accepted'][0]['replacement'], 'conscrypt-server-trust')
                obj['interfaces'] = []
                self.assertFalse(candidates(obj)['accepted'])

    def test_platform_conscrypt_and_external_references_do_not_become_owned_targets(self):
        obj = cls('Lcom/android/org/conscrypt/ConscryptEngine;', [method(CONSCRYPT_CALLBACK)])
        self.assertFalse(candidates(obj)['accepted'])
        caller = cls('Lcaller;', [method('run()V', refs=['Lorg/conscrypt/ConscryptEngine;->' + CONSCRYPT_CALLBACK])])
        self.assertFalse(candidates(caller)['accepted'])

    def test_skipping_is_not_a_pinning_signal(self):
        obj = cls('Lct/OrdinaryTrustManager;', [method('checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V',
            strings=['Skipping certificate transparency'], refs=['Ljava/security/cert/CertificateException;'])],
            interfaces=['Ljavax/net/ssl/X509TrustManager;'])
        self.assertFalse(candidates(obj)['accepted'])

    def test_constructor_is_not_a_pinning_boundary(self):
        obj = cls('Lconstructor;', [method('<init>(Ljava/lang/String;Ljava/util/List;)V',
            strings=['Certificate pinning failure!'], refs=['Ljavax/net/ssl/SSLPeerUnverifiedException;'])], fields=['Ljava/util/Set;'])
        result = candidates(obj)
        self.assertFalse(result['accepted']); self.assertEqual(result['rejected'][0]['reason'], 'constructor-or-class-initializer')


@unittest.skipUnless(os.environ.get('REPACK_TEST_SDK') == '1', 'Set REPACK_TEST_SDK=1 for real library/DEX integration')
class RealLibraryDexControls(unittest.TestCase):
    def test_real_libraries_through_d8_shadow_and_host_execution(self):
        from scripts.pinning_extension_cases import host_cases
        result = host_cases()
        self.assertEqual(result['verification'], 'passed')
        self.assertEqual(set(result['cases']), {'okhttp', 'ct', 'interceptor', 'plugins', 'conscrypt'})
        self.assertEqual(result['android_runtime_verification'], 'not-run')


if __name__ == '__main__': unittest.main()
