"""Constrained app-owned Java families and their explicit replacement contracts.

Names identify library entry points; code evidence keeps names alone from becoming
patch authorization. External providers and native/abstract definitions stay out.
"""
import re
CT_PACKAGES = ('com/appmattus/certificatetransparency', 'com/babylon/certificatetransparency')
CT_SELECTORS = {f'L{p}/internal/verifier/CertificateTransparencyBase;' for p in CT_PACKAGES}
CT_INTERCEPTORS = {f'L{p}/internal/verifier/CertificateTransparencyInterceptor;' for p in CT_PACKAGES}
CT_SELECTOR = 'enabledForCertificateTransparency(Ljava/lang/String;)Z'
INTERCEPTOR = 'intercept(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;'
CHAIN_REQUEST = 'Lokhttp3/Interceptor$Chain;->request()Lokhttp3/Request;'
CHAIN_PROCEED = 'Lokhttp3/Interceptor$Chain;->proceed(Lokhttp3/Request;)Lokhttp3/Response;'
PLUGINS = {
    'Ldiefferson/http_certificate_pinning/HttpCertificatePinningPlugin;':
        'checkConnexion(Ljava/lang/String;Ljava/util/List;Ljava/util/Map;ILjava/lang/String;)Z',
    'Lcom/macif/plugin/sslpinningplugin/SslPinningPlugin;':
        'checkConnexion(Ljava/lang/String;Ljava/util/List;Ljava/util/Map;ILjava/lang/String;Ljava/lang/String;)Z',
}
CONSCRYPT = {f'L{p}/{c};' for p in ('org/conscrypt', 'com/google/android/gms/org/conscrypt')
             for c in ('ConscryptEngine', 'ConscryptFileDescriptorSocket')}
CONSCRYPT_CALLBACK = 'verifyCertificateChain([[BLjava/lang/String;)V'
CRONET_BUILDER = 'Lorg/chromium/net/impl/CronetEngineBuilderImpl;'
CRONET_PINS = 'publicKeyPins()Ljava/util/List;'


def known_shape(cls, method):
    owner = cls['descriptor']; desc = method['descriptor']
    return ((owner in CT_SELECTORS and desc == CT_SELECTOR)
            or (owner in CT_INTERCEPTORS and desc == INTERCEPTOR)
            or PLUGINS.get(owner) == desc
            or (owner == CRONET_BUILDER and desc == CRONET_PINS)
            or (owner in CONSCRYPT and desc == CONSCRYPT_CALLBACK))


def additional_match(cls, method, ancestors):
    if not known_shape(cls, method): return None
    owner = cls['descriptor']; desc = method['descriptor']; refs = method['references']
    calls = [ref for ref in refs if '->' in ref and '(' in ref]
    class_refs = [ref for m in cls['methods'] for ref in m['references']]
    class_strings = [value.lower() for m in cls['methods'] for value in m['strings']]
    kind = replacement = None
    if owner == CRONET_BUILDER and desc == CRONET_PINS:
        if CRONET_BUILDER + '->mPkps:Ljava/util/List;' in refs:
            kind, replacement = 'cronet-public-key-pins', 'return-empty-list'
    elif owner in CT_SELECTORS and desc == CT_SELECTOR:
        # The base class implements the policy and produces typed verification
        # results; an unrelated method pasted under its name is insufficient.
        result_evidence = any('/VerificationResult' in ref for ref in class_refs)
        policy_evidence = ('Ljava/util/Set;' in cls['field_types'] and bool(calls)
                           and any('transparency' in s for s in class_strings))
        if result_evidence and policy_evidence:
            kind, replacement = 'ct-policy-selector', 'return-false'
    elif owner in CT_INTERCEPTORS and desc == INTERCEPTOR:
        ct_evidence = any('->verifyCertificateTransparency(' in ref or '/VerificationResult' in ref for ref in refs)
        if (ct_evidence and 'Lokhttp3/Interceptor;' in ancestors(owner)
                and CHAIN_REQUEST in refs and CHAIN_PROCEED in refs):
            kind, replacement = 'ct-interceptor', 'interceptor-proceed'
    elif PLUGINS.get(owner) == desc:
        comparison = any(ref.startswith(('Ljava/lang/String;->equals(', 'Ljava/lang/String;->equalsIgnoreCase(',
                                        'Ljava/util/List;->contains(', 'Ljava/util/Collection;->contains(')) for ref in calls)
        fingerprint = any('->getFingerprint(' in ref and ref.endswith(')Ljava/lang/String;') for ref in calls)
        if comparison and fingerprint and 'Lio/flutter/plugin/common/MethodChannel$MethodCallHandler;' in ancestors(owner):
            kind, replacement = 'flutter-plugin-fingerprint', 'return-true'
    elif owner in CONSCRYPT and desc == CONSCRYPT_CALLBACK:
        provider = owner.rsplit('/', 1)[0] + '/'
        parses_chain = any(ref.startswith(provider) and ('->decodeX509CertificateChain(' in ref or '->fromX509Der(' in ref) for ref in calls)
        contexts = ('Ljavax/net/ssl/SSLEngine;', 'Ljava/net/Socket;', provider + 'ConscryptEngine;', provider + 'AbstractConscryptSocket;')
        trust_call = re.escape(provider + 'Platform;->checkServerTrusted(') + (
            r'Ljavax/net/ssl/X509TrustManager;\[Ljava/security/cert/X509Certificate;Ljava/lang/String;'
            r'(?:' + '|'.join(map(re.escape, contexts)) + r')\)V')
        validates_chain = any(re.fullmatch(trust_call, ref) for ref in calls)
        callback_interface = provider + 'NativeCrypto$SSLHandshakeCallbacks;'
        if parses_chain and validates_chain and callback_interface in ancestors(owner):
            kind, replacement = 'bundled-conscrypt-callback', 'conscrypt-server-trust'
    if kind: return {'kind': kind, 'replacement': replacement}
    return None


CHROMIUM_OWNER = 'Lorg/chromium/net/AndroidNetworkLibrary;'
CHROMIUM_RESULT = 'Lorg/chromium/net/AndroidCertVerifyResult;'
CHROMIUM_PARAMS = ('[[BLjava/lang/String;Ljava/lang/String;', '[[BLjava/lang/String;Ljava/lang/String;[B[B')
HOSTNAME_OWNERS = {'Lokhttp3/internal/tls/OkHostnameVerifier;', 'Lcom/squareup/okhttp/internal/tls/OkHostnameVerifier;'}
APACHE_OWNER = 'Lorg/apache/http/conn/ssl/AbstractVerifier;'
HOSTNAME_METHODS = {'verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z',
                    'verify(Ljava/lang/String;Ljava/security/cert/X509Certificate;)Z'}
APACHE_METHODS = {'verify(Ljava/lang/String;Ljavax/net/ssl/SSLSocket;)V',
                  'verify(Ljava/lang/String;Ljava/security/cert/X509Certificate;)V',
                  'verify(Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;Z)V',
                  'verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z'}


def chromium_match(cls, method, classes):
    desc = method['descriptor']
    if cls['descriptor'] != CHROMIUM_OWNER or desc not in {
            'verifyServerCertificates(' + p + ')' + CHROMIUM_RESULT for p in CHROMIUM_PARAMS}: return None
    if not method['access_flags'] & 8: return None
    suffix = desc[desc.index('('):]
    inner = []
    for ref in set(method['references']):
        if '->' not in ref or not ref.endswith(suffix): continue
        owner, name = ref.split('->', 1)
        target = classes.get(owner)
        if not target or owner == CHROMIUM_OWNER or not target['access_flags'] & 1: continue
        methods = [m for m in target['methods'] if m['descriptor'] == name and m['implementation'] == 'present'
                   and m['access_flags'] & 9 == 9 and not m['access_flags'] & (0x100 | 0x400)]
        anchors = [m for m in target['methods'] if m['descriptor'] == 'addTestRootCertificate([B)V'
                   and m['implementation'] == 'present' and m['access_flags'] & 9 == 9
                   and any('Ljava/security/KeyStore;' in r for r in m['references'])]
        if len(methods) == 1 and len(anchors) == 1: inner.append(ref)
    if len(inner) != 1: return None
    return {'kind': 'chromium-owned-verifier', 'replacement': 'chromium-anchor', 'inner_verifier': inner[0]}


def hostname_match(cls, method):
    owner = cls['descriptor']; desc = method['descriptor']; refs = method['references']
    if owner in HOSTNAME_OWNERS and desc in HOSTNAME_METHODS:
        if any('Ljava/security/cert/X509Certificate;' in r or '->getPeerCertificates(' in r for r in refs):
            return {'kind': 'standard-hostname-relaxation', 'replacement': 'return-true'}
    if owner == APACHE_OWNER and desc in APACHE_METHODS:
        if any('SSLException;' in r or '->getSubjectAlternativeNames(' in r or '->getPeerCertificates(' in r
               or '->getSubjectAltNames(' in r or '->getSubjectX500Principal(' in r for r in refs):
            return {'kind': 'standard-hostname-relaxation', 'replacement': 'return-void' if desc.endswith(')V') else 'return-true'}
    if any(apache_call(ref) for ref in refs):
        return {'kind': 'apache-hostname-callsite', 'replacement': 'hostname-callsite'}
    return None


def apache_call(ref):
    if '->' not in ref: return False
    owner, desc = ref.split('->', 1)
    owners = {APACHE_OWNER, 'Lorg/apache/http/conn/ssl/X509HostnameVerifier;',
              'Lorg/apache/http/conn/ssl/BrowserCompatHostnameVerifier;',
              'Lorg/apache/http/conn/ssl/StrictHostnameVerifier;',
              'Lorg/apache/http/conn/ssl/DefaultHostnameVerifier;'}
    return owner in owners and desc in APACHE_METHODS | {'verify(Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;)V'}
