"""Runtime leads from the source catalog. Presence never implies a bypass."""
from pathlib import PurePosixPath


def runtime_hints(data, entry):
    name = PurePosixPath(entry).name; result = []
    def add(runtime, evidence, adapter, status):
        result.append({'runtime':runtime,'evidence':evidence,'adapter':adapter,'status':status,
                       'interpretation':'presence-only; an enforcing check and successful request require separate evidence'})
    if name == 'libapp.so': add('dart-aot',['library-name'], 'typed-arm64-predicate', 'requires-matching-analysis-and-code-evidence')
    if name == 'libflutter.so': add('flutter-tls',['library-name'], 'offline-arm64-boringssl', 'requires-unique-verifier')
    if name.startswith('libcronet.') or any(s in name for s in ('webviewchromium','monochrome','trichrome')):
        add('chromium',['library-name'],'owned-java-verifier','requires-owned-dex-helper')
    if name == 'libil2cpp.so': add('unity-il2cpp',['library-name'],None,'research-only-no-generic-patch')
    if name.startswith(('libmonosgen-2.0','libmonodroid')): add('mono',['library-name'],None,'research-only-managed-assembly-analysis-required')
    if b'crypto/tls: ' in data or b'Go build ID' in data:
        add('go-tls',['crypto/tls or Go build marker'],None,'research-only-Go-ABI-and-verifier-analysis-required')
    if b'/rustls-' in data or b'rustls::' in data:
        add('rustls',['rustls path or namespace marker'],None,'research-only-concrete-verifier-and-Rust-ABI-required')
    return result
