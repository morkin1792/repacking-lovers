# Pinning targets transferable to APK patches

Reviewed `/home/water/workspace/pinning-haters` on 2026-11-07 at commit
`5a9e044826cf239dbd61d479e0b80167632da06e`. The review inspected its active target
tables, DEX replacement code, native locators, fixtures and architectural notes.
That repository and the device were left unchanged. This document is an assessment;
it does not enable additional patch rules or expand existing support claims.

Implementation follow-up (2026-11-08): the scoped Java batch is now implemented.
See [current replacement contracts and validation](../pinning-patches.md).
Additional follow-up: [Chromium/Cronet, hostname, offline native TLS and typed Dart adaptations](../pinning-expansion.md) now have implementations and separate acceptance evidence.
The assessment and extracted catalog below retain their original review state;
they are not the runtime configuration or current acceptance matrix.

The useful inputs are **target identities, success contracts, failure cases and
fixtures**. Our APK patcher should keep its own packaging and discovery mechanisms.
The Zygisk loader, ART checksum interception, oat eviction, system-library GOT
hooks and mapping concealment are outside this adaptation.

The extracted [22-target catalog](pinning-haters-targets.json) records exact owner,
method, descriptor, replacement, source line, source hashes, current-engine gaps
and named-definition observations from the retained original Midway1.85 DEX scan.
It is advisory documentation, not a config consumed by the patch engine.

## Transfer assessment

| Family in the source | Targets | Current APK coverage | APK adaptation |
| --- | ---: | --- | --- |
| OkHttp CertificatePinner | 4 | Lazy `Function0` shape, with body/hierarchy evidence; demonstrated on Midway | Extend recognition to the older `List` implementation and relevant wrapper overloads |
| Flutter Android pinning plugins | 2 | No dedicated plugin matcher | Recognize the actual boolean fingerprint-check method and return true |
| appmattus/babylon Certificate Transparency | 4 | No dedicated CT matcher; no false/object-return template | Return false from the CT policy selector; use an interceptor pass-through only as a fallback |
| App-bundled Conscrypt | 4 | No dedicated callback matcher | Patch an owned `verifyCertificateChain(byte[][], String):void` implementation; do not confuse it with platform or external-provider classes |
| Chromium verifier | 2 | No result-object/delegating-verifier template | Consider only app-owned Cronet/verifier DEX; the separate WebView provider is outside the input APK |
| OkHttp/Apache hostname verification | 6 | Pin-specific custom hostname verifiers only | Keep ordinary hostname relaxation separate and opt-in; it is not automatically required for a correctly named proxy certificate |

The native table adds platform and bundled TLS mechanisms, plus BoringSSL/OpenSSL
table locators. They are research inputs for a different APK-native adapter, not
additional Java method rules. The six foreign-runtime/pinning markers are
presence indicators, not six implemented bypasses.

## Existing engine constraints

[find_candidates](../../repack/patches.py) currently recognizes the lazy OkHttp
check, evidence-bearing X509TrustManager implementations, and evidence-bearing
pinning HostnameVerifiers. It does not have the source project's wider table.
Its OkHttp rule uses signatures and code evidence rather than a required class or
method name; retain that advantage when adding known library shapes.

[DexPatch.patched](../../tools/DexPatch.java) can emit `return-void` or boolean
`true`. Its selection file carries only owner/method, so it cannot select a
different success value for two boolean methods. The matcher also rejects static
methods by default. Consequently:

- A CT selector cannot be added to the accepted list yet: returning true would
  enable the check, the opposite of the desired result.
- An interceptor cannot become `return-void`, `return null`, or a fabricated
  response. It must return the real `chain.proceed(chain.request())` result.
- Conscrypt/Chromium callbacks need per-family static/instance handling. Removing
  the global static-method refusal would broaden unrelated rules incorrectly.
- Chromium needs the real non-empty verified certificate chain. The source's
  earlier `new AndroidCertVerifyResult(0)` approach is explicitly superseded after
  a device failure; do not implement that discarded shortcut.

Before adding these families, introduce an explicit replacement contract carried
from the candidate through selection into the Java writer: at least `void`,
`true`, `false`, then the narrowly scoped interceptor delegation. Keep existing
families' behavior unchanged. The shadow writer can construct a fresh method body
with new registers/references; the source module's in-place register squeezing and
try-range relocation are constraints of its backend, not requirements for ours.

## First implementation batch

### 1. Older OkHttp overloads

Source shapes:

```text
check(String, List):void
check(String, Certificate[]):void
check$okhttp(String, Function0):void
check(String, Function0):void
```

The current signature rule can cover a `Function0` implementation under either
method name when its code evidence matches. `List` and certificate-array shapes
are missing as directly selectable boundaries. A newer wrapper can already be
covered indirectly by delegating into the lazy method; do not claim every wrapper
is currently unprotected or patch redundant methods just to increase a count.

Add a constrained `List` verifier matcher using the actual pin field, pinning
failure and exception behavior, with delegation-aware handling of varargs.
Verify a pinned actual OkHttp3 artifact and the existing OkHttp4 fixture, plus
renamed/R8 and unrelated-method controls. Check the body that actually enforces
pins, not merely the presence of the public class name.

Pass requires the original controlled request to reject the intercepted chain and
the patched request to return the expected local fixture response. Retain the
existing exception/field/hierarchy negative controls and payload-preservation checks.

### 2. Flutter plugins whose checks are Java

Source targets:

```text
diefferson.http_certificate_pinning.HttpCertificatePinningPlugin
  checkConnexion(String, List, Map, int, String):boolean
com.macif.plugin.sslpinningplugin.SslPinningPlugin
  checkConnexion(String, List, Map, int, String, String):boolean
```

These helpers fetch a certificate fingerprint in Android code and compare it with
the allowed values supplied by Dart. A verified `true` result is the useful
contract. This can fit our boolean template once recognition and fixtures exist.

Start with the named descriptor plus implementation/registration and comparison
evidence. Report renamed/inlined forms as unrecognized until there is evidence
for a structural matcher. Patch the synchronous decision helper, preserving the
MethodChannel callback path. Making `onMethodCall` a no-op can leave a Dart future
unresolved indefinitely.

The source fixtures describe these method shapes; they are not the real released
plugins. Pin real plugin source/artifacts and exercise both the Android helper and
its channel completion. Prove one success/failure response, no duplicate callback,
unchanged request/header behavior, and refusal of an unrelated boolean method.

**Boundary:** bypassing the plugin's fingerprint comparison does not establish
trust or routing for subsequent `dart:io` HTTPS. Flutter's native engine and any
pure-Dart `peerCertificate` comparison remain separate paths.

## Second implementation batch

### 3. Certificate Transparency

The source handles both `com.appmattus.certificatetransparency` and the older
`com.babylon.certificatetransparency` namespaces. Its preferred boundary is
`CertificateTransparencyBase.enabledForCertificateTransparency(String):boolean`:
false disables that library's CT policy while preserving its delegates.

Implement and verify the explicit false template before accepting this target.
Use a real library fixture that fails with a trusted interception certificate
because of missing/invalid CT data, then succeeds with the selector patched.
Ensure an unrelated wrong-host case still fails its normal hostname check.

Only when the selector is missing/renamed should a *recognized CT interceptor*
use the delegating fallback. It must preserve request, response, chain and
exceptions. Do not apply this to arbitrary interceptors: authentication, signing,
retry and application logic also live in interceptors. If both selectors and
interceptors exist, avoid selecting both without a demonstrated need.

Library CT and Android platform/NSC CT are distinct. Success here must not mark
the still separately gated platform CT cells accepted.

### 4. App-owned Conscrypt callbacks

The source has `ConscryptEngine` and `ConscryptFileDescriptorSocket` rows in the
`org.conscrypt` and `com.google.android.gms.org.conscrypt` namespaces. Each returns
void from `verifyCertificateChain(byte[][], String)` instead of throwing.

Require a concrete implementation defined in the selected app/split DEX, an
audited callback signature, and an allowed provider/library version. Fixture the
actual bundled provider and JNI handshake; a synthetic class with a matching
name is only a structural control. Record that this replacement skips the
TrustManager callback rather than preserving its side effects.

The same descriptor arriving later from Play services or another external loader
does not make its code part of our APK. Platform `com.android.org.conscrypt` and
boot-image trust managers are also outside this transformation. Our own NSC and
app-owned custom trust-manager paths remain the appropriate existing mechanisms.

## Native and external-provider research

### Chromium/Cronet versus the WebView provider

The module can see DEX loaded from the separate WebView provider inside the
target process. Rebuilding Midway cannot change that provider's APK. App-owned
Cronet/verifier definitions are possible candidates, but require an adapter and
fixtures independent of external-provider support.

The shipped source template adds a received leaf certificate to Chromium's test
trust store, then invokes a real inner verifier. An APK adaptation needs explicit
trust scope, a resolvable helper and unique real verifier, correct static-call
semantics, and the non-empty chain required by native code. Prefer a narrowly
selected proxy trust anchor where the actual owned provider supports it; do not
claim that interface exists merely because the module used a test hook.

Test real app-bundled Cronet, ambiguity and missing-helper cases, an external-only
provider refusal, and certificate/result semantics. Returning a dummy "OK" object
or shadowing a class that actually lives in a parent/external loader is not proof.

### BoringSSL, OpenSSL and Flutter native TLS

Useful source leads are `SSL_set_verify`, `SSL_CTX_set_verify`, custom-verifier
callbacks, `SSL_get_verify_result`, `X509_verify_cert`, BoringSSL's
`ssl_crypto_x509_method` verifier slot and OpenSSL's `SSL_METHOD` connection slots.
Their success conventions differ; a boolean true verifier is not the same ABI
contract as a zero-valued verify result or an enum-valued custom callback.

The source locators operate on loaded ARM64 mappings, function pointers and
RELRO tables. Do not write those process addresses into an ELF file. An offline
adapter needs file/virtual-address and relocation handling, a bounded unique
match, known ABI/contract, original bytes/hash binding, and a per-library fixture.
If an app-local injected shim is ever chosen instead, it remains an explicit APK
native mode with its own loading/ABI tests, not the Zygisk infrastructure.

Our existing `native_tls.py` supports one pinned reFlutter engine/AOT profile.
That is not a general BoringSSL/OpenSSL patcher and does not match Midway1.85's
current engine. These locators are valuable research for future profiles.

Lower-level TLS acceptance still does not defeat libcurl's own pinned-public-key
comparison or arbitrary application digest comparisons after the handshake.

### Presence-only runtimes and hostname verification

The source's Go, rustls, IL2CPP, Mono and pure-Dart leads do not contain generic
implemented pinning patches. An ELF/string marker identifies a possible runtime,
not an enforcing check. Keep them as diagnostics and binary-specific research.

Its six standard hostname-verifier targets are also not extra pinning families.
Correctly named proxy certificates should not need that relaxation. If an
explicit hostname-relaxation mode is added later, keep app-owned versus platform
Apache/OkHttp definitions and the existing pin-specific verifier behavior distinct.

## What this adds for Midway today

Static inspection of the retained original1.85 inventory finds three named
CertificatePinner methods and both standard OkHostnameVerifier overloads.
References show this existing delegation chain:

```text
check(String, Certificate[]) -> check(String, List) -> check$okhttp(String, Function0)
```

The last method is already patched and was observed executing in our verified
full APK. This scan does not establish an additional unhandled OkHttp gate.
The other named families in the extracted Java catalog are absent from that
inventory; R8 renaming, encrypted payloads, later code and external providers can
still conceal equivalent behavior, so this is not proof that those paths cannot
exist. The obfuscated TrustKit manager is already matched structurally by our
own rule even though the module's Java table has no TrustKit row.

Midway's native Flutter/AOT libraries remain a concrete later-flow lead. The
catalog does not establish a working native patch for them. No new installed
artifact, device test, or backend request was created during this review.

## Coverage and provenance rules for the implementation

Report discovery, applicability, rewriting and runtime observation separately.
A class reference alone is not an implementation, and a successful rewrite is
not a demonstrated intercepted request. For each new family retain the input
hash, method/descriptor, discovered evidence, selected replacement, fixture and
the actual observed path. Avoid inflating support from overlapping wrappers.

Use current implementation tables as the catalog source. Some source docs retain
older statements that no pattern backends ship or that Chromium is unreachable,
while the current table and code contain the native locators and corrected
Chromium template. Superseded constructor-result experiments are explicitly kept
in AGENTS.md for history. Do not promote those older claims into new requirements.

This assessment imports no source implementation and enables no hooks. Production
matcher/writer code, the verified Midway APK and both repositories' runtime state
remain unchanged. The private extraction script is
`.work/reviews/pinning-haters/extract_catalog.py`; it can regenerate the advisory
JSON from the pinned local source and retained input scan.
