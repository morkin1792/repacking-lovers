# Java APK pinning patches

For the later Chromium/Cronet, hostname, native and Dart additions, see
[additional adaptations](pinning-expansion.md). This page records the first Java batch.

The public `repack patch` command now carries explicit replacement contracts from
discovery through the signed artifact report. Its interface is unchanged. The
additional Java families come from the [pinning-haters assessment](research/pinning-haters-apk-adaptation.md);
no root module, ART hook, native library injection or external-provider patch is
introduced by these additions.

| Recognized implementation | Replacement | Scope |
| --- | --- | --- |
| OkHttp lazy Function0 check | `return-void` | Existing evidence-based rule; method/class renaming can be handled when the code evidence survives |
| Older OkHttp List or certificate-array enforcement body | `return-void` | Pin set, pinning-failure and exception evidence required; wrappers already delegating into a patched check need no duplicate patch |
| App-owned pinning X509TrustManager | `return-void` | Existing pin-specific interface/body rule |
| App-owned pin-specific HostnameVerifier | `return-true` | Existing custom pin-check rule, not standard hostname relaxation |
| Flutter `http_certificate_pinning` / `ssl_pinning_plugin` helper | `return-true` | Named synchronous `checkConnexion` shape, MethodCallHandler ancestry, fingerprint helper and comparison evidence |
| appmattus/babylon CT base policy selector | `return-false` | Named base, policy/result evidence; preferred over patching its related interceptor |
| Recognized CT interceptor with no selected ancestor selector | `interceptor-proceed` | Returns the real `chain.proceed(chain.request())` response; preserves request identity and propagated exceptions |
| App-owned Conscrypt verification callback | `conscrypt-server-trust` | Removes one audited server-trust invocation while retaining the original callback body |

Every accepted candidate and the public artifact's Java transform record now name
the `replacement`. Internal selection TSV has three columns:

```text
CLASS_DESCRIPTOR<TAB>METHOD_DESCRIPTOR<TAB>REPLACEMENT
```

The writer rejects missing/unknown contracts, duplicates and return-type
mismatches. It does not infer success from return type alone. Constructors,
native/abstract methods, ambiguous duplicate definitions and unaudited static
shapes are excluded. Existing pinning rules also require a pin/pinned/pinning
word rather than matching an incidental substring such as "Skipping".

## Family details

Flutter support targets the plugins' Android decision helper, leaving the
MethodChannel callback path intact. An empty `onMethodCall` body would strand the
caller. The matcher handles both direct Java string comparisons and the current
Kotlin collection-based comparison. Renamed/inlined plugin helpers without the
required evidence remain unrecognized. This does not bypass a separate Dart
`SecureSocket.peerCertificate` comparison or native Flutter TLS validation.

The CT selector must return false, not true. A selected base selector suppresses
its descendant interceptor fallback so the patch does not unnecessarily skip the
interceptor. The fallback is limited to the known CT interceptor shape with the
original request/proceed calls; arbitrary business/authentication interceptors
are not rewritten. Standard delegated hostname checks remain in place. Android
platform/NSC CT and these application libraries have separate acceptance scopes.

Conscrypt's callback also decodes certificates and updates the negotiated peer
chain. Replacing its whole body with return-void can break clients later in the
connection. The new contract retains those operations, exception handling and
client-trust calls, removing only one matching void `Platform.checkServerTrusted`
invocation. Replacement nops occupy exactly the invocation's original code-unit
span, preserving branch, try-handler and debug positions. A missing or ambiguous
call fails the rewrite. Server chain/endpoint validation performed by that call
is intentionally bypassed; this is not a pin-only trust-preserving edit.

Conscrypt recognition requires callback implementations in the selected app DEX
under `org.conscrypt` or the GMS-repackaged namespace. Merely referring to such a
class does not make an external Play-services provider patchable. Boot-image
Conscrypt, the separate system WebView provider, Chromium result objects,
native BoringSSL/OpenSSL and broader Flutter engines remain outside this batch.

## Validation and reproduction

Matcher controls cover named and renamed enforcing methods, missing code
evidence, callback-only lookalikes, wrong scope, static/native/abstract/duplicate
definitions, CT fallback selection and unrelated interceptors.

The host integration runner pins its test-only dependencies in
`config/pinning-fixture-dependencies.json`. It compiles real libraries/source to
DEX, builds/signs an owned APK, calls the production shadow patcher, verifies
original DEX preservation, then translates the rewritten DEX for strict JVM
execution. Java stack-map frames are recomputed for this host adapter; JVM
verification is not disabled. D8-generated plugin lambda helpers are supplied
from the preserved original DEX.

The functional cases exercise:

- Real OkHttp3.14.9 List and varargs pin checks: reject before, accept after.
- Real appmattus2.8.4 policy/result behavior and its HostnameVerifier wrapper:
  CT is disabled while a wrong hostname still fails the delegate.
- An owned CT interceptor fallback fixture: exactly one proceed call, the same
  request/header/response objects, and unchanged exception propagation.
- Published `http_certificate_pinning`3.0.2 and `ssl_pinning_plugin`2.0.0 Kotlin
  sources: wrong fingerprint rejected before, secure result after, callback
  completed exactly once. Android/Flutter scheduling/channel adapters are host
  stubs; this is not a Flutter-engine/device test.
- Conscrypt2.5.2 shared Java callback code in its real OpenJDK provider: local
  TLS rejection before, successful handshake/payload after, peer-chain data
  retained. Both rewritten callbacks are inspected to retain parsing/session and
  client-trust calls. This is not Android JNI/device verification.
- Malformed, ambiguous selection metadata and replacement/type mismatch refusal.

```sh
. /home/water/workspace/Projects/pentest/tools/configure
# Explicit, hash-verified test downloads only when the fixture cache is missing:
python -m scripts.pinning_extension_cases --fetch-dependencies
# Repeat with no downloads:
python -m scripts.pinning_extension_cases
# One diagnostic case:
python -m scripts.pinning_extension_cases --case conscrypt
# Full host regression suite including real-library checks:
REPACK_TEST_SDK=1 python -m unittest discover -s tests -v
```

The optional fixture JRE17/Kotlin compiler/dex2jar tooling lives under ignored
`.work/` and is independent of the production SDK/JDK. These fixtures currently
target a Linux x86_64 host. Normal APK patching uses the existing pinned SDK and
smali dependencies and does not download these test tools.

These host checks provide discovery, APK packaging, DEX transformation and Java
semantic evidence. Device acceptance is recorded separately below.

On 2026-11-08 the complete 103-test host suite passed, including all five library
cases. Its initial immutable library report is
`.work/evidence/runs/20261107T153910-36f5f1b3a2/report.json`; the initial regression
log is `.work/pinning-extensions-regression.stderr.log`.

### Android acceptance (API30, ARM64, target35)

The repeatable runner builds an ordinary app with a real Android Activity,
Handler and Looper. It reapplies the current production patcher to the pinned
original library APKs, appends the test code/dependencies, signs, installs and
runs each original/patched pair. Its token-bound JSON records include app UID,
PID, target SDK, APK hash and the observed result. It refuses an existing fixture
package, updates only the package created by this run, verifies installed hashes,
then removes that fixture and its owned TLS server/reverse mapping.

```sh
. /home/water/workspace/Projects/pentest/tools/configure
# Generate the immutable host inputs if they are missing:
python -m scripts.pinning_extension_cases --fetch-dependencies
# Workspace uses a remote ADB server; bind its reachable workspace interface:
python -m scripts.pinning_extension_android --device 5c94c0e5 --tls-bind 10.20.30.2
# With local ADB, omit --tls-bind (defaults to 127.0.0.1).
# To select one diagnostic pair:
python -m scripts.pinning_extension_android --case conscrypt-fd --tls-bind 10.20.30.2
```

Twelve observations passed on the recorded Redmi K20: original and patched
variants of OkHttp3, CT policy/hostname wrapper, the owned CT interceptor fallback,
both published plugin sources, and both Conscrypt socket backends. The fixture
ran as UID10598, target35, without hidden-API exemptions or root commands.
Unpatched controls rejected their intentionally wrong pins/trust; patched controls
accepted. CT retained wrong-host rejection, interceptor delegation retained
request/header/response and exception identity, and each plugin callback completed
exactly once. Plugin execution used real Android scheduling and fixture Flutter
channel adapters; a Dart engine and real Flutter transport remain untested.

Conscrypt uses the separately pinned Android2.5.2 AAR and its original ARM64 JNI
library, not the host OpenJDK provider. Both `Java8EngineSocket` and
`Java8FileDescriptorSocket` completed a local TLS1.2 handshake and read a payload
after patching; the rejecting trust manager ran once before and zero times after.
Negotiated peer certificates remained available. This verifies the bundled
provider on this cell; system/GMS providers, other versions, mutual TLS and other
Android releases have no new acceptance claim.

Immutable device report:
`.work/evidence/runs/20261107T162221-0fb201f871/report.json`.
Index: `.work/evidence/PINNING-EXTENSIONS-android.json`.
The runner and Java fixture sources are under `scripts/` and
`tests/fixtures/pinning_extensions/android/`; no AI is needed to repeat them.

The new public Midway artifact at
`.work/outputs/midway-pinning-extensions-host-v1/manifest.json` also passed fresh
and retained-data cold launches, 90 seconds each, on the same phone. Both showed
the normal welcome screen and decrypted primary API GraphQL200 and SDK log201;
both selected Java methods logged execution in the app process. Headers and the
operator's global proxy were unchanged. All50 native libraries and six original
DEX payloads remain preserved. These are the same two Midway methods as before,
so the separate fixtures above supply the new-family proof. Details and current
operator command: [Midway acceptance](targets/midway-pinning.md).

The final host rerun also passed103 tests in60.610 seconds; log:
`.work/pinning-extensions-device-regression.stderr.log`. Its immutable library
report is `.work/evidence/runs/20261107T162052-717c170da4/report.json`.
Final installed-hash and cleanup proof:
`.work/evidence/runs/20261107T162456-ddbf808100/report.json`.
Midway remains installed and stopped; the owned fixtures, proxy/TLS listeners and
reverse mappings are removed. Start the documented proxy session to use its baked
loopback endpoint.
