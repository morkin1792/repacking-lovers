# Implementation progress

Current gate: additional APK pinning adapters
State: accepted within the recorded API30/ARM64, target35 fixture scopes
Last completed task: Chromium/Cronet with a native pin control, optional hostname/call-site edits, offline native TLS, typed Dart predicates, public CLI composition and126 passing host tests
Evidence paths: [handoff](../../.work/evidence/PINNING-EXPANSION-handoff.json), [commands and exact limits](../pinning-expansion.md)
Next task: operator-selected target/flow or new runtime evidence; login remains deferred
Blocking prerequisite: none for the implemented adapters; foreign-runtime markers and unsupported Dart shapes are not generic bypasses

## Continuing goal — 2026-11-06

User objective remains: implement all phases, then test the installed Midway app. No later phase
or Midway runtime validation is claimed complete.

- Implemented manifest RepackFactory, early/late bootstrap, original-factory composition and the
  internal spike command. ARSCLib1.4.0 is pinned by SHA-256 for binary-manifest edits.
- Host checks pass across own/final, AndroidX, absent-factory, custom-loader and exception variants.
  [Host report](../../.work/evidence/BOOTSTRAP-host.json) retains the five signed artifacts and logs.
- Eleven host/runner checks passed, including unchanged DEX/resources/other manifest attributes,
  malformed/prepatched refusal, matching versus conflicting recreation events and immutable references.
- The Redmi is reconnected and authorized. BOOTSTRAP passed the actual five-variant runtime
  matrix; earlier duplicate-event and device-availability failures remain historical evidence.
- T-N10 passed both default/explicit HTTP endpoint paths. The first T-N12 run exposed the phone's
  existing operator proxy in the unrelated-app control; the control now compares ordinary selector
  state before/after and uses a separate direct-socket origin control. Retained failures are not acceptance.
- The workspace uses an external ADB server. Its CLI rejects host-qualified reverse specifications;
  the tested smart-socket protocol accepts them. Owned listeners are observed on phone loopback,
  bind to this workspace's isolated bridge, and are removed without changing unrelated mappings.
- T-N11 is explicitly not-run for global proxy transitions. Existing operator proxy settings are
  preserved; startup acceptance makes no persistence claim.

Midway `br.com.midway` was identified on the Redmi and its original three-member installed APK set
was pulled read-only. [Static summary](../../.work/targets/midway/static/summary.md) confirms the
main React Native/TrustKit path and a bundled Flutter module; selected splits and native handling
are required for the final test. Original Midway installation/data were not changed or launched.
The final network-header choice remains pending; all earlier work used owned fixtures/static reads.

## M0 accepted — 2026-11-05

- First cell: Redmi K20, API30, arm64-v8a, 4096-byte pages, non-root shell; fixture target35/min28.
- Toolchain: installed JDK27 with javac --release 8, compileSdk36, build-tools36.0.0.
- Git initialized locally; .work, credentials and build output are ignored. No commit or remote created.
- Four release APKs built/verified: own/final factory and AndroidX CoreComponentFactory for each app.
- T-A00 passed 34 comparisons: 32 actual signing queries and two wrong-expected controls.
- Final run recorded 0 UI-wait timeouts. Four runner negative-control tests passed.
- Only dev.repack.fixture.identity and dev.repack.fixture.other were installed/updated; they remain
  installed with the persistent original/other keys. No user app, CA, proxy or hidden policy changed.

Source the [operator ADB setup](/home/water/workspace/Projects/pentest/tools/configure) before
ADB discovery. Its configured server sees the phone; the default unconfigured local server does not.
The runner records/reuses the configured server socket. All commands close stdin for noninteractive
execution; this resolved the observed am start -W harness stalls.

[Host](../../.work/evidence/M0-host.json), [device](../../.work/evidence/M0-device.json),
[build](../../.work/evidence/M0-build.json) and gate summaries point to immutable per-run reports.
Earlier failed build/launch runs are retained. Original own/AndroidX APK snapshots, public cert DER
and [input hashes](../../.work/inputs/fixture-snapshots.json) are available under ignored .work/inputs.
Private keys/password remain in ignored .work/keys and are reused across builds.

## Handoff defaults

Default bootstrap is our appended RepackFactory plus binary manifest attribute edit and composition
delegation. Shadowing stays in the separate --dex-only/M3 paths. Identity inventory/T-A06 open in
M1a task 3, using the selected phone API. Prefix ["L"] is process-local. The public CREATOR/Parcel
metadata branch precedes hidden constructors for a selected API28–34 cell; API35 source facts
remain reference cases and do not establish API30 identity support. The manifest bootstrap is accepted; routing, trust and identity behavior remain pending their gates.

## Gate ledger

| Packet | State | Evidence |
|---|---|---|
| M0 | accepted | M0.json / T-A00.json |
| BOOTSTRAP | accepted | .work/evidence/BOOTSTRAP.json |
| M1a identity spike | accepted | .work/evidence/M1a.json |
| M1b-5 startup HTTP routing | accepted, transitions not-run | .work/evidence/M1b-5.json |
| M2 embedded-CA HTTPS trust | accepted | .work/evidence/M2.json |
| M3 Java pinning | accepted | .work/evidence/M3.json |
| M1b-1 signing contracts/caches | accepted, cache-hit repair unobserved | .work/evidence/M1b-1.json |
| M1b-2 JNI/fresh Java Binder | accepted, raw/retained paths excluded | .work/evidence/M1b-2.json |
| M1b-3 split/install/public CLI | accepted | .work/evidence/M1b-3.json |
| M1b-4 process/release cells | accepted, explicit single physical cell | .work/evidence/M1b-4.json |
| Optional M2-CT / M2-DEX | planned | none |
| Conditional T-A16 legacy metadata | accepted API30 adapter, three profiles/invalid controls in T-A10 | M1a.json / T-A10.json |
| RELEASE-1 | accepted | .work/evidence/RELEASE-1.json |

The remaining requested phases retain their full scope:

| Later phase | State |
|---|---|
| M4 original-byte/native import hooks | accepted, explicit native-base-bytes scope |
| M5 input-container support | accepted |
| M6 native/managed pinning | accepted, exact third-party reFlutter ARM64 scope |
| M7 explicit gadget mode | accepted, owned raw-syscall fixture only |
| M8 verification and evidence presentation | accepted, owned fixture auto-pairing and manual inconclusive captures |
| Midway target validation | 1.85 plain resource-rebuild startup verified on two 60-second launches with target-specific signer/permission configuration; maintenance/error UI, login/pinning unverified; historical1.53 attribution remains qualified |

## BOOTSTRAP accepted on reconnected Redmi

T-A01 passed 11 comparisons: five factory variants before/after compilation and the preserved
exception contract. T-A02 passed eight signing observations plus the compressed-resource rejection.
[Gate evidence](../../.work/evidence/BOOTSTRAP.json) freezes immutable M0/T-A01/T-A02 references.
The service fixture now uses a normal foreground service and verifies its destruction callback,
so the locked-screen/background UID state does not invalidate component-delegation testing.
All changes remain confined to project fixtures; Midway has not been launched or replaced.

## M1b-5 accepted — startup-only HTTP

T-N10 passed default8080 and explicit18080 endpoints before Application networking. T-N12 passed
nine controls including an independently reachable origin, proxy-down fresh-client failure with
zero origin hits, explicit direct-socket success, unchanged second-app proxy selection, conflict
refusal, proxy recovery and ADB reconnect recovery. Only owned mappings/processes were cleaned up.
T-N11 remains not-run: the operator phone already has a global proxy, preserved exactly.
[Gate](../../.work/evidence/M1b-5.json) declares startup HttpURLConnection HTTP scope only.
Twelve host/runner controls passed. No HTTPS, other-stack, mobile-data or OS-transition claim follows.
The local mitmproxy12.3.1 wheel is pinned by SHA-256 and each run retains installed package versions.
Apktool3.0.3 was downloaded from its official release and matched the publisher's SHA-256; M2 will
use its raw-DEX resource decode/build path and private framework cache.

## M2 runtime progress and external ADB outage

- Pinned Apktool3.0.3 raw-DEX resource round trips passed the independently aapt2-built absent,
  existing and API-qualified NSC fixtures: 3/3 attempted fixture rebuilds. The selected Midway
  split set remains not-run until selected-set validation exists; its base alone was excluded.
- T-T20 observed three actual decrypted HTTPS requests and app responses after public-CA insertion.
  Existing domains/anchors/pins and opaque DEX/native/assets are retained. Every explicit anchor
  set gains overridePins=true for the injected public root. No CA private material is embedded.
- T-T21 observed six successful comparisons: proxy requests for domain/nested explicit-anchor
  configurations; original private-anchor/matching-pin success on a direct TLS origin; rejection
  of another key signed by that same original CA; rejection without the injected root; rejection
  in the second app without that root. These are individual observations, not M2 acceptance.
- The external ADB server stopped responding during the wrong-CA request. M2 remains unaccepted;
  wrong-CA and complete final policy assertions must finish after reconnect. The user was asked
  to restore the host server. Local proxy/origin processes were stopped. An owned phone reverse
  mapping tcp:8080 -> tcp:10.20.30.2:18080 could not be inspected/removed during the outage.
  [Pending cleanup](../../.work/evidence/pending-cleanup.json) binds it to its creation record.
  Verify the exact current destination before removing this mapping; preserve all others.
- The shared device helper now records incomplete cleanup and keeps the original request error.
  A missing ADB server is a prerequisite failure, separate from a measured TLS mismatch. Rerun
  the current trust cases before accepting M2; prior per-run evidence remains immutable.
- Host controls cover additive NSC inheritance/qualifiers, private/malformed certificate refusal,
  unchanged opaque payloads, modified-DEX rejection, and honest zero-denominator screening counts.

M3 and later phase work remain gated by M2. The full requested scope and final Midway runtime
test remain outstanding. Midway's installation/data have not been modified or launched.

Final host checkpoint: `python -m unittest discover -s tests -q` passed 23 tests, including five
SDK-built bootstrap variants, after the M2 implementation and cleanup hardening. Python compilation
also passed. The final availability probe still returned connection refused for 10.20.30.1:5037.

After restoring the external ADB server, first inspect `adb -s 5c94c0e5 reverse --list`. Remove
only the pending owned source when its destination exactly matches the recovery record. Then run
T-T19, T-T20, T-T21 and `gate M2` against the current source revision. T-T19 does not install apps;
T-T20/T-T21 require the fixture-only replacement flag and `--proxy-bind 10.20.30.2` on this host.

## Continuation: second server loss and bounded isolation

The configured server returned and the Redmi was rediscovered. Recovery verified that the previous
owned mapping was already absent after server restart. The recovery report is retained, and T-T19
and T-T20 were rerun successfully: 3/3 resource fixture rebuilds and 3/3 decrypted HTTPS responses.
The same six T-T21 policy comparisons passed again, before the external ADB server disappeared
during the wrong-CA broadcast. The improved helper retained the original request error and an
explicit pending cleanup record. Cause of the server exit is unknown; no technique-failure or
Android wrong-CA acceptance claim follows.

The wrong-CA control now uses the already-tested host port8080, changing only the proxy CA.
An isolated internal `run T-T21-CA` case reuses a hash-verified T-T20 artifact, with no resource
rebuild. It is diagnostic; gate M2 still requires the complete current T-T19/T-T20/T-T21 results.
The host-only [oracle diagnostic](../../.work/evidence/M2-wrong-ca-host.json) passed both positive
and wrong-root TLS controls on that identical endpoint. This does not substitute for Android TLS.
Six trust host controls and Python compilation passed. Google smali/baksmali3.0.9 and the explicit
OkHttp4.12.0/Okio3.6.0/Kotlin1.9.10 fixture dependency closure were downloaded from Google Maven
and Maven Central into ignored .work/tools/maven. Jar/POM hashes are retained there; both official
Google command-line tools launched successfully. M3 implementation remains gated by M2.

The user was asked to restart the host ADB server with its terminal left open and capture its
last lines if it exits again. The most recent probe still found connection refused. After recovery:

1. Inspect/remove only the mapping bound in pending-cleanup.json (currently tcp:8080 with
   destination tcp:10.20.30.2:18080); preserve any different owner/destination.
2. Run `python scripts/acceptance.py run T-T21-CA --device 5c94c0e5 --replace-existing-and-wipe-data --proxy-bind 10.20.30.2 --out .work/evidence/T-T21-CA.json`.
3. Once isolated Android failure/cleanup are observed, rerun current T-T19, T-T20, T-T21 and gate M2.

Midway's original installation/data remain untouched. All later phases and its final runtime
test remain outstanding. The most recent local proxy/origin processes have been stopped.

## M2 accepted after recovery

The isolated T-T21-CA Android wrong-root control passed on the unchanged port8080 endpoint while
a separate raw ADB health observer remained connected. Full current T-T19, T-T20 and T-T21 then
passed, and gate M2 accepted its three insertion/HTTPS variants and eight policy controls. All
owned mappings/processes were cleaned up. The earlier daemon exits remain unexplained; no causal
claim is made about the wrong-CA test. The current daemon reports android-tools36.0.1 on the host.

M3 is now open. Official Google smali/dexlib2/baksmali3.0.9 and pinned fixture dependency hashes
are recorded in config/java-dependencies.json. Midway remains untouched, with all later phases
and its final runtime test still outstanding.

## M3 implementation in progress

The typed DEX helper uses the pinned Google dexlib2 API, with conservative descriptor/hierarchy,
exception/reference and pinning-string signals. Complete matched classes share one shadow DEX;
original DEX entries are shifted contiguously with unchanged payload hashes. It preserves method
contracts and logs REPACK_PATCH at actual execution. No original owning-DEX rewrite is used.

T-U30 passed the unpinned routing/trust control, five original pinned failures and five patched
decrypted request/response cases: OkHttp4.12.0, direct/inherited X509TrustManager and direct/inherited
HostnameVerifier. The initial matcher missed OkHttp's compiler-combined multiline failure string;
its descriptor/field/exception checks were retained while recognizing that actual string form.
Four matcher host controls passed, including string-only false positives and unsupported contracts.

The first T-U31 run passed R8-renamed classes and a 65,530-method original DEX, including cold
launch after compilation. The expanded run adds a genuinely inlined guard/optimization case with
explicit unsupported-path evidence. T-U32 compares complete-class canonical disassembly outside
selected methods, and tests prepatched/missing-trust/resource-failure controls. Baksmali-generated
synthetic-accessor comments are disabled because the partial shadow has less analysis context;
actual unedited code/metadata still must match. Final current-source T-U30–32 and gate M3 remain
required. All later phases and final Midway testing remain outstanding.

## M3 accepted

Current-source T-U30/T-U31/T-U32 passed 11/22/6 comparisons and gate M3 accepted their immutable
reports. The R8 optimized variant retained three matchable method owners for the five supported
clients, and all five requests passed after patching; the guard actually inlined into perform
remained enforced with zero decrypted requests. Original near-limit DEX bytes were preserved at
65,530 method references, and selected shadow definitions ran after speed compilation. The
independent complete-class disassembly comparison passed for all unedited members. String-only
input reports unsupported rather than a missing-environment prerequisite; prepatched/native/
abstract/unsupported-contract and missing-trust/resource-failure controls passed.

The remaining identity track is now open. API30 CSV bytes were downloaded from the pinned official
URL and matched the 45,003,418-byte file's expected SHA-256. LSPosed HiddenApiBypass6.2 AAR/POM/module
and its full classes.jar were downloaded to ignored .work/tools for the selected Unsafe-based
implementation. Its separate LSPass variant is not the selected mechanism. Pin/license/closure
and on-device access observations remain to be implemented in the identity packet.

## M1a accepted — API30 scalar identity

Current-source ordinary and pinned T-A06 observations passed. Live guarded logcat capture keeps
startup records that were previously evicted from logd's ring. Ordinary enumeration exposed56
methods while the pinned mode exposed195 (194 CSV methods and an image-specific difference); both
read-only proxy forwards and the ApplicationInfo canary passed. Counts remain diagnostic. The
functional strategy is still the pinned Unsafe HiddenApiBypass6.2 with process-local prefix L.
No live proxy reference is replaced by T-A06.

The API30 public Parcel/SigningInfo.CREATOR adapter passed without embedding/invoking the bypass,
with actual current/history getters and a second parcel round-trip. Its layout is API30-specific.
T-A03 passed10 comparisons: four direct/reflective legacy/current paths for self and unrelated
package, plus two missing-package exceptions through the published wrapper. Shell-side installed
UID/path/version truth and framework createPackageContext/getApplicationInfo canaries stayed valid.

T-A04 passed four forced-before-publication/failure-transparency cases. T-A05 passed retained APK
byte/hash equality, framework current/legacy/history parsing, a provider's original-signing query
before archive provisioning, and a later query. The parser callback actually ran after attach,
providers and Application.onCreate. Installed sourceDir reads were never redirected. Embedded
metadata remains required for synchronous startup; framework parsing is a post-context source.
Gate M1a freezes these immutable observations. No signing predicates, lists, JNI or fresh-Binder
coverage is claimed yet. Midway remains untouched. All later phases are still outstanding.

## M1b-1 signing contracts and cache observations

T-A10 passed 362 comparisons across seven genuine reference/companion pairs: single signer,
two v2 signers, and a verified original-to-other rotation lineage with matching, different and
ancestor companions. Public predicates, package/UID comparisons, missing/invalid inputs, metadata,
both list APIs and installer getters are compared against actual reference installations.
The public Parcel adapter separately passed all three profiles and rejected invalid layout/cert
controls without hidden access. List evidence now joins public count/order hashes to the actual
transformed Binder container; the final current-source regression includes that stronger oracle.

Initial T-A11 passed late publication through an existing cached ApplicationPackageManager,
new-context managers, a single process-local clear and retained-object controls. Compatible
same-key updates preserved fixture private sentinel and UID while changing original input hash
and the signing identity supplied by the shim. No retained PackageInfo object was mutated.
The phone reports cache_key.package_info=0 and repeated lookups did not reuse cached results;
repair of an actual prewarmed cache hit is therefore unobserved and stays a named limitation.
No device-wide invalidation/disable or global settings were used. Final current-source gate
joining remains required. Midway was not launched, replaced or modified.

## M1b-1 accepted

Final current-source T-A10/T-A11 passed and gate M1b-1 accepted their immutable reports with the
M1a parent. The known installer fixture was seeded explicitly as com.android.shell and then
captured/preserved by preflight across the signer replacements. This does not fabricate an
installer for arbitrary input APKs. Public list count/order observations match the transformed
Binder containers. Three negative/positive list-oracle unit checks and seven runner controls passed.
Cache-hit repair, already returned objects, shared/cross-user UIDs, unobserved contexts, typed
long overloads absent on API30 and other API levels remain named limits. VersionedPackage queries
are outside the tested String-package contract. Midway remains untouched.

The official NDK r28c archive was verified against its published length/SHA-1 and pinned with
SHA-256 dfb20d396df28ca02a8c708314b814a4d961dc9074f9a161932746f815aa552f.
Compiler/linker/readelf hashes and source.properties/NOTICE/jni.h are recorded in
config/ndk-dependency.json. JNI will build directly with its Clang target driver, without adding
CMake or Gradle. First runtime ABI is the connected phone's arm64-v8a; x86_64 is built and inspected
for the unavailable emulator cell, with no x86_64 runtime claim.

## M1b-2 accepted

Current-source T-A12 passed30 comparisons: genuine and patched JNI-to-public-Java calls with
direct/reflection counterparts, self/other identities, no-A controls and original missing-package
exceptions. Both x86_64 and arm64 JNI libraries have16KB ELF load alignment; only arm64 was loaded
on the phone. Native fixture libraries are confined to owned fixture APKs. C/C++/assembly sources
now participate in source/fixture hashes.

T-A13 passed28 observations across normal early and controlled deferred publication. Fresh Java
ServiceManager package handles resolve through the exact queryLocalInterface descriptor to A.
A handle/stub captured by fixture code before deferred publication retains the real signer.
Raw getPackageInfo parcels through both the wrapper and original Binder also retain the installed
repack signer. The shim forwards transact unchanged. Descriptor, ping/liveness, asBinder identity,
unrelated descriptors, Object identity, registration/unregistration of death recipients and an
unknown transaction were measured. Actual system-service death was deliberately not triggered.
A wrapper-specific forced rollback remains unexercised; M1a's ordinary A rollback is separate.

Gate M1b-2 binds these current reports, compiler and platform-inventory snapshots to M1b-1.
It opens M1b-3; selected split sets, installer lifecycle and public CLI remain outstanding.
Midway remains installed unchanged and unlaunched. All later phases and the final target test
remain outstanding.

## M1b-3 initial read-only inventory

Added repack/recon.py for binary manifest inspection, verified current signer PEM/DER and available
rotation lineage extraction, ELF/ABI inspection and selected-set dependency/type validation.
The locked apksigner supports --print-certs-pem for both verify and lineage, so no certificate
extraction helper project is needed. A selected device also gets an API-specific verification
view; the default/latest signer view is retained separately for rotation targeting.

The original on-disk Midway three-member set passed the initial inventory: matching package,
version100946 and signer; required base__abi/base__density members; arm64 native split. No target
APK was patched or installed. Six host validator controls passed: valid dependencies, missing
base/feature/type, conflicting IDs/package/version/signers, cycles/config targets, SDK/ABI mismatch,
and preserving a 32-bit input ABI on a compatible 64-bit phone. This is read-only calibration,
not T-P10 or runtime acceptance. Signed split fixtures, install-multiple lifecycle and public
pipeline/CLI still remain to be implemented.

## M1b-3 split/runtime and lifecycle controls in progress

Initial T-P10 passed15 comparisons. The five-member fixture contains a base, dependent parent/child
feature DEX, an actual density resource split and an arm64 JNI split. Genuine and repacked legacy/
current queries loaded both classes, a lazy asset, density-config string and native library; the
repacked set also passed after speed compilation. All selected members were re-signed, including
unchanged native/resource/code splits, whose opaque entry bytes/compression were compared.
Ten malformed sets were rejected: missing base/feature/ABI/density types, duplicate split ID,
wrong signer/version/package, prepatched input and corrupted signed payload. Current code also
requires each rejection's intended cause, so an environment failure cannot count as a negative pass.

Initial T-P11 passed8 comparisons: absent install, actual changed-feature compatible update with
private sentinel/UID preserved, unapproved signer refusal, explicit fixture replacement/data loss,
platform INSTALL_FAILED_TEST_ONLY with old package/data retained, missing/changed members before
uninstall and persistent key. install-multiple captured/preserved the known installer; both public
legacy and installing getters were observed, with initiating/originating reported separately.
The first failure fixture used the wrong setup argument and was correctly blocked by signer
preflight; the corrected run reached the intended platform rejection. Failed evidence is retained.

The shared installer now normalizes explicit member lists, validates actual split manifests and
checks every hash before uninstall. Fixture callers retain their fixed allowlist. A future public
CLI caller must bind a separate exact requested package; user-app replacement still requires its
explicit wipe flag and refuses another Android user with installed/unknown package state. No user
app has been installed/replaced. Public CLI/schema integration and final current-source M1b-3 join
remain outstanding.

P0 now preserves SDK-range signer records. A v3.1 fixture's host verifier reports the old certificate
for API30 and the new certificate/history for API35; this is host metadata evidence, not API35
runtime support. Split verification inherits the base minimum SDK. Typed DEX inventory now includes
field references and integer literals for advisory signing triage. Five conservative Java matcher
controls passed, including rejecting an exception-typed field as exception behavior. Midway remains
unchanged and unlaunched; all later phases remain outstanding.

## M1b-3 public integration working; final regression pending

Implemented public triage/patch/verify, a version1 artifact manifest and console/module entry points.
Single APK sidecars and selected-set manifests carry output hashes plus semantic configuration
bound to an embedded signed-base marker. Output creation refuses overwrites. Keys are resolved
from existing operator references; missing keys are never regenerated. The marker records actual
original input hash, selected-platform signer/history, CA, endpoint, transform decisions and tools.
Runtime verdicts are separate measured reports; editing a manifest to say passed cannot satisfy
verification. Seven artifact parser/marker controls passed.

Initial T-P12 passed10 comparisons: installed-set read-only triage; stable semantic report fields
across equivalent trust builds; default no-A actual signer control; combined A/routing/CA selected
set with decrypted HTTPS and request/response oracle; lazy feature/native/density loading after
resource rebuild; original hash binding; modified-output/endpoint refusal; prepatched/unsupported/
conflicting/removed-flag/missing-key controls; v3.1 API-specific host views matched by an actual
API30 genuine install; schema controls. API35 runtime remains not-run. Read-only triage now permits
inspection of patched artifacts and excludes helper classes from signing-reference advisories;
patch still requires clean original input. A full current-source T-P10/T-P11/T-P12 join is running.

The configured proxy's public CA was fetched from its local export endpoint into ignored
.work/keys/operator-burp; its SHA-256 is fdaa77f27f13d76cc53b9f427f871ea91b661df9ddb07dc209124e38fe8b3803.
No CA was added to the phone. The eventual Midway artifact can use this actual operator anchor.
Midway remains installed unchanged and unlaunched. Header choice/runtime replacement approval,
M1b-4, RELEASE-1, M4–M8 and the final target test remain outstanding.

## M1b-3 accepted

Final current-source T-P10/T-P11/T-P12 passed15/8/10 comparisons and gate M1b-3 accepted their
immutable reports and exact dependency chain. Combined startup HTTPS was independently decrypted
by the owned proxy, with actual original identity, lazy feature DEX/asset/density/native loading
and original-input hash binding. Native/file/Binder negative gaps remain named. Source/header/
installer/key/manifest refusals and failure states were observed. Only the two owned fixtures
were installed/replaced. The public runtime verifier still reports not-run until M8.

Before opening process-code work, a host-only public patch of the original Midway selected set is
running with the exported operator proxy CA. This is calibration of real-target resources and
Java candidates, not target runtime evidence or installation approval. Its original three APK
hashes and phone installation remain preserved. M1b-4, RELEASE-1, M4–M8 and final Midway runtime
validation remain outstanding.

## Real-target resource compiler correction

The first public Midway build failed because the forced SDK aapt2 rejected decoded private
$avd/$facetec drawable names. Its original/failed artifacts and commands are retained. A bounded
trial using Apktool3.0.3's own patched aapt2 rebuilt the same decoded resources successfully;
an independent SDK dump found all6,456 original resource ID/name bindings preserved, with one
new CA resource. The compiler blob is pinned at SHA-256
df312db814c018019b2b79a993b041b738d7b76f4a8f28da25bc874a026368cc and is now the decoded-resource
compiler. SDK36 aapt2 remains the source-fixture compiler and independent metadata/resource reader.
Every rebuild now checks original resource ID/name bindings; host controls reject remapping.

A complete host-only Midway calibration artifact was built at
.work/outputs/midway-calibration-v2/manifest.json using the actual operator proxy's public CA.
All three members were re-signed; Java selection contains TrustKit PinningTrustManager's
checkServerTrusted and OkHttp CertificatePinner's check$okhttp. API30 A is explicitly selected.
The source originals and phone's original installation were not changed or launched. Static
matching/build success is not a target pinning/identity/runtime acceptance claim.

The resource fixtures now include inline animated-vector source that stock aapt2 expands into
private $ names, preventing the compiler regression from hiding behind simple fixtures.
T-T19/T-T20/T-T21 and M2 revalidation passed with those generated private-name fixtures.
The binary-resource fallback remains available as a planned branch for future engine failures;
this failure was resolved with Apktool's pinned intended compiler, without renaming resources.

## M1b-4 process tests and release regression in progress

The first process test exposed a fixture-oracle error: Android appends the isolated service's
class name to its process name. After correcting that expectation, actual main, remote, restarted
remote and isolated-process queries succeeded independently. The provider control then exposed
a production bug: constructing SigningInfo on every lookup used the application's newly installed
X.509 provider and threw UndeclaredThrowableException. Its failed run is retained at
.work/evidence/runs/20261106T013709-b2d9e0a423/report.json.

OriginalIdentity now prepares a private SigningInfo template before PM publication and returns
fresh public-Parcel copies. The process fixture mutates caller-visible signer arrays; later
queries must still match the independent original signer. Forced setup failure with the Binder
wrapper enabled now occurs after actual service-cache publication, then verifies restoration of
both cache and PM references. T-A14 passed143 comparisons across11 runs, including the provider
and rollback controls, before additional installed-metadata and per-PID ordering assertions.
Those strengthened assertions are included in the current regression; final acceptance is pending.

config/support-matrix.json declares only the connected physical API30/target35/arm64/4KB fixture
cell. Its fingerprint and ordinary non-root execution are recorded; factory-stock firmware
provenance is not established. Other APIs, emulator and16KB runtime cells remain excluded.
T-A15/M1b-4/RELEASE-1 now join immutable same-cell reports and check current sources/tools; the
pre-regression release attempt correctly refused stale M0 evidence. All44 host tests passed.
A serial40-step release regression is running with source frozen. It reruns both tracks,
selected-set install/public CLI composition, HTTPS and process tests before the final join.

The first full regression passed every runtime case, including strengthened T-A14 and T-A15,
but M1b-4 rejected the join because its new gate compared absolute and relative index strings as
different references. The immutable report path and SHA-256 were identical. The gate now
canonicalizes its input path before resolving the reference. Three focused host controls cover
path aliases, stale-source refusal and tampered-child refusal. The first run/log and original
gate source are retained under .work/evidence/release-path-fix. The required current-source
regression is running again; no app-side source changed for this correction.

The recovered configured ADB server sees5c94c0e5. No cause for its earlier daemon exit has been
established. Only owned fixtures are installed/replaced. Midway remains unchanged and unlaunched;
its host calibration artifact is not runtime acceptance. M4–M8 and the final authorized target
test remain outstanding.
The calibration-v2 artifact predates the provider-independent signing-template fix; rebuild the
final Midway artifact from preserved originals after the remaining implementation phases.

## RELEASE-1 accepted

The corrected40-step regression completed. Final immutable release report:
.work/evidence/runs/20261106T021837-371dc4443a/report.json. T-A14 passed143 comparisons with
per-PID ordering, installed metadata, isolated UID, restart, caller-copy, X.509 provider and actual
published-Binder rollback controls. T-A15 joined the declared same-cell packets, and M1b-4 plus
RELEASE-1 accepted their hashes and current tool/access locks. OS proxy transitions remain not-run;
emulator/API35/16KB/other firmware claims are excluded. Main-process predicate/list/Binder scope
does not automatically extend to services. No factory-stock firmware claim is made.

M4 is now open. Read-only research downloaded ByteHook1.1.2 and its required ShadowHook2.0.1
upstream artifacts, license and source archive, with hashes retained under .work/tools/native-research.
ARM64/x86_64 prebuilt LOAD segments have16KB alignment; that host observation is not runtime proof.
The first experiment will record imported-symbol coverage and delayed loading without redirecting
file paths. Midway remains original and unlaunched.

## M4 import smoke and first scoped original-byte experiment

T-B00 passed59 checks on the recorded API30 arm64 phone. Both owned caller libraries import all14
named opening/metadata functions. The openat-only stage caught only its own import; the full family
caught all8 opening variants. Delayed loading and its constructor open were observed, all28 import
tasks were removed, and raw syscall/dlsym reads remained explicit bypass controls. The app linker
namespace refused the private libart load. x86_64 binaries were built and checked, not run.

The first integration failures are retained: Android selected a dependency's JNI_OnLoad until the
bridge defined its own native-only initializer; a large log message then exceeded logcat's entry
limit. Results now use58 individually bounded events with exact completeness/PID checks. Native
reads now report full-file SHA-256 in addition to the initial FNV/size smoke fingerprint.

T-B01 passed178 checks over initial/cached/deliberately corrupted fixture storage. The embedded
original is independently host verified, copied atomically to a hash-specific private directory,
verified before reuse, made read-only and checked again after native reads. Corrupt storage was
repaired from the verified embedded original. Canonical paths are used because this phone resolves
/data/user/0 to /data/data. Its first failed exact-path oracle and a compile-time macro-shadowing
error are retained rather than counted as technique failures.

Only absolute read-only APK opens in the two selected native callers are redirected. Their full
read hashes and stat/fstat sizes match the exact original; unselected Java reads still match the
installed patched APK. Raw syscall/dlsym reads return patched bytes, and descriptor readlink/readlinkat
explicitly reveal the retained private file. That disclosure is a named unsupported check, not a
concealment success. Relative dirfd paths, preopened/duplicated descriptors, offsets/mmap, other
metadata fields, early provisioning and split-original mapping are not yet accepted. No public B
flag is exposed. T-B02/T-B03 and the M4 gate remain outstanding; Midway remains untouched.

## M4 expanded native experiments passed

Final prototype T-B00/T-B01/T-B02/T-B03 all passed after source was frozen for that group.
T-B00 now has64 comparisons and full read/mmap SHA-256 checks. T-B01 has193 comparisons, including
shared offsets after dup, pread preserving the cursor, duplicate-fd size/path observations, full
mmap bytes and a pre-hook descriptor that continues to expose installed bytes. The first added
preopened control needed an explicit seek before repeating a full-file comparison; that failed
fixture run is retained. Relative dirfd redirection and proc-fd path concealment remain excluded.

T-B02 passed130 comparisons. In the same PID, selected native callers read the exact original
base while A returns original signer metadata, Java loads a shadow-patched verifier and changed
string/ZIP markers, fresh ApkAssets sees the patched resource, and lazy parent/child features,
density assets and native code load normally. The checks repeat after delayed native loading.
Explicit reads of the retained original still show original resource/ZIP values. A control build
shows the original values and false verifier result. The first toy verifier lacked the existing
matcher's required TLS/pin signals; the fixture now includes a pinned-host/certificate check.
The conservative matcher was not broadened.

T-B03 passed385 comparisons. The original ARM32-only fixture actually runs32-bit, and hook injection
preserves its sole armeabi-v7a ABI and32-bit runtime. ARM64 selected-set tests retain and read all5
original base/ABI/density/feature APKs independently. Hook libraries go in the existing ABI split.
Both profiles use extractNativeLibs=false and verified STORED/16KB-aligned APK entries. Original
ABI selection and existing split payload bytes/compression are preserved. Runtime evidence is on
the4KB phone;64-bit ELF segment checks do not establish a16KB-device claim. Upstream ARM32 backend
segments are4KB and carry no16KB runtime claim.

The earlier private-library negative used a missing /system/lib64/libart.so path, so it could not
establish namespace enforcement. The corrected probe resolves the actual VM implementation from
JNI's GetEnv address: /apex/com.android.art/lib64/libart.so exists, and dlopen explicitly reports
that it is inaccessible to classloader-namespace. Actual path/existence/error are now retained.

These are scoped experiments; the persistent production loader/public --integrity interface is
still being implemented. Native source files are included in the source fingerprint. Midway has
not been changed or launched. M5–M8 and the authorized final target test remain outstanding.

## M4 public module accepted

M4 accepted at .work/evidence/runs/20261106T064449-ef55189609/report.json. Its7 bound packets are
T-B00/01/02/03/04 plus current T-A03 and T-P12 default regressions. They passed64/193/130/385/22
native checks and10/10 default identity/combined HTTPS comparisons. All43 non-SDK host tests and
4 SDK bootstrap checks passed. The default path remains unchanged unless the explicit native
module is requested; no native backend is injected by ordinary Java/trust patches.

The public flag is --integrity native-base-bytes:libCaller.so[,libOther.so]. It preserves existing
ABI selection and refuses unknown/platform callers, unsupported cells, missing opening imports
and backend/helper name collisions. A marked, bounded private store verifies and publishes the
exact input base before the original factory is constructed, using ApplicationInfo paths without
requiring an Application context. Tested import thunks are shared by the experiments and persistent
module. The module uses source-data hash invalidation, a free-space guard, atomic publication and
cleanup limited to its own prior hash-named originals. Registered future-load tasks remain distinct
from actual observed calls.

T-B04 used the real public patch/verify path on ARM32 and ARM64. Off controls read real installed
bytes; enabled imported opens and delayed native constructors read the exact original. Setup
precedes the original factory in the same PID. ARM64 A/Java/fresh-resource/split composition and
all input ABI choices passed. B remains partial: base-only public mapping, explicit selected
callers, normal processes and the measured cells. Its raw/descriptor/path/mixed-purpose limitations
remain in the artifact and gate report. Midway remains original and unlaunched.

M5 preparation pinned Google's bundletool1.18.3 (upstream release SHA-256 verified). A read-only
get-device-spec probe succeeded through a temporary host-loopback relay to the configured external
ADB server: ddmlib itself hardcodes loopback, so ADB_SERVER_SOCKET alone is insufficient. Only the
child tool's environment/owned listener changed; the configured server/device were not restarted.
The genuine phone spec is retained under .work/evidence/M5-device-probe.


## M5 accepted — targeted container inputs

M5 accepted with 17 observed comparisons in T-I50. Immutable gate: `/home/water/workspace/Projects/repacking-lovers/.work/evidence/runs/20261106T065931-19a4f7f7ce/report.json`.
The generated bundletool fixture contains alternative ARM64/x86_64 and density configurations;
only the compatible install-time subset was selected. A separate offline API35/x86_64 spec
selected that ABI and governed signer verification without a runtime claim. Version-2 XAPK
retained the exact five explicitly selected APKs and passed lazy feature/native loading. Both
public patched formats installed and returned original identity on the API30 phone.

Wrong package/version/split ids, missing/unlisted members, traversal, missing toc and expansion
requirements were refused; the installed fixture paths stayed unchanged through negative tests.
Signed artifact metadata binds original archive hash, device spec and selected entry hashes.
Full archive inventory is stored separately. Eight host container controls cover path/symlink,
duplicate ZIP/JSON, target ambiguity and input/spec mutation. Fifty prior-plus-new host checks
passed before the final extra duplicate-JSON control; SDK bootstrap regression also passed all four checks.

Only owned fixtures were replaced. Midway remains installed unchanged and unlaunched.


## M6 known Flutter experiment

Official Flutter3.10.6 SDK archive SHA-256 matched its release index. Its ARM64 engine matches
8e6c4471…; the released reFlutter replacement is pinned separately (e5729e10…). T-U60 observed
original certificate rejection, a marked decrypted HTTPS response from the replaced engine,
proxy-down failure without an origin request, preserved unrelated Dart computation and unchanged
operator global proxy. This is third-party reFlutter mode, with a fixed raw-TLS loopback listener
on8083; it is separate from Java's explicit HTTP proxy listener. It does not match Midway's engine.

The first fixture run incorrectly used a CA as server certificate and failed on key usage; it was
corrected to the existing proper server leaf. Both failed raw reports remain retained. VM and
isolate snapshot headers each legitimately carry the same hash; validation now uses their ELF
dynamic symbols and pinned Dart full-AOT header layout, not substring counting. Six host tests
cover forged/appended hashes, wrong snapshot kind/magic/ABI and return-convention mistakes.

T-U61 and public CLI opt-in T-U62 are being checked before accepting M6. Managed DLL rewriting,
other native engines/ABIs/APIs and16KB runtime remain unsupported. The implementation contains
no guessed Midway offset or unconditional generic SSL return patch.


## M6 accepted

Immutable gate: `/home/water/workspace/Projects/repacking-lovers/.work/evidence/runs/20261106T072646-07df835b62/report.json`. T-U60/T-U61/T-U62 passed5/6/7 comparisons on one frozen source revision. Public default-off output preserved the original engine and rejected the controlled leaf; explicit mode returned a marked decrypted response, preserved libapp.so and refused unknown engine/mode and trust-only conflicts before publishing/installing. Fifty-seven host controls passed.

Public composition exposed a valid APK with an empty, zero-package resource table. The pinned Apktool recorded packageId0/empty name and could not add its first CA resources. The guarded normalization now applies only to absent/validated zero-package tables and assigns the actual manifest package/id127; original ID preservation still runs. The SDK fixture runtime exercises this path. An owned proxy bind probe also now uses SO_REUSEADDR so its own prior TIME_WAIT connections do not mimic a foreign listener. Failed and source-stale development runs remain retained.


## M7 initial Gadget spike

The pinned Frida17.26.0 ARM64 Gadget library loaded in the owned fixture, but registering a
module observer and subsequently loading the fixture library aborted in the Android linker
(`ElfReader::Load`, did_read_ check). No marked request was observed. Raw process/crash evidence:
`.work/evidence/runs/20261106T072744-93b3849218`. This is a failed experiment, not M7 acceptance.
A bounded follow-up preloads the named fixture library and attaches directly to its known export,
without a module observer. Gadget remains outside the public patch path until the experiment works.


## M7 accepted

Immutable gate: `/home/water/workspace/Projects/repacking-lovers/.work/evidence/runs/20261106T162605-c8bb4af099/report.json`. All12 T-G70 controls passed: raw syscall/export calibration, static-import refusal, explicit/default packaging, native return0→1 with same-PID hook events and marked decrypted TLS response, detection refusal, independent proxy-down failure, and preserved operator proxy. Four host dependency/scope controls passed.

The working loader preloads the exact pinned fixture library and attaches directly to its export; it does not use a module observer. The private read-only Gadget/script/config assets are checked by SHA-256 and loaded before the original factory. Script mode has no instrumentation listener. The first no-observer prototype delivered a marked response but its am-start-W client timed out; it is retained as a partial spike, not acceptance. The accepted runner uses an asynchronous activity trigger and joins actual PID/token/hook/HTTP observations. A visible owned fixture view was also added.

Only the named API30 ARM64/4KB fixture is supported. There is no generic gadget/RASP or Midway bypass claim. The original failed module-observer crash remains retained.


## M8 accepted

Immutable gate: `/home/water/workspace/Projects/repacking-lovers/.work/evidence/runs/20261106T164112-defd91ee34/report.json`. T-V80 passed21 comparisons. Two fresh actual NetworkReceiver actions were captured independently as CONNECT plus decrypted HTTPS metadata, paired with same-PID/token app responses, and assessed through the public CLI. Equivalent captures produced identical semantic results. The read-only path hashes/rechecks installed APK bytes and performs no install; a different installed APK blocks assessment without changing it.

Missing/unrelated/CONNECT-only/cleartext/stale traffic, wrong PID, forged comparison fields, app failure, conflicting events and manual attribution controls did not pass. Tampered/escaping references, a wrong artifact fingerprint and a forged artifact runtime status were refused. Private human reviews omit raw response payloads. Eight host runtime controls also passed. Manual real-app captures remain inconclusive; the tool does not invent automatic app/action attribution from proxy traffic.

The full73-test host suite and default T-P12 HTTPS/identity regression passed on the current implementation before the final Midway build. No Midway launch, replacement or backend request has occurred.


## Final regression and target preparation

The complete host suite passed73 tests, including SDK bootstrap checks. Current-source T-P12
passed10 comparisons after waking the phone. The preceding launch-wait failure happened while
Android reported Dozing/screen-off; no launch assertion was weakened. A secure-keyguard prompt
was raised while investigating, but waking the screen was sufficient for the accepted rerun and
no PIN interaction was used. Midway remains the original3-member installed set, user0/UID10243,
non-system and the sole package on that UID. The final build now takes a fresh read-only pkg pull
and uses the local capture proxy's public CA, chaining future target traffic through the existing
operator proxy for audit. The operator's global proxy remains unchanged.

All captured phase gates are accepted only for their recorded scope/cells. M6's exact official
Flutter engine mode and M7's owned raw-syscall Gadget mode do not match the actual Midway target;
they are not selected for its final artifact. Final runtime outcome remains not-run until the
operator approves replacement/data loss and the outstanding identifying-header decision.


## Real-app preflight UID format fix

Read-only Midway preflight confirmed the original installed/member hashes and the need for explicit
replacement authorization. It also revealed that this phone prints `package:br.com.midway uid:10243`
for `pm list packages --uid10243` even without -U. The non-fixture replacement branch previously
compared that entire suffix-bearing text as a package name and would incorrectly reject the sole
package as shared/unknown UID. The parser now accepts both observed and legacy formats while
retaining multiple siblings and rejecting conflicting UIDs/unknown suffixes. Four focused tests pass.
The final artifact is being rebuilt as v4 after full host and runtime/default regressions on this fix.
The v3 candidate remains a retained host build, not the artifact selected for installation.


## Final v4 ready for operator decision

The post-fix full host suite passed77 tests. Current-source T-V80/M8 and T-P12 passed again. The final v4 build and read-only preflight passed with the original3 installed members unchanged, all8 original DEX payloads and78 native libraries byte-preserved, and all 6456 original resource IDs retained. Review: `.work/targets/midway/READY.md`; immutable preflight: `/home/water/workspace/Projects/repacking-lovers/.work/evidence/runs/20261106T170012-76b60daed8/report.json`. The phase/evidence ledger is `.work/targets/midway/readiness.json`.

A combined explicit decision is pending: replace/test with the identifying header, replace/test with an explicit header waiver, or preserve the installed original. Replacing it requires uninstall/data deletion under PLAN R-INSTALL; pentest-core requires the header choice or waiver before target traffic. No target installation, launch or backend request has occurred. Original APKs are retained, not private app data. No owned proxy process or reverse listener is retained between runs.


## Actual Midway test completed — 2026-11-07 operator date

The operator explicitly approved deleting the current local Midway app data, then explicitly chose
unchanged request headers. The reviewed v4 set was installed with the public verify/install path.
The original app data was deleted as approved; original APKs remain retained. The current patched
copy remains installed and was force-stopped after testing.

Two launches were captured in immutable runs20261106T172705-9f4998a0b6 and
20261106T173413-ee23f25d61. PIDs19104 and19105 remained stable at every sample. The second
cold start reused and rechecked the installed APK bytes and stayed foreground for all6 samples
through110seconds. No target fatal exception, native fatal signal or ANR marker was observed.
The original manual-repack startup crash was not reproduced by this build on this phone.

The two proxy captures contain59 completed decrypted HTTPS responses in total, including6
responses from api.bancomidway.com.br. Each includes POST /channel-app-v1/graphql with HTTP200
and two SDK logging HTTP201 responses. This establishes observed primary-API interception;
it does not establish every client path or successful login. Other third-party proxy error events
were recorded (8/7), and their causes were not established by this scoped test. Unrelated-process
logs were not treated as Midway crash evidence.

The UI consistently displays Atualizar Aplicativo and says the installed version is outdated.
Tapping X intentionally exits the activity: the original JavaScript directly calls
BackHandler.exitApp(). No update-store action, credentials, login, payment or account-changing
operation was performed. The mandatory-update UI limited further normal-flow validation.

Public read-only assessments rechecked installed artifact bytes for both capture packets. The
manual adapter correctly remains inconclusive about automatic app-response attribution; the
explicit human-observed startup/UI/primary-API checks above remain separate. Full functionality,
attestation acceptance, all third-party endpoints and native-only flows are unclaimed. No native
integrity, reFlutter or Gadget module was selected for this target.

Both runs stopped their own proxy processes and removed their own reverse listener, with the
operator's global proxy preserved. The signed artifact manifest remains runtime-not-run by design;
measured results are separate in .work/targets/midway/runtime-summary.json and runtime-review.md.
Reproduction instructions are .work/targets/midway/setup/SETUP.md. The support matrix records a
separate target trial without broadening all release capability claims.

### Fresh Play install / external pinning module disabled (2026-11-07, active)

The operator reinstalled Midway from Play and disabled the previously created pinning module.
Fresh input is 1.85.0 (399590), four selected APKs including pt, on the same API30 phone after
a recent reboot. The earlier 1.53.0 results above have an uncontrolled external-module variable;
they establish observation, not attribution solely to this tool. Root-only module state cannot
be independently inspected by ordinary ADB; no root command is used. A target-local TLS control
will retain original trust/pinning while adding the same identity/bootstrap/route as the full patch.

Fresh P0 exposed a Play source-stamp parsing error. Signer metadata now excludes the distribution
stamp certificate, and repacking drops its stale stamp-cert-sha256 entry (as apksigner itself does).
Three host regression controls pass. The resource guard also caught Apktool renaming obfuscated
numeric names; a pinned ARSCLib helper restores only the exact APKTOOL_RENAMED_<original-ID>
synthetic names, then repeats the independent SDK dump comparison. All 6,779 original bindings
were preserved in a measured cached rebuild; arbitrary changed/missing bindings still fail.
Fresh originals and new results are isolated under .work/targets/midway/play-1.85.0-module-off/.
The operator's prior replacement/data-loss approval and unchanged-header waiver still apply.

The module-off retrial is complete: both route/identity-only control and full trust/Java/A patch
crash in MainApplication.attachBaseContext with ArithmeticException before the main UI. Their
only proxy observations are Guardsquare CONNECT attempts; zero decrypted HTTPS responses.
The exact four Play originals were restored, then checked on first launch and a second cold
start without clearing data. They also crash: CustomFcm NullPointerException on first launch
and obfuscated background Thread-5 ArithmeticException on both. The second launch verifies all
four installed APK hashes against the originals. Thus no healthy baseline exists; tool-only
interception success and a specific RASP diagnosis remain unproven. This trial does not accept
Midway 1.85.0 support. Twenty-six focused host controls pass after the host fixes. No broader
full-suite pass is claimed for this revision (the pre-fix broad run was stopped).

The original is left installed and force-stopped; headers/global proxy are unchanged, and owned
proxy/reverse resources are cleaned up. The latest review is
.work/targets/midway/play-1.85.0-module-off/runtime-review.md; raw reports are linked in its JSON
companion. Previous 1.53.0 results are preserved under history/1.53.0-module-state-uncontrolled
and the support matrix explicitly qualifies their attribution. A stable original under a known
module/device configuration is the next diagnostic prerequisite.

### User-directed isolation: plain repack before pinning (2026-11-07)

The user explicitly requested three parts: clarify implementation completeness, make a plain
repacked Midway open, and only then work on removing pinning. Main gates are implemented and
fixture-scoped; optional M2-CT/M2-DEX, DEX-only mode, wider cells and deferred features are not
complete. The implementation index now states that distinction. Earlier route/identity controls
were not plain repacks, so their crashes do not isolate a build/sign round trip.

Current bounded experiments: (1) observe the byte-verified installed original; (2) ZIP/re-sign
all four original APKs while preserving non-signature payloads and compression; (3) raw-DEX
resource decode/build of the base, preserve original IDs/names, and re-sign the complete set.
Neither repack control injects DEX, hooks, CA, NSC changes, proxy settings or pinning transforms.
The existing original currently displays a maintenance/error screen; cold-start behavior is
being measured again rather than assuming the prior crash reproduces. Scripts live under
.work/targets/midway/setup/build_plain.py and run_plain.py. Plain-trial reports are separate
under .work/targets/midway/plain-repack/. Pinning work is gated on a working repack.

Plain isolation results: original ADB-restored Play-signed bytes crashed in background Thread-5;
ZIP/re-sign-only and raw-DEX resource round-trip controls both crashed in MainApplication.onCreate
with ArithmeticException. Resign-only preserved every non-signature entry's payload/storage;
round-trip preserved all six DEX and 6,779 original resource ID/name bindings (74 added compiler
placeholder IDs). Neither injects any runtime code, CA, NSC/pinning change or proxy configuration.
Thus resource rewriting is not necessary for the observed startup failure. No specific integrity
check has yet been established and a working repack has not been achieved.

Important baseline correction: earlier restored originals used genuine Play-signed APK bytes
installed via ADB, not a new Play-delivered installation. Play installation provenance was not
controlled. A true Play reinstall was initiated through the inspected store Install button after
removing the plain control under existing approval. The download is stalled at 0%; read-only
phone TCP connection to existing global proxy 192.168.3.18:8080 times out. Workspace access to the
operator proxy succeeds. No global settings changed. An operator question about restoring proxy
reachability is pending; at this point the target is uninstalled with Play restoration pending,
not falsely described as restored. This is a network prerequisite, separate from the recorded
plain-repack startup failures. Pinning work stays deferred. Current handoff:
.work/targets/midway/plain-repack/README.md, comparison.json and play-restoration.json.

### Plain repack startup resolved on the measured Midway cell

The user narrowed the task to startup isolation only. Optional plan features, proxy and pinning
work were excluded. A fresh Play installation completed and matched the four archived1.85.0
original hashes; its background crash reproduced, ruling out ADB provenance as the sole cause.

The investigation established two intentional reactions. MainApplication.onCreate compares
signer-check states and reaches a mathematically guaranteed zero divisor on mismatch. Its encoded
expected fingerprint is exactly the original signer. H2's branch-only intervention removed the
first failure but poisoned later seed arithmetic. H3 changed only the expected-signer payload to
the persistent operator key, preserving all instructions, and removed both onCreate failures.

Offline decryption of original a-/b- containers (ZIP CRC and DEX SHA1/Adler32 verified) recovered
the exact background classes. StartupActivity3 caches its result in DocumentXActivity.cancelAll;
the callback deliberately divides by zero, and CustomFcm deliberately throws null on the same
cached mismatch. A read-only native observer captured0→29 in two processes. Testing actual
package/class/activity metadata through the original native matcher identified package name
me.bmax.apatch, folded hash b7fd4ae7, blacklist entry29. Application class APApplication was a
rejected hypothesis. No other apps/root modules were changed.

H6 removed broad permission and launcher visibility requests and opened. H8 added a specific
APatch query and still opened. H9 retained every original queries entry and removed only
QUERY_ALL_PACKAGES; it also opened. An independent SDK manifest diff confirms that exact single
permission deletion. The final recipe uses the simpler permission-only configuration.

H10 performs a fresh raw-DEX resource decode/build from immutable originals, applies only the
encoded expected-signer update and single permission deletion, then aligns/verifies all four
members. It preserves6DEX members (only128 configuration bytes plus standard checksum/signature
headers change),50 original native payloads and6,779 original resource bindings, with74 compiler
placeholder IDs added. No diagnostic helper/identity proxy/CA/route is packaged. Independent
binary XML comparison verifies the original NSC pin policy is unchanged.

Fresh-data run20261107T025001-03bf60c54b (PID7834) and retained-data cold run
20261107T025159-a092eed3ae (PID7836) each remain foreground/stable for 60 seconds, with no target
fatal markers. The cold run checks actual installed APK hashes before launch. This establishes
startup opening only: the app displays its maintenance/error screen; login/service functionality
is unverified. The generic real-app response adapter remains inconclusive, separately from the
explicit startup observation. No pinning or backend success claim is made.

Current handoff: [target recipe and result](../targets/midway-startup.md), private
.work/targets/midway/plain-repack/RESULTS.md and investigation/final-summary.json. The four final
H10 APKs remain installed and force-stopped; no diagnostic helper, proxy/reverse or temporary
shell inventory helper remains. Existing device settings and other apps/root modules are
preserved. At that handoff, public generic CLI integration was not yet claimed.

### Standalone startup repair search (2026-11-07)

Implemented `python -m repack startup`, separately from proxy/pinning transforms.
`repack/startup_analysis.py` and the typed `tools/StartupDex.java` inspector discover
64-character affine-XOR signer payloads using verified input-certificate digests,
local decoder use and all 64 matching characters. They derive locations and both
encoding constants from each input; production code contains no Midway names,
offsets or native blacklist values. Rewriting is bound to original DEX hashes and
preserves all instructions and bytes outside payload/checksum regions.

`repack/startup.py` implements a bounded, deduplicated subset search: baseline,
recognized signer-payload repairs and, when declared, QUERY_ALL_PACKAGES removal.
Each trial starts from one immutable resource-rebuild baseline, uses the persistent
key for the complete set, runs install preflight and explicitly authorized target
data clearing, captures own-package Java/native/ANR evidence and samples PID/focus.
Infrastructure failures interrupt separately. A candidate must pass a second
cold launch with the same APK hashes. No AI service or per-target profile is used.

The first real run was interrupted after exposing that `dumpsys window windows`
omits mCurrentFocus on this phone. The corrected oracle uses the full dump and
reports a missing field as inconclusive, with a regression control. The complete
91-test host suite passes, including real renamed/relocated DEX fixtures with
changed parameters, unrelated-hash controls, search budgets and failed confirmation.

Accepted narrow runtime observation: run20261107T032955-0db34c7c2c, outputs in
`.work/outputs/startup-generic-midway-02`. The CLI independently selected baseline
(application-init crash), signer-only (background crash), then both repairs.
Trial 3's fresh-data PID 14776 and retained-data confirmation PID 14777 each remained
foreground/stable for 60 seconds with installed hashes verified and no target fatal.
The final four APKs are installed and force-stopped. The original maintenance/error
screen remains; login/service behavior is not verified.

Independent preservation confirms 6 DEX members match measured H10, only the derived
128-byte region and DEX headers differ from original DEX, all 50 native libraries
and 269 opaque entries retain bytes/storage, and the manifest/NSC match H10 exactly.
No proxy, CA, pinning, identity-proxy, diagnostic-helper or other-app changes were
introduced. Arbitrary encrypted-container/blacklist attribution remains manual;
the automated visibility experiment does not claim to reconstruct that checker.
See [standalone command and limits](../startup-search.md).

### Midway1.85 APK pinning/interception acceptance (2026-11-07)

Used the accepted standalone startup winner as an immutable input to the existing
public patch CLI. No new production patch algorithm was needed. The generic
matchers accepted OkHttp CertificatePinner.check$okhttp and the obfuscated TrustKit
o.isRtl.checkServerTrusted. The build adds embedded CA trust and app-local routing;
identity proxy, native hooks and Gadget are disabled. All six startup DEX payloads
remain byte-identical in shifted slots, with one shadow DEX and one bootstrap DEX
added. All50 native libraries and original opaque entries are unchanged; original
resource bindings and QUERY_ALL_PACKAGES removal are retained.

Controlled phone observations distinguish route/trust from the larger Java patch:

- Routing-only control20261107T041627-cbee254fe5 remains stable60seconds but rejects
  the proxy certificate for the primary API and decrypts no HTTPS response.
- CA/trust-policy plus routing control20261107T041302-6bf35e4a66, with original Java
  pinning, stays stable90seconds, decrypts GraphQL HTTP200 and SDK log HTTP201, and
  reaches the normal welcome screen. Java replacements are therefore not shown
  necessary for this first-screen request path.
- Full APK run20261107T041836-0215497af8, fresh-data PID20222, stays foreground and
  stable90seconds with both primary responses and own-process markers from both
  patched methods.
- Same-artifact cold run20261107T044311-6834b37c91, PID20224, repeats90seconds and
  both primary responses with both patch markers. Installed hashes are checked
  around the observations; no target Java/native fatal or ANR is recorded.

Current public artifact: `.work/outputs/midway-pinning-startup-v1/manifest.json`.
Comparison/bindings: `.work/targets/midway/pinning-20261107/summary.json`.
Private preparation/capture/keep-alive commands are saved under target setup.
The operator proxy command passed a15-second smoke session. Patched APKs remain
installed and stopped; owned proxy/reverse resources are cleaned. Headers, the
operator global proxy, root modules and other apps are unchanged.

Scope remains first-screen Java/API interception. Login, Flutter/native TLS and
later identity-SDK flows are not verified; operator-disabled external pinning
module state was not independently read. [Artifact, controls and reproduction](../targets/midway-pinning.md).

### Pinning-haters source assessment (2026-11-07)

Reviewed the local pinning-haters active Java/native target tables, replacement
contracts, tests and implementation notes without modifying that repository or
the phone. Extracted22 Java target contracts into an advisory catalog with source
commit/hashes and checked their named definitions against retained Midway1.85 DEX.
This is an assessment; production pinning coverage and installed artifacts are
unchanged.

Recommended first batch: older OkHttp overload recognition and Java-backed Flutter
pin plugins. Next: CT selector/interceptor contracts and app-owned Conscrypt
callbacks. CT needs explicit false-return selection, and interceptor/Chromium
targets need object-return/delegation templates; adding matcher rows alone would
be incorrect. Standard hostname relaxation stays separate; external WebView/boot
providers and native table swaps do not transfer directly into an app APK.

Midway's retained OkHttp List/varargs references delegate to its already patched
lazy checker. No additional named Java family from this catalog was found; that
does not rule out obfuscated, encrypted, external or later-loaded implementations.
Native Flutter remains unverified. See [source assessment and fixture tasks](../research/pinning-haters-apk-adaptation.md)
and [22-target advisory catalog](../research/pinning-haters-targets.json).

### Java APK pinning extensions implemented (2026-11-08)

Implemented the scoped Java batch in `repack/pin_families.py`, `repack/patches.py`
and `tools/DexPatch.java`; the public CLI flags are unchanged. Candidates now carry
explicit replacement contracts into selection and signed transform metadata.
New recognition covers older OkHttp enforcing overloads, the two named Flutter
Android fingerprint helpers, appmattus/babylon CT selectors and their interceptor
fallback, and app-owned Conscrypt callbacks. CT returns false; the interceptor
returns the actual request/proceed response. A selected CT base suppresses the
related fallback. Constructors/static/native/abstract/duplicate/insufficient-evidence
cases remain refused. Pin-word matching no longer mistakes "Skipping" for pinning.

Conscrypt is more precise than the reviewed return-void shortcut: the writer
neutralizes exactly one audited server-trust invocation and preserves parsing,
peer-chain/session updates, client-trust calls and code-unit/handler positions.
This avoids losing peer certificates needed after a successful handshake.
External providers, standard hostname relaxation, Chromium result templates and
generic native/Dart TLS are not added by this batch.

All103 host tests pass with REPACK_TEST_SDK=1. The new integration case uses
published OkHttp3.14.9, appmattus2.8.4, both published Kotlin plugin sources
(http_certificate_pinning3.0.2 and ssl_pinning_plugin2.0.0), and Conscrypt2.5.2
common Java/OpenJDK provider code. It builds/signs actual DEX-containing fixtures,
uses the production APK patcher, preserves original DEX, translates for strict JVM
verification and executes baseline/patched behaviors. The CT wrapper still rejects
a wrong hostname; plugin callbacks complete exactly once; interceptor request,
response and exception identity are retained; Conscrypt completes a real local TLS
handshake with peer-chain data intact. Four malformed selection/type/duplicate
controls are refused. Android/Flutter adapters are fixture stubs and these are
host semantics, not ART or Android-JNI acceptance.

Immutable host report: `.work/evidence/runs/20261107T153910-36f5f1b3a2/report.json`.
Regression log: `.work/pinning-extensions-regression.stderr.log`.
Handoff: `.work/evidence/PINNING-EXTENSIONS-handoff.json`.
The optional test-only dependencies are separately hash-pinned; the production
patch path retains the existing SDK/JDK dependencies.

Public CLI host regression built
`.work/outputs/midway-pinning-extensions-host-v1/manifest.json` with the same two
Midway targets. The shadow and six preserved original DEX, manifest and NSC are
byte-identical to the previous device-tested build, and all50 native libraries are
unchanged; bootstrap build-token/metadata differ. This is recorded in
`.work/evidence/PINNING-EXTENSIONS-midway-host.json`. At the initial host handoff no device was connected; the subsequent device
acceptance below supersedes that pending runtime status.

### Java extension device acceptance (2026-11-08)

The configured Redmi K20 reconnected. All twelve original/patched observations
passed in an owned ordinary target35 app on ART (UID10598): OkHttp3, appmattus CT
policy plus hostname delegate, the owned interceptor fallback, both published
plugin sources and actual Android Conscrypt2.5.2 engine/file-descriptor backends.
CT still rejects a wrong hostname; delegation preserves headers, objects and
exceptions; plugin callbacks complete once. Conscrypt's unpatched controls reject
TLS and its patched variants complete TLS1.2, retain peer certificates and read
a payload. Flutter channel adapters are fixtures; no Dart-engine claim is made.
Client authentication and external/system providers remain outside acceptance.

Project runner: `scripts/pinning_extension_android.py`; source fixtures:
`tests/fixtures/pinning_extensions/android/`. The Android AAR is hash-pinned in the
test dependency manifest. The runner applies the production patcher, records
artifact hashes and app result tokens, and owns/cleans only its temporary fixture,
TLS server and reverse. It does not require an AI, root or device-wide settings.
Report: `.work/evidence/runs/20261107T162221-0fb201f871/report.json`.

New Midway artifact `midway-pinning-extensions-host-v1/manifest.json` is now
installed and verified: fresh90s run 20261107T160300-9bba60500c (PID28123) and
cold90s run 20261107T160808-2d84d76012 (PID24085), stable foreground/welcome,
GraphQL200 and SDK log201 in both, both patched-method markers in the app PID.
Headers, global proxy and root/module state were not changed by the runner.
Midway exercises the existing two methods, so its regression is separate from
new-family fixture coverage. The owned fixtures/proxies/reverses are removed;
Midway remains installed and stopped. Its local proxy session command now defaults
to this newly verified artifact. [Commands and limits](../pinning-patches.md).

Current gate: Java pinning extension device acceptance.
State: accepted for these API30/ARM64 fixtures and Midway's observed first screen.

Final verification: all103 host tests passed again (60.610s), and the final
repeat of all12 Android observations passed from the current fixture-runner
sources. The runner retains a hash-bound copy of its host input report. The
updated default operator proxy command passed a15s smoke session. Final installed
Midway hashes, absent fixture/listeners/reverses, stopped target and preserved
global proxy are bound in
`.work/evidence/runs/20261107T162456-ddbf808100/report.json` and indexed by
`.work/evidence/PINNING-EXTENSIONS-handoff.json`.

### Additional pinning-haters APK adaptations (2026-11-07, Recife)

Implemented owned Chromium verifier delegation with the selected CA, Cronet's
configured-pin getter, optional standard hostname bodies and Apache owned-call
rewrites, offline ARM64 TLS export/table discovery with original-call wrappers,
and snapshot-matched typed Dart predicates. The public flags are
`--relax-hostname`, `--native-tls offline-arm64` and `--dart-pinning`.
Dart analyzer preparation is scripted and pinned; normal APK patching performs
no analyzer downloads/builds. Runtime-lead diagnostics explicitly separate Go,
rustls, Mono and IL2CPP presence from patchability.

Direct Android checks passed14 expansion observations and6 Flutter/Dart controls.
The Cronet CA-only control reached ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN; the full
patch returned HTTP200; wrong-host verification still failed. Native OpenSSL3.0.16
and3.4.1 completed TLS with peer certificates/payload intact; ordinary callbacks
ran once. Flutter's rejecting callback also ran once while the patched native
verifier allowed HTTP. Native TLS alone still failed the post-handshake Dart pin;
the typed AOT edit passed with an unrelated boolean remaining false.

The public CLI built and verified three artifacts, proved that default native/AOT
bytes stay unchanged, and passed6 runtime composition observations. The complete
host suite passed126 tests after the final production changes. Nine native corpus
images passed host discovery/ELF rewriting; these are separate from Android proof.
Reports and commands are in [the adaptation guide](../pinning-expansion.md).

Midway was not reinstalled, cleared or launched. Final hashes match the previous
verified installed artifact. Its retained libflutter image has no matching static
locator inputs, so no new Midway native claim is made. Owned fixtures/listener/
reverse are removed; global proxy and root/module configuration were not changed
by the runners. Login remains deferred. Handoff:
`.work/evidence/runs/20261107T235202-58cbc5117a/report.json`.
