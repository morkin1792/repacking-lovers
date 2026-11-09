# Architecture reference

Read only the subsection required by the active [work guide](implementation/README.md).
[PLAN §1](../PLAN.md#1-shared-execution-rules) owns policy; this file records mechanisms and why
the acceptance cases exist. It is not permission to implement later modules.

For the later user-authorized Chromium/Cronet, hostname, offline native and Dart
work, see [additional APK adaptations](pinning-expansion.md). Its verified
contracts supersede the original narrow M6 profile boundary for those explicit
new modes; the original profile remains available.

## A: package-manager boundary

For the pinned API-35 source, ordinary getPackageInfo uses PackageManager.sPackageInfoCache;
its recompute calls ActivityThread.getPackageManager(), hence sPackageManager. ContextImpl creates
ApplicationPackageManager lazily from that interface. M1a therefore publishes sPackageManager
first. Inspect known ContextImpl.mPackageManager references without calling getPackageManager to
create one; the controlled factory fixture expects zero observed existing managers. This is not
a count of every object in the heap or a universal startup assertion.

The API-35 hasSigningCertificate/checkSignatures paths still use ApplicationPackageManager.mPM.
That field is private final; M1b-1 must cover existing/new instances for those methods. Record
descriptor, modifiers, access/write result and subsequent behavior, not just Field.set success.
Inspect applicable PropertyInvalidatedCache users on each pinned release; do not extrapolate
the API-35 swap order to every Android version.

Use a Java `InvocationHandler` around the real `IPackageManager`. Dispatch by declaring interface,
name, parameter types and argument values. Support cells explicitly cover flags/overloads,
package/user/UID scope, return types and exceptions. Forward unrelated calls with original
semantics and avoid mutating a result shared by the real cache. UID/shared-UID and cross-package
comparisons require both signing identities, not an unconditional true.
List-returning queries are separate paths: getInstalledPackages and getPackagesHoldingPermissions
can expose the self PackageInfo alongside unrelated packages. On the API35 Binder boundary they
return ParceledListSlice, not a plain List. M1b-1 inventories the actual descriptor/container,
copies only self entries with the same signing recipe and preserves ordering, visibility, flags,
unrelated entries and null/exception semantics. A scalar getPackageInfo result does not cover them.

| Caller | Path condition |
|---|---|
| Direct Java / reflective query | Traverses a replaced manager and no earlier result cache |
| JNI calling Java PackageManager | Same Java path, separately tested |
| Fresh Java Stub from ServiceManager | Additional raw-Binder cache wrapper required |
| Hand-built transaction / native libbinder | Outside the Java interface-proxy design |
| Archive parser | Client-side file parse; does not traverse A |

**Rationale — raw Binder:** replacing `mPM`/`sPackageManager` does not replace
`ServiceManager.sCache["package"]`. A Java wrapper there can return the interface from
`queryLocalInterface()` for the exact descriptor. `asBinder()`, forwarding, death handling and
fresh acquisition have separate contracts. Previously retained handles and native transactions
remain different paths. Proxy-class introspection can detect this design.

**Rationale — caches:** replacing an interface cannot retroactively repair values already
returned or cached elsewhere. A type-based reflective sweep may miss hidden members and cannot
prove completeness. Use the pinned source inventory plus existing/new-context and stale-result
fixtures. T-A03 requires the first controlled self query after publication to enter the handler;
it does not deliberately prewarm the cache. M1b-1 owns deliberate prewarming and optional
one-shot process-local sPackageInfoCache.clear at publication; it does
not repair already returned objects. Disabling/flushing all platform caches remains outside scope.
Do not call the public self getPackageInfo path from the shim before publication: it may populate
the cache with the real signer for that package/flags/user key. Prewarmed entries remain a separate
M1b-1 case even when the shim itself avoids warming them. Widened long flags must not be
truncated; an unchanged method name selects a handler but does not validate its argument contract.

## Bootstrap and DEX packaging

Build our Java shim against the public android.jar only. ActivityThread, IPackageManager and
ApplicationConfig are absent from that SDK surface. Resolve hidden classes using Class.forName
and use Class<?>/Object plus reflection/dynamic proxies; do not import hidden types, add framework
JARs as implementation dependencies or ship classes in platform namespaces. Centralize class names,
member names and full descriptors in `shim/src/dev/repack/shim/Hidden.java`, adding only the active
task's entries. PlatformAccess owns access and invocation behavior, not a second descriptor table.
The pinned bypass may use its upstream build-only stubs; exclude those stubs from the shipped
DEX and record the actual dependency closure. Centralized descriptors do not prove access.

The default bootstrap appends RepackFactory/shim DEX and changes the binary manifest factory
attribute. RepackFactory extends the public platform factory and delegates by composition to the
original instance, including its loader/result/exception behavior; final factories are supported.
Its constructor invokes initEarly before original factory construction; instantiateApplication
entry invokes initLate. No original DEX rename or duplicate class is required by this path.

For --dex-only bootstrap and M3 class patches, use the separately tested shadow strategy below.
Its assembly dependency is Google-maintained com.android.tools.smali 3.x, pinned only when that
strategy opens; the default manifest bootstrap has no smali dependency.
Compile Java shim source with javac/d8. The shadow-strategy T-A01 trial uses DEX shadowing: copy and patch the
configured factory class, assemble it separately, and package it with the compiled shim in a new
classes.dex. Rename original classes.dex to classes2.dex, classes2.dex to classes3.dex, and so on,
in a fresh archive; preserve every original DEX payload byte. Record the old/new entry mapping
and SHA-256 equality. Entries must be unique and contiguous from classes.dex; ART's APK loader
stops when an index is missing. Reject ambiguous original inventories instead of silently omitting
a DEX. Build from immutable originals so successive transforms share one shadow-class set.
The initial shadow strategy emits exactly one injected DEX; if d8 emits additional DEX files, stop with
the concrete size/limit diagnostic rather than overwrite shifted originals. Supporting a larger
contiguous injected prefix requires an explicit packaging extension and the same selection tests.

API35 ART searches a loaded APK's DEX files in order for a class definition. This supports the
trial on that loader path; it does not establish behavior for parent-provided classes, isolated
splits or custom loaders. Only shadow a complete class that this APK owns and the tested loader
actually selects. Preserve its descriptor, superclass, interfaces, fields, methods and delegation.
M3 uses the same shadow set for supported pinning classes; it does not prepend an independent
layer per patch. Preserve originals alongside the intentional duplicate definitions.

The shadow T-A01 variant must show the shadow marker, original behavior/order, payload-hash preservation, complete
startup logs without duplicate-class/verification failure, and a successful cold relaunch after
recorded compilation. The injected DEX still needs reference/verification checks; shadowing avoids
adding references to original DEX files, not all DEX limits. Renaming entries and changing the APK
does not preserve archive identity or defeat integrity checks.

If shadow lookup or tooling fails, record that failure and run one owning-DEX rewrite fallback:
append shim DEX at the next contiguous index, rebuild only the DEX containing the call, and check
method/type/string limits, code offsets and checksums. Keep fallback headroom/near-limit checks
until shadow acceptance; thereafter run them only if the fallback is shipped. Keep a near-limit
original-payload shadow regression in M3. Mode-specific evidence must name the selected strategy.

The --dex-only alternative copies the configured component-factory class present in editable app DEX, including packaged
library classes such as AndroidX CoreComponentFactory. Add a static constructor `<clinit>()V` if
none exists; otherwise preserve its body. The no-initializer path is required in the first fixture.
Then try the earliest suitable Application ancestor initializer. Preserve factory/class-loader
delegation. A manifest swap is a separately recorded build path, not a disguised DEX-only pass.
Validate injected class visibility from the selected loader, including isolated split loaders later.

Split initialization into early idempotent cache operations and context-dependent file/native
operations. Record which capabilities are ready before each check. Prevent recursion, partially
published proxies and class-initialization deadlocks; test recoverable-error rollback. Capability
completion is separate from entry logging. Initialization belongs to each supported process.

On API35's standard bind path, createAppContext/factory loading precede platform proxy setup,
which precedes Application construction. initEarly therefore owns identity publication, while
initLate at factory instantiateApplication entry owns routing. Create a delegating override if
the factory inherits the method. Preserve custom construction and record any earlier custom code.
The context phase can be posted from initLate to the main looper, but runs after synchronous
startup returns; provider/onCreate checks can precede original-byte provisioning.

T-A01 also measures an alternate early hook at factory instantiateClassLoader(ClassLoader,
ApplicationInfo) entry. This method is public from API29, not API28. It supplies sourceDir/dataDir
without a Context, but runs after factory class initialization and construction; it cannot cover
checks already run there. Preserve the existing override/returned loader or add an invokesuper
delegate if inherited. Test this variant separately from clinit publication and retain initLate
at instantiateApplication. ApplicationInfo paths are metadata, not proof that storage/provisioning
is already usable. No default hook switch or API28 coverage follows from the API35 variant.

**Rationale — timing:** custom factories, superclass initializers, native loads and cached
handles may precede a subclass constructor. Earlier injection reduces the window but cannot
prove every RASP initializer runs later. Providers and wrapped Applications are ordering fixtures.

## Hidden-member access

Inspect the exact published `hiddenapi-flags.csv` for the selected API, then probe ordinary access
in a release, non-debuggable APK at its original target SDK. Capture source revision, flags-file
hash and actual errors. `@UnsupportedAppUsage` alone is not an access result. Lowering target SDK
does not unlock universally blocked APIs and changes installation/storage/permission behavior.

Meta-reflection is not a current baseline for apps targeting API 30+. A has one supported access
mode: a pinned AndroidHiddenApiBypass implementation with its required helper classes, license
and notices. Upstream is Apache-2.0, not MIT. Vendor the dependency closure and initialize it in
initEarly before A's hidden reflection/proxy setup; record version/commit, hashes and exemption
prefix ["L"], including the full IPackageManager interface during proxy generation. Do not start a custom hidden-API framework. Bootstrap-only and interception
builds without A do not load this dependency; an optional hidden routing experiment declares its
own use of the same pinned implementation when that experiment is executed.

T-A06 records normalized full signatures and real forwarding/canary behavior. App-visible method
enumeration may be filtered, while ART treats Proxy specially for caller checks; raw CSV row count
equality is not a proxy-completeness oracle. Ordinary T-A06 is an informational diagnostic in a
fresh process without the bypass; retain its actual result. Functional A acceptance and release
regressions use the single pinned process-local mode, without a second ordinary support matrix.
Required functional failures follow PLAN §8. A failed identity observation does not invalidate
the independent bootstrap/interception path; library claims alone do not establish API28–36 support.

**Rationale:** policy-exempt/debug harness success does not establish behavior of the release
target. Device-wide exemptions are forbidden. The recorded process-local bypass configuration permitted by
R-DEVICE is distinct from ordinary-access support. A changed target SDK is a changed environment.

## Signing metadata

For owned initial fixtures, keytool exports original cert DER and apksigner verifies matching APK
certificate digests. General-input P0 extraction begins in M1b-3 and retains original bytes, all current signers and available verified
rotation history. Printed digests are comparison beacons, not certificate bytes. For archive
parsing, provide an immutable original in app-private storage, parse before enabling B and cache
by original member hash. Provisioning must exist before the query it supports.

M1a measures `getPackageArchiveInfo(originalPath, GET_SIGNING_CERTIFICATES)` and legacy flags.
Validate null/errors, flags, current signer set and history against host data. Copy only signing
fields into a fresh result; retain installed UID, source paths and unrelated fields. Do not
replace an installed PackageInfo wholesale with an archive-parsed one.
Clone PackageInfo via a temporary Parcel and CREATOR, then set only signing fields; recycle the
Parcel and verify unrelated fields/paths. Unwrap reflective forwarding exceptions to their cause.

Public no-arg/copy `SigningInfo` constructors exist from API 28; populated public construction is
API 35+. Hidden `SigningDetails` construction is a bounded fallback if a required parse case
fails, not the initial API35 implementation. Recording an API28–34 first/release cell activates
M1b-1 task 3 / T-A16: test the selected-release public CREATOR/Parcel layout first, with independent
archive/host truth, then the exact hidden constructors as the bounded fallback. This subpacket may precede M1a task 4 on a selected API28–34 first cell,
preventing a gate cycle. Multi-signer and history predicates must agree with the
recorded metadata; M1b-1 defines accepted semantics.

## Routing

The baked device endpoint defaults to 127.0.0.1:8080; the reference host proxy listens on loopback
and adb reverse supplies transport. The patch endpoint is configurable under PLAN §6 and is
stored as host/port in generated Route configuration and the artifact manifest. For an explicit
remote endpoint, the operator supplies actual reachability; do not create an adb reverse mapping
for that remote route. Endpoint validation and reachability are different checks.
The in-process selector/properties affect only clients that consult them; already constructed
clients, explicit app proxies, direct/native sockets, Cronet, Dart HTTP and UDP/QUIC need distinct
fixtures/strategies. Static Proxy-construction scans are hints, not exhaustive routing detection.
WebView routing is separate too: check WebViewFeature.PROXY_OVERRIDE before AndroidX ProxyController
use and wait for setProxyOverride's completion callback before loading the test page. NSC trust
configuration alone does not establish WebView proxy routing; record provider/version and target
SDK in that optional fixture rather than assuming Java ProxySelector applies.

API35 startup proxy setup can reset early values before Application construction; install the
initial route in initLate. Later Android proxy updates may reset the properties and selector. The saved
`android.net.Proxy.sDefaultProxySelector` is hidden and `private static final`; PAC updates can
choose another selector. M1b-5 defines a first persistence experiment and its failure branch.
An app-context PROXY_CHANGE_ACTION receiver provides supplementary reapplication with a measurable
race window; it is not a substitute for route/callback/escaping-request evidence.
Final-field mutation is not guaranteed by a successful reflection write; test actual fresh and
existing callers. Ordinary instance-final and static-final field behavior must be measured separately.

**Rationale:** loopback avoids LAN/Wi-Fi reachability problems, but losing adb only blocks the
covered route. It does not prove all app traffic fails closed. A temporary listener is not an
app isolation mechanism. Never replace unrelated reverse mappings or device proxy settings.
An endpoint on the proxy's Wi-Fi LAN generally does not become reachable on mobile data. Test
off-USB reachability separately from whether the app retains its selector/properties after a
network transition; acceptance of one does not establish the other.

For covered HTTP(S) destinations, return a singleton list containing the configured HTTP proxy;
never return an empty list, append NO_PROXY or delegate to a direct fallback after failure. Log
connectFailed when the client invokes it and retain separate request/connection failure events.
Apply the same selection to proxy-host URLs; the proxy socket is opened directly by the client
transport and does not recursively invoke URI selection. Keep direct sockets outside this claim. T-N12 tests a fresh proxy-down request against an independently
reachable controlled origin and requires client failure with zero origin requests. A captured
selector/reset, explicit app proxy, pooled connection or uncovered stack retains its own scope.

Android11+ paired wireless debugging is an optional adb transport: select its current serial and
create/verify owned reverse mappings on that connection. USB disconnection need not terminate
this transport, but mappings may need recreation; test instead of promising migration. This is
off-cable Wi-Fi coverage, not mobile-data coverage. Keep pairing/operator settings explicit and
record cleanup separately from mapping ownership.

## Trust configuration

Use Apktool resource decode/compile/link as the first engine for NSC changes. An early bounded
corpus records rebuild, insertion, install, launch and HTTPS stages separately; trust coverage
cannot exceed the tested runtime outcomes. On a concrete resource-engine failure, trial a pinned
APKEditor/ARSCLib path against the identical fixtures before selecting it as a fallback. Do not
assume a general binary read/write library already implements our resource insertion operation.
Resolve manifest references and qualified XML
variants. Add the public test CA with `overridePins="true"` to the base and every domain/nested
configuration with its own trust anchors. Preserve existing private/system anchors, effective
defaults, pins, cleartext policy and unrelated attributes. Never embed the CA private key.

For API 36+, resolve `<certificateTransparency enabled="..."/>` and inheritance. Raw/user anchors
normally disable CT unless explicit policy enables it; modify only needed test policy and verify
the added API cell. User-store trust is a future explicit alternative to embedded trust.

**Rationale:** explicit domain anchors do not inherit a replacement base set. Pin override is
specific to chains using that test anchor and does not bypass programmatic pinning. Text XML
copied into an archive with raw `resources.arsc` does not create compiled resource IDs.
New IDs require a consistent compiled resource table and binary XML/manifest references. Some
targets can reuse suitable existing entries, so a resource-table edit is not an every-target
requirement; a full text decode/build is not the only possible implementation.

**M2-DEX experiment:** after M2, test a separate runtime trust mode in initLate using the same
pinned process-local access implementation, even when A is disabled. On API35's standard bind
path, NetworkSecurityConfigProvider.install runs before instantiateApplication; factory class
initializers/constructors can nevertheless create TLS state earlier. Read the original
ApplicationConfig and preserve its default/per-domain source semantics in a wrapped ConfigSource.
Build fresh configurations adding a public CA CertificateSource/CertificatesEntryRef with
overridesPins=true to every effective anchor set while retaining pins, domain matching, cleartext,
HSTS and CT settings. A Builder does not clone an existing configuration automatically. Its
setParent takes another Builder, not NetworkSecurityConfig; the source may already have been
consumed and mConfigSource nulled. The experiment must handle or explicitly reject those states.

Construct/publish a replacement ApplicationConfig only after the complete copy is validated.
Inventory ConfigNetworkSecurityPolicy/libcore policy bindings as well: provider installation
stores a policy object referring to the original config. TrustManagerFactory instances capture
ApplicationConfig at initialization, so replacing its static default cannot repair retained trust
managers, SSLContexts or socket factories. T-T23 uses fresh and deliberately precreated clients,
tests rollback and retains those gaps; it does not reset every global TLS singleton. The API35
core constructor/source methods are max-target-o, but newer CT members are blocked. Extend the
exact inventory rather than assert that all required members share a flag or are already reachable.
This mode preserves manifest/resources payloads and embeds public CA bytes in DEX. It is not the
default resource pipeline, a programmatic pin bypass or an accepted cross-release trust engine.

## Java matching

Match multiple surviving signals: framework-interface contracts and inherited implementations,
descriptors/return contracts, exception/control-flow shape and strings. R8 can remove/inline
methods, merge classes and change internal signatures. A failure string may identify a caller
without identifying a safe patchable method. Skip ambiguous, native, abstract or unsupported
return variants; never stub an unrelated enclosing method solely because it contains a string.

Test unoptimized, minified and optimized/merged/inlined fixtures with pinned dependency/toolchain
versions. Preserve caller register/range and exception contracts in static rewriting. That future
fallback can still invoke helper code; it is not zero runtime footprint or JNI/reflection coverage.

## Build and sign

The DEX-only path preserves resources/manifest and uses the accepted shadowing or recorded
rewrite strategy above in a fresh archive. The resource path uses the selected engine
plus compilation/linking; `-s` keeps DEX raw for resource-only work. jadx and dex2jar/CFR/Procyon
are read-only analysis fallbacks, not repair engines for a failed rebuild. Packer indicators gate
analysis of a loader-only DEX.

For device-sourced inputs, record installer-of-record and available InstallSourceInfo provenance
in P0 before replacement. When known and supported, pass that installer with `adb install -i` or
the tested install-multiple equivalent. Verify observed installer getters after installation;
record rejection/mismatch rather than retrying silently with different provenance. This does not
establish initiating/originating identity. File-only inputs have unknown provenance unless the
operator supplies evidence. M1b-1 adds a scoped shim only for a demonstrated remaining field gap.

Remove obsolete signature artifacts, maintain ZIP/native packaging requirements, align, sign,
then verify all selected split members with the persistent repack key. Compare preserved entry
contents and expected transform locations. Validate outputs before R-INSTALL device actions.
Preserve unedited entries' original compression methods. For target30+, resources.arsc must be
uncompressed and four-byte aligned; .so storage depends on extractNativeLibs/loader policy.
Test this in T-A02, before native modules. Prefer zipalign -P 16 over deprecated -p; changing ZIP
alignment cannot repair incompatible ELF segments.

Native additions preserve original ABI selection/bitness, inspect base and ABI splits, and respect
compression/extraction/linker paths. Pure-Java targets acquire an explicit declared ABI set. Check
all target and added libraries' ELF alignment plus uncompressed APK entry alignment on 16 KB
devices; `zipalign -P 16` cannot repair incompatible existing ELF segments. Native details remain
behind [M4/M6](implementation/LATER.md).

## B rationale: two different views of one APK

The required distinction is original bytes for supported integrity checks and patched bytes for
runtime loading. ART, libandroidfw, ZIP readers and app code can read the same paths through the
same libraries. Caller filtering and sourceDir matching alone cannot establish that distinction.
The exact import inventory, fd/metadata consistency, provisioning and two-sided loading tests
are specified once in [M4](implementation/LATER.md#m4--original-byte-read-experiments).

## Reference project layout

Create entries only when the active task needs them:

```text
config/implementation-lock.json
scripts/acceptance.py
scripts/spike.py
repack/{recon.py,rebuild.py,shim.py,trust.py,verify.py,report.py,cli.py,pipeline.py,patches.py}
shim/src/dev/repack/shim/
tests/fixtures/identity/{app,other}/
tests/fixtures/identity/{app,other,common}/       # primitive SDK builds
tests/corpus.json
.work/{inputs,outputs,keys,tools,evidence}/       # ignored local artifacts
```

JNI fixture code appears in M1b-2, selected-split support in M1b-3, B native code in M4 and native
pinning data in M6. Published source links live in [PLAN §9](../PLAN.md#9-technical-sources).

Embedded baseline profiles may stop matching after a DEX shift; record lost optimization and verify installation/startup. External .dm metadata is a separately validated input.
