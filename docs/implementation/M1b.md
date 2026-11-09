# M1b — independent integration gates

Open the current subsection only when its PLAN §5 prerequisites are accepted. M1b-1 through -4
form the identity track; M1b-5 starts the interception track directly after BOOTSTRAP, before full M1a.
Read PLAN §1/§7 and CONTRACT.
Each gate adds its own case handlers to the existing runner; it does not reopen unrelated modules.
All commands below are interfaces implemented by the corresponding numbered task.

## M1b-1 — signing contracts and caches

Read Architecture's A and signing metadata sections. Prerequisite: M1a accepted.
Exception: conditional task 3 / T-A16 opens after M1a task 3's access probe when an API28–34 first
cell needs its metadata adapter to complete M1a task 4. It does not accept the full M1b-1 gate.

1. **Files:** `tests/platform/signing-contracts.json`, PackageHandler, OriginalArchive, corpus,
   fixture installer arguments in the existing verify helper.
   **Steps:**

   1. Write the exact method/flag/user/UID/return/exception matrix. Extend from
      getPackageInfo to supported hasSigningCertificate/checkSignatures overloads, legacy signatures,
      SigningInfo accessors/history predicates and installer methods. Include unsupported/ambiguous
      shared-UID/cross-user cases explicitly. Preserve original installer provenance or an explicit
      unknown result; do not assume `com.android.vending`. Support InstallSourceInfo only with its
      fields/semantics tested, not by naming one string getter.
      Add the fixture-only `-i` preservation argument to the shared installer helper now; M1b-3
      generalizes it for arbitrary inputs/sets. First measure installer-of-record preservation;
      compare getInstallerPackageName and InstallSourceInfo.getInstallingPackageName against host
      provenance. This is an installer argument, not evidence that initiating/originating fields
      match. Add a scoped shim for a remaining field (such as getInitiatingPackageName) only when
      an authorized target/fixture demonstrates the need and the exact field semantics are tested.
      Preserve untouched InstallSourceInfo fields and test install-multiple independently.
      On the pinned API35 source, hasSigningCertificate/checkSignatures use mPM rather than the
      getPackageInfo cache's sPackageManager path. Patch observed old manager references where needed
      and test newly created managers after publication. mPM is private final: record both reflective
      write outcome and actual reads/behavior; a successful assignment alone is not the oracle.

   2. Add getInstalledPackages(GET_SIGNING_CERTIFICATES) and getPackagesHoldingPermissions to the
      method/flag matrix, including legacy and typed public overloads where present. Declare a
      normal fixture permission requested by both apps for the permissions-list scenario. Observe
      the real Binder return descriptor: API35 uses ParceledListSlice, not a plain Java List.
      Read/materialize it through the pinned hidden access path, copy the list and only its self
      PackageInfo entries, apply the same scoped signing-field copy, and construct the matching
      return container. Preserve list order, package visibility, unrelated entries, null/errors
      and non-signing fields; no in-place edits to cached entries or signing data without requested
      flags. List methods do not have a package-name first argument: dispatch on their actual
      descriptors/flags/user, then match each returned PackageInfo.packageName. Inventory the
      container constructors/getList in Hidden.java before using them.
      If a container/path cannot be supported, report the exact list-query gap rather than count
      scalar getPackageInfo success as complete A coverage.

   **Check:** `python scripts/acceptance.py run T-A10 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A10.json`.

   **Pass:**

   - self identity matches original, unrelated identities match truth, negative/missing
     package and raw/hashed certificate comparisons retain correct semantics. Include actual
     multi-signer and rotation fixtures signed by host tools; do not fake history solely in JSON.
   - Both list queries find self and unrelated entries under the controlled visibility/permission
     setup; self signer data matches original, unrelated signer data and order/non-signing fields
     match truth. Controls without signing flags retain the original return contract.

   **Fail→:** narrow the named contract or repair semantics before task 2; update release scope.

   **Stop:** no generic unconditional true answers, blanket installer spoof or new API range.

   **Interpretation:** Installer-of-record, signing predicates and history are independent contracts; one matched value cannot accept the others.

2. **Files:** PlatformAccess, `tests/platform/api35-members.json`, cache fixture scenarios.
   **Steps:**

   1. Inventory existing/new contexts, ContextImpl cached managers and platform query
      caches on the pinned source revision. Choose framework-parsed metadata when T-A05 supplies the
      required case at its required time; otherwise retain tested public construction for API 35.
      Add hash invalidation, cloning and recursion protection. Check stale references/results before
      bootstrap, after publication and after an ordinary compatible fixture update.
      Cover cache hits/misses across package/flags/user keys, including an intentionally prewarmed
      self signing entry. Confirm shim setup never warms public self-getPackageInfo before publication.
      Keep T-A03's first-query-handler baseline separate. Make the prewarm scenario an explicit
      alternate startup arrangement, not a claim that it precedes every factory initializer.
      Observe earlier framework caches independently of shim-created entries.
      Preserve full long flags and test typed/legacy overloads; method-name selection alone is insufficient.

   **Check:** `python scripts/acceptance.py run T-A11 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A11.json`.

   **Pass:**

   - exact path-by-path observations, no in-place signing-field edits to shared cached
     results, and no stale
     metadata after input changes. Any pre-hook values that cannot be intercepted remain a named gap.

   **Fail→:** fix scoped copying/lookup. An optional one-shot process-local sPackageInfoCache.clear
   at publication may be tested here; record before/after results, member access and the exact
   clear count. Its absence/failure narrows prewarmed-cache support, not T-A03's unwarmed baseline.
   Verify prewarmed new queries recompute when that capability is claimed and unrelated-package
   results stay truthful. Do not globally flush/disable platform caches or claim already returned
   objects changed. Member access permission alone does not guarantee final-field write semantics.

   **Stop/next:** run conditional task 3 when an API28–34 phone is a first/release target, then `gate M1b-1`.
   Otherwise record the inactive legacy-cell condition and gate on T-A10/T-A11; do not claim API34 support.

   **Interpretation:** A measured scoped clear can repair new lookups; it cannot alter objects already returned to callers.

3. **Files:** `shim/.../LegacyIdentity.java`, selected-API source/layout inventory and T-A16.

   **Steps:**

   1. Activate for the selected API28–34 phone (currently API30). Pin that release's SigningInfo
      and SigningDetails serialization source. This metadata subpacket can precede M1a task 4;
      full M1b-1 acceptance still requires M1a/T-A10/T-A11.
   2. First try public Parcel plus SigningInfo.CREATOR. For the pinned layout, write the UNKNOWN
      marker as int0, current Signature[] with writeTypedArray, verified scheme version, then the
      public-key set as count plus writeValue(PublicKey) per element, then verified past Signature[]
      or null. This reproduces the ArraySet encoding without hidden Parcel.writeArraySet. Reset
      position and call SigningInfo.CREATOR.createFromParcel; recycle in finally. Compare current
      signers, legacy/history/multiple-signer predicates and a second parcel round-trip against
      independent original-archive/host truth. Add invalid-layout/invalid-cert controls.
   3. If the selected-cell layout branch fails, trial the hidden SigningDetails/SigningInfo
      constructors with the same pinned bypass and exact source descriptors. The hidden class
      may be PackageParser$SigningDetails on older releases. Retain one selected implementation
      per tested API; API35's public populated constructor is not called on this phone.

   **Check:** `python scripts/acceptance.py run T-A16 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A16.json`.

   **Pass:** metadata matches independent current/history truth at the claimed check time;
   public-CREATOR and constructor results are recorded separately, including round-trip controls.

   **Fail→:** classify the selected legacy-cell path unsupported if both bounded branches fail;
   keep interception evidence and apply PLAN §8 to the missing identity path.

   **Stop/next:** when opened early, return to M1a task 4; otherwise join T-A10/T-A11 before gating.

   **Interpretation:** public methods avoid hidden access for this branch, but SigningDetails'
   wire format is internal; a tested API30 layout is not blanket API28–34 coverage.

**DO:** compare all identities, flags and non-signing fields. **DON'T:** add hidden constructors
for unneeded API levels, JNI, Binder wrappers, broad CLI, network forcing or B.

## M1b-2 — JNI and fresh Java Binder stubs

Read Architecture's A rationale. Prerequisite: M1b-1 accepted.

1. **Files:** fixture `app/src/main/cpp/`, native build configuration, lock and runner.
   **Steps:**

   1. Pin NDK/CMake (or ndk-build) revisions supported by the selected fixture build;
      record their package/source hashes before adding JNI. Build x86_64 and the selected physical
      ABI (currently arm64-v8a) directly with pinned NDK Clang. Run first on the connected phone;
      retain the unavailable x86_64 runtime cell explicitly. No CMake/Gradle dependency is needed.
      Have JNI invoke the same Java PackageManager path, with independent direct/reflection controls.

   **Check:** `python scripts/acceptance.py run T-A12 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A12.json`.

   **Pass:**

   - JNI-to-Java self/other results agree with host truth and Java counterparts; native
     loading/ABI state is recorded. This adds no native Binder or file hook support.

   **Fail→:** isolate JNI signature/loading failures from Java proxy failures; stop task 2 until
   this path is classified correctly.

   **Interpretation:** JNI-to-Java follows the tested Java path and does not establish native Binder coverage.

2. **Files:** `shim/.../PackageBinder.java`, PlatformAccess, fresh-stub/raw-transaction scenarios.
   **Steps:**

   1. Implement the separate ServiceManager cache-wrapper trial. Match the exact package
      interface descriptor in queryLocalInterface, preserve unrelated Binder operations and record
      asBinder/death/forwarding behavior. Test a fresh Java Stub from getService, an earlier retained
      handle, and a hand-built transaction separately. Do not patch transaction codes generically.

   **Check:** `python scripts/acceptance.py run T-A13 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A13.json`.

   **Pass:**

   - supported fresh Java stub queries observe original identity; raw native/hand-built
     transactions remain a documented real-identity negative case. Unsupported acquisition paths
     are not counted as covered. Avoid recursive getService calls through the wrapper.

   **Fail→:** retain accepted A while disabling only the failed fresh-stub claim; record the
   release scope decision. Do not turn an interface wrapper into an unplanned Binder emulator.

   **Stop/next:** `gate M1b-2` accepts only explicitly supported paths and negative-control evidence.

   **Interpretation:** Fresh Java acquisition and retained/raw Binder handles are distinct evidence paths.

**DO:** pin native dependencies and distinguish JNI-to-Java from native Binder. **DON'T:** implement
B, syscall hooks, proc concealment, global cache mutation or fresh-stub claims without T-A13.

## M1b-3 — split sets and install integration

Read Architecture's build/sign section and PLAN §6/§7. Prerequisite: M1b-2 accepted.

1. **Files:** `repack/recon.py`, selected-set validator, split fixture, corpus/runner.
   **Steps:**

   1. Validate one base, package/version/signers, unique split IDs, feature/config
      dependencies, SDK/ABI targeting and installed member inventory. Track each member by hash.
      Re-sign all selected members with the persistent key, including untouched members.

   **Check:** `python scripts/acceptance.py run T-P10 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-P10.json`.

   **Pass:**

   - valid on-disk selected sets round-trip; missing dependencies, mismatched versions
     or signers and conflicting split IDs are rejected before any install. No `.apks` subset selector.

   **Fail→:** repair normalization or leave the named input form unavailable; do not install all
   container members blindly or silently merge splits into one APK.

   **Interpretation:** Selected-member validation is not a container selector or proof of unavailable dynamic features.

2. **Files:** `repack/verify.py`, install preflight, key-resolution paths, runner.
   **Steps:**

   1. Implement R-INSTALL/R-KEY once for fixture and public callers. Exercise absent install,
      same-key compatible update, mismatched signer refusal, explicit wipe replacement, install failure
      and recorded post-failure state. Use `install-multiple` for validated sets.
      Capture installer-of-record before replacement. If known and supported, pass it as
      `adb -s SERIAL install -i INSTALLER APK` or the corresponding tested install-multiple option.
      Implement the actual argv as a subprocess argument list. Verify the resulting installer getters;
      preserve rejection/mismatch evidence and do not silently retry without -i. Unknown provenance
      remains unknown; no original installer is invented for an arbitrary file-only APK.

   **Check:** `python scripts/acceptance.py run T-P11 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-P11.json`.

   **Pass:**

   - ordinary same-key update preserves a fixture sentinel; mismatched signer without
     authorization leaves original package/data intact; explicit replacement records data loss;
     a missing/bad member never triggers a preflight-passing uninstall. No recovery guarantee.

   **Fail→:** stop all replacement work until the refusal/preflight controls pass.

   **Interpretation:** Installer arguments and successful installation do not establish all provenance fields or data recovery.

3. **Files:** `repack/{cli.py,report.py,pipeline.py}`, artifact-manifest schema, pyproject/README.
   **Steps:**

   1. Freeze PLAN §7's public schema and implement only §6's permitted surface. Add P0
      multi-signal stack/protection evidence (library names, file layout, package structure/resource
      hashes), installer provenance and original cert/history extraction. Device pull uses explicit
      serial plus `pm path`/all installed members; absent dynamic features are not invented. Integrate
      `pm list packages -i PACKAGE` evidence and available InstallSourceInfo fields before replacement.
      Retain source and null/unknown values individually, rather than treating installer, initiating
      and originating identities as interchangeable. Add advisory signing-reference triage with
      descriptors/locations, combined flag use (0x40/0x08000000), PackageInfo.signatures/signingInfo and
      signing predicates. Record uncertainty after R8/library attribution; use reference evidence only to recommend A; its absence leaves self-check status unknown. Report explicit --antitamper
      requested/selected state and the reason, as specified in PLAN §6.
      Integrate fresh-unpack, helper exclusions and output hashes. Future transforms return unsupported/error.
      General APK extraction uses the selected apksigner's verified signer/PEM output and retains
      actual certificate bytes, all current signers and available verified history. Check the locked
      tool's supported flags; a missing required output is a tool/input limitation to resolve explicitly,
      not a reason to restore an extraction-helper project to M1a. Fixture keytool export remains
      a fixture oracle only. Expose trust/routing/Java implementations already accepted on the other
      track through the limited public CLI; never make that track depend on this integration task.

   2. Detect L-PAIRIP indicators separately from generic RASP: `Lcom/pairip/` DEX descriptors
      (normalized `com.pairip.*` class names)
      and `libpairipcore.so` member paths across the selected base/ABI splits. Record exact
      locations/hashes and static confidence. Link possible Play automatic protection to its own
      scope limit; absence of either marker does not exclude protected/obfuscated variants and
      marker presence does not establish an enforced Play/license/device check. Release 1 does
      not remove this protection. Evaluate PairIP/Play-origin checks independently of installer strings and A query results.

   **Check:** `python scripts/acceptance.py run T-P12 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-P12.json`.

   **Pass:**

   - manifests bind outputs to inputs; modified output fails verify; prepatched input
     fails clean-room preflight; semantic report diffs are stable; missing metadata remains explicit.

   **Fail→:** fix provenance/validation before exposing the affected command.

   **Stop/next:** `gate M1b-3` requires all three reports; open M1b-4 after acceptance.

   **Interpretation:** Static references guide triage; the explicit transform request and runtime evidence determine accepted behavior.

**DO:** keep input and output artifacts separate and report actual device state. **DON'T:** add
container formats, target lowering, side-by-side rename, user-store fallbacks or B flags. Preserve
accepted interception behavior while integrating it; do not reimplement it as a second pipeline.

## M1b-4 — process and startup coverage

Read Architecture's bootstrap section. Prerequisite: M1b-3 accepted.

1. **Files:** bootstrap adapters, fixture remote/isolated services, loader/startup scenarios.
   **Steps:**

   1. Record factory/ancestor/constructor/attach/provider/native ordering; start supported
      main/remote processes independently and after restart. Test class-loader visibility and early
      checks before context-dependent provisioning. Treat isolated/WebView/external processes as
      separate paths and record limitations rather than assuming main-process state propagates.
   2. Use ProcessProbe's13 events per run: direct/reflection/JNI legacy/current self/other plus
      missing-package error. Genuine and patched arrangements each run main, remote, isolated and
      restarted remote; then run genuine/patched app-local X.509 provider controls and a published
      Binder rollback control. Require143 comparisons across11 runs. Join actual PIDs, process names,
      loader/ABI and installed UID/source/version. Isolated services have distinct UIDs and a
      service-class process-name suffix. Classify any restricted genuine path as an equivalent-error
      control, not a positive identity claim.
   3. Prepare original SigningInfo before PM publication and return private-template Parcel copies.
      An Application-installed X.509 provider must not affect later lookups; caller mutations of
      returned signer arrays must not affect subsequent results. Force Binder-enabled setup failure
      after service-cache publication and verify both PM and cache references return to their prior
      values. Existing T-A04 retains the separate before-publication failure control.

   **Check:** `python scripts/acceptance.py run T-A14 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A14.json`.

   **Pass:**

   - per-PID capability events and correct self/other queries in each declared process;
     early/uninitialized paths are detectable and cannot be reported as covered.

   **Fail→:** remove only the failed process/path claim or fix its initialization; no global hook.

   **Interpretation:** Each process/loader has its own initialization window; main-process results cannot stand in for it.

2. **Files:** `config/support-matrix.json`, source adapters, corpus and runner.
   **Steps:**

   1. Start release validation on the recorded release_target's actual API/target/ABI (default
      API35/target35 when no different operator target is selected), on a non-rooted physical ARM64 device
      and a production-like Google Play image where available. Preserve the initial AVD as a separate
      cell. Additional APIs/targets are individually scheduled extensions; API28–34 signing branches
      are not required merely because minSdk is 28. An explicit API28–34 target activates task 3 /
      T-A16 above and the normal signing regressions on that cell. Retain unavailable cells explicitly.
   2. Read the exact cell declaration from config/support-matrix.json. The initial delivered
      declaration is API30/target35/arm64/4KB, user0, with the recorded Redmi fingerprint. Rerun
      M0/BOOTSTRAP, M1a, M1b-1/2/3/5, M2/M3 and strengthened T-A14 with frozen sources. T-A15 joins
      their immutable report hashes, tools and cell; it does not manufacture additional device runs.
      Declare unavailable emulator/16KB/other-API cells explicitly. Recorded non-root execution and
      ro.debuggable=0 do not independently establish factory-stock firmware provenance.

   **Check:** `python scripts/acceptance.py run T-A15 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A15.json`.

   **Pass:**

   - M1a and relevant M1b cases pass on each declared release cell with release APKs,
     recorded firmware and no root/device-wide policy changes. A uses the single pinned process-local
     access mode; the identity packet's ordinary diagnostic is retained without a separate support matrix. Physical ARM evidence is required for the
     stock-phone claim; missing hardware blocks that claim, not the evidence from other cells.

   **Fail→:** narrow the declared matrix explicitly; do not relabel emulator evidence as physical.

   **Stop/next:** accept `gate M1b-4` against the declared matrix. If M3 is accepted, run the
   RELEASE-1 join; otherwise continue the next eligible interception gate. Do not place this
   physical-device gate ahead of the first controlled HTTPS proof.

   **Interpretation:** A support claim names the tested physical/production cell and pinned access mode.

**DO:** name each process/build cell. **DON'T:** silently expand API support, use device-wide/debug exemptions,
or implement arbitrary OEM adapters to hide a missing required release test.

## M1b-5 — routing and persistence

Read Architecture's routing section. Prerequisite: BOOTSTRAP (T-A01/T-A02) accepted; no dependency
on identity tasks T-A03–06 or M1b-1 through -4. Reuse the bootstrap packet's fixture preflight,
build/hash/report helpers. Add only the route/reverse lifecycle
needed now; public CLI and complete schema/split integration stay in the identity track.

1. **Files:** `shim/.../Route.java`, reverse-mapping lifecycle in verify, HTTP fixture/runner.
   **Steps:**

   1. Install the selected Arch reference proxy with `sudo pacman -S --needed mitmproxy`,
      record its resolved version/hash, and start it on host loopback. Its initial startup creates
      the local CA. The default public --ca input for this reference setup is
      `~/.mitmproxy/mitmproxy-ca-cert.pem`; use the actual confdir's public certificate if overridden.
      Never embed mitmproxy-ca.pem, which contains the private key. Record certificate fingerprint
      and verify the proxy chain before M2. Add `scripts/spike.py patch --proxy host:port` now and bake
      validated host/port into Route configuration under PLAN §6. Default 127.0.0.1:8080. Implement
      ProxySelector/properties in Bootstrap.initLate, not initEarly. Record the effective endpoint
      in the minimal artifact manifest. Use adb reverse only for the selected loopback reference
      transport; a remote endpoint does not implicitly create a mapping. Start with deterministic
      HTTP routing on the controlled fixture; HTTPS trust is M2.
      For covered HTTP(S) URIs, select exactly `[configuredProxy]`; do not return null/empty,
      append NO_PROXY, retry directly or delegate failure to the old selector. Treat the
      configured proxy URI exactly as other HTTP(S) destinations; no proxy-host exception. Log connectFailed
      when invoked and request failures separately. Uncovered URI schemes/explicit app proxies
      retain named scope, not an accidental claim that every socket uses HTTP proxy selection.
      This fixture-only HTTP control does not enable cleartext globally in target manifests. Preserve
      existing mappings; use no-rebind/explicit refusal for a conflicting port and record ownership.
      Test both the default and an explicit fixture endpoint (127.0.0.1:18080 with its own owned
      reverse mapping to host port 8080), so hardcoded ports cannot pass. Reject malformed endpoints
      before building; verify --proxy compares configuration rather than changing it. Public CLI
      exposure still waits for M1b-3; reuse this parser/configuration then.

   **Check:** `python scripts/acceptance.py run T-N10 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-N10.json`.

   **Pass:**

   - a per-run marker reaches the host proxy on the covered path and the expected
     response reaches the app. Record which client constructed/captured its selector and when.
     The initLate completion event must follow API35 startup proxy setup and precede the fixture's
     first Application networking request; the early hook's selector/property values are not the oracle.

   **Fail→:** isolate reachability from selection/connection reuse; do not change Wi-Fi proxy.

   **Interpretation:** Route configuration requires independent reachability and HTTPS trust observations.

2. **Files:** Route, configuration-transition fixtures and runner.
   **Steps:**

   1. First measure the initLate selector/property installation across configuration updates,
      client reuse and process restart. If it resets, trial replacing the saved sDefaultProxySelector
      on this cell as one explicit hidden-field experiment. Record private/final access and PAC
      behavior separately. If this experiment needs hidden access, pin/vendor the same process-local
      dependency specified for A, record its prefixes and scope it to this optional routing experiment.
      Keep this optional experiment independent of identity acceptance and initial routing. Reuse that pin when the identity task opens; do not choose a second bypass.
      Once a usable context exists, add a lifecycle-managed public
      PROXY_CHANGE_ACTION receiver that reapplies the configured endpoint as supplementary recovery;
      register with the SDK's required receiver semantics. Reapply the baked endpoint; measure the receiver's race window against the platform update.
      Repeat fresh-client, pooled-client and requests during transitions; record callback order,
      missed/escaping requests and actual recovery. Hidden-API access does not by itself make a
      private static final field writable or the update durable.

   2. On the selected fixture test cell, snapshot whether global http_proxy exists and its exact
      value. Trigger a real configuration change with `adb -s SERIAL shell settings put global
      http_proxy :0`, observe PROXY_CHANGE_ACTION and fresh requests, then restore the exact prior
      value; use `settings delete global http_proxy` only when it was originally absent. Record
      mutation/cleanup even on failure. This is a transient device-wide test, so an operator phone
      run must explicitly select that mutation; startup-only routing acceptance can leave this
      transition unsupported when the mutation is unavailable.

   **Check:** `python scripts/acceptance.py run T-N11 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-N11.json`.

   **Pass:**

   - exact covered transition set with markers at the proxy and correct responses.

   **Fail→:** if the saved-selector experiment fails access or persistence (including
   PAC), preserve initial routing evidence but do not claim persistence. Record a scoped unsupported
   transition and stop this release claim for decision under PLAN §8. Retain the bounded saved-selector trial and its measured scope. Accepted
   initial routing still permits the controlled M2 proof; unsupported transition scope must stay
   explicit rather than suppress all interception work or masquerade as general persistence.

   **Interpretation:** Observed transition requests determine persistence; callbacks and reflective writes alone do not.

3. **Files:** reverse ownership/cleanup and direct Java-socket control scenarios.
   **Steps:**

   1. Disconnect/reconnect adb, restart the proxy, check existing mappings, then cleanup
      only owned mappings. Exercise an uncovered direct Java route and a second app's ordinary
      traffic. Native-socket controls join the regression suite after JNI fixtures exist; they are
      not an early interception-track dependency or evidence of native routing support.
      If the operator supplies a reachable remote endpoint, build with that endpoint and test off
      USB, including Wi-Fi→mobile-data transition on an available phone. Record DNS/TCP reachability
      independently of selector persistence and marked proxy requests. A laptop LAN address is not
      assumed reachable over mobile data. Without this environment, leave off-USB/mobile coverage
      not-run; loopback fixture acceptance cannot establish it and does not wait for that claim.

   2. Add a proxy-down negative control for each claimed covered client. Use a separately reachable
      controlled origin with per-token request logs (for example, an independently owned reverse
      mapping to an origin port distinct from proxy 8080). First prove direct origin reachability
      with a separate calibration token. Stop the proxy, start a fresh fixture process/client
      without retained pools, and issue the covered HTTP(S) request with a new token and bounded
      timeout. Require client failure, observed proxy/connection failure, and zero requests with
      that token at the origin. Log connectFailed if the client calls it; absence of that callback
      alone is not proof of success/failure. Keep an explicit direct/uncovered route control and
      restore the proxy afterward. No blanket fail-closed claim extends beyond this tested path.

   3. Optionally test Android11+ paired wireless debugging on the operator phone. Pair through
      the documented system UI/`adb pair` flow; do not log the pairing code or enable a legacy
      unauthenticated adb TCP listener. Select the wireless serial explicitly and verify/create
      owned reverse mappings there. Disconnect USB, confirm adb uses the wireless transport, and
      require a fresh marked request/response at the loopback proxy. A USB reverse mapping is not
      assumed to migrate; recreate only the owned mapping if needed and record that event. Test
      wireless disconnect/reconnect and cleanup. Record pairing/debug-setting changes separately;
      Preserve unrelated pairings and mappings. This optional Wi-Fi cell does
      not establish mobile-data reachability or block the reference wired fixture case if absent.

   **Check:** `python scripts/acceptance.py run T-N12 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-N12.json`.

   **Pass:**

   - covered route loses/restores transport as observed; direct controls are not
     misreported as intercepted/blocked; unrelated mappings/app traffic remain unchanged.
   - Proxy-down fresh requests on each claimed client fail with zero controlled-origin hits;
     the direct calibration/control remains independently reachable.
   - When wireless-adb coverage is claimed, the selected wireless transport and owned mapping
     carry fresh marked requests after USB removal, with disconnect/recovery/cleanup evidence.

   **Fail→:** repair lifecycle or record the unsupported route. Any proxy-down origin hit fails
   the covered client's fail-closed claim; do not hide it under transport loss. Missing optional
   wireless/remote-endpoint environments stay not-run; no blanket fail-closed result follows.

   **Stop/next:** accept `gate M1b-5` with its declared routing scope, then open M2.

   **Interpretation:** Off-USB endpoint reachability is separate from selector persistence and loopback cleanup.

**DO:** record selector, transport and client lifetime separately. **DON'T:** claim all traffic is
intercepted, add a VPN/Wi-Fi proxy, ship B, or use CT/TLS bypasses to explain a routing failure.
