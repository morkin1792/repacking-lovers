# Future work

Recorded on 2026-11-09. This backlog separates missing implementation, missing
runtime evidence and architectural limits. It preserves future work while we
release the current scoped implementation. Items below are follow-up work, not
new prerequisites for the current release.

The main M0–M8 phases have accepted implementations for their recorded scopes.
Additional delivered work includes standalone startup search and the selected
[pinning-haters adaptations](pinning-expansion.md). Historical milestone names
and research tables are not a universal compatibility promise.

## Platform support and verification

- [ ] **Broader identity adapters.** Public `--antitamper` and the SigningInfo
  adapter currently require API30. Another Android version needs implementation
  and fixtures, not just removal of the guard. Cover hidden access, publication
  timing, existing managers, metadata/rotation, caches, installer contracts,
  lists, Java/JNI and fresh Binder paths. Include API33+ long flags and API35
  metadata construction where appropriate. See [M1a](implementation/M1a.md) and
  [M1b](implementation/M1b.md).
- [ ] **Broader device matrix.** Test more OS/target-SDK combinations, firmware,
  ARM32/x86_64 and 16KB native environments. ZIP alignment does not establish
  runtime compatibility. Confirm stock-device behavior separately from non-root
  execution on the current phone. See [support matrix](../config/support-matrix.json).
- [ ] **Proxy transitions, T-N11.** Test resets, broadcasts and recovery through
  OS proxy changes, restoring the operator's settings. Startup routing acceptance
  does not establish transition persistence. Add Wi-Fi/mobile-data, reachable
  remote-proxy and wireless-ADB observations independently.
- [ ] **API36 CT, M2-CT/T-T22.** Run certificate-transparency policy/inheritance
  controls on API36 and add demonstrated adaptations. This is separate from the
  implemented Java appmattus CT patches.
- [ ] **Cache-hit repair evidence.** Deliberate prewarm controls exist, but actual
  platform cache-hit repair was unobserved on the recorded cell. Prove a cache
  hit and its repair on a platform where that path is active.
- [ ] **Midway authenticated flows.** Login was deferred by the user. Later test
  login, account actions and Flutter/native/Unico paths separately from welcome
  API traffic. Confirm external-module state and stock-device behavior before
  making stronger tool-only claims.

## Remaining named implementation packets

| Item | Current state | Work needed |
| --- | --- | --- |
| DEX-only bootstrap | `--dex-only` rejects the request | Implement its separate bootstrap strategy; test ordering, class resolution and payload preservation. M3 class shadowing is not this mode. |
| Runtime trust, M2-DEX/T-T23 | Planned experiment | Copy reflected NSC configurations, add the CA, preserve domain policy, and test rollback/early-created TLS objects. Resource trust remains the current default. |
| WebView routing | Optional module absent | Feature-gate AndroidX `ProxyController`, await completion, and test provider/version, processes, routing and trust. |

Runtime trust and DEX-only bootstrap are separate packets. Neither completes the
other. See [M2/M3](implementation/M2-M3.md) for runtime trust and CT acceptance.

## Startup repair and integrity

- [ ] Add recognizers/experiment axes for more signer encodings and check
  families. Search currently solves one encoded signer-string family and tests
  QUERY_ALL_PACKAGES removal. Keep input-derived locations and deterministic
  rules without target offsets or an AI dependency.
- [ ] Automate more manual investigation: encrypted configuration decoding,
  native-check attribution and a package blacklist's exact match. The current
  standalone search does not reconstruct those checks.
- [ ] Extend original-byte mappings with independent coexistence fixtures.
  Public M4 covers selected callers' read-only absolute base-APK opens;
  split-original mappings remain experimental. Relative/dirfd and proc-fd paths,
  readlink exposure, raw syscalls, dlsym pointers and preopened descriptors remain
  gaps. Add metadata handling only for demonstrated cases.
- [ ] Handle callers mixing integrity and legitimate APK reads. Library-name
  selection cannot distinguish those uses. Preserve patched lazy resources,
  classes and split loading for every added path.
- [ ] Treat memfd variants and broader static anti-tamper rewriting as separate
  experiments with fd/metadata, null/receiver/exception, reflection/JNI/Binder,
  cache and lifecycle controls.
- [ ] Expand Gadget beyond the exact owned raw-syscall fixture only with named
  mechanisms, footprint, ABI and runtime evidence. It is not currently a generic
  production-app fallback.

## Pinning, native and managed stacks

- [ ] Extend native matching to more verified builds/layouts and ABIs. Current
  ARM64 exported contracts and hidden BoringSSL locator are implemented;
  unmatched layouts, independent post-handshake digest comparisons and redundant
  self-integrity need more adapters. Midway's retained Flutter engine did not
  match the current static native locator.
- [ ] Add native trampoline unwind support/verification where needed. Current
  wrappers have no asynchronous unwind metadata.
- [ ] Expand Dart recognition across proven snapshots/runtimes, async predicates,
  erased types, inlining and shared/unrecognized shapes. Preserve Dart object
  and async semantics. Current measured runtime is Dart3.0.6/Flutter3.10.6.
- [ ] Add native/Dart proxy routing separately. Removing TLS validation does not
  route stacks that ignore ProxySelector; loopback TLS fixtures do not prove
  generic native proxy routing.
- [ ] Develop Go, rustls, Mono/Xamarin and IL2CPP bypasses from concrete fixtures
  and function/assembly contracts. The source catalog supplies detection markers,
  not generic bypasses to port.
- [ ] Broaden Chromium/Cronet, Conscrypt, hostname and plugin recognition with
  version/obfuscation fixtures. External and reflective-only paths need separate
  treatment; current rules require supported ownership and code evidence.
- [ ] Broaden exact reFlutter replacement after engine/AOT/ABI and route
  validation. The version-specific mode is not a universal engine swap.

## Resources, inputs and app compatibility

- [ ] Grow the authorized resource-rebuild corpus and report attempted/pass/
  unsupported counts. Fixtures and Midway do not establish a broad Play-app rate.
- [ ] After a concrete Apktool failure, trial a pinned binary resource fallback
  against identical trust/policy/runtime controls. Existing ARSCLib manifest
  edits do not establish full resource/CA fallback support.
- [ ] Expand container support beyond targeted .apks subsets and selected-set
  .xapk v2 cases. Expansion/assets, ambiguous configurations and uninstalled
  on-demand features need explicit handling.
- [ ] Test in-process Firebase signing-header construction before claiming that
  integration covered. External GMS verification stays outside local spoofing.
- [ ] Add optional side-by-side renaming as its own packet: authorities,
  permissions, component/reference changes, package-name checks, deep links and
  backend registrations. Renaming does not recover original private data.
- [ ] Define/test optional user-store trust, installer overrides and target-SDK
  lowering separately, with provenance and behavioral changes reported.
- [ ] Define delivery for runtime proxy reconfiguration. Ordinary adb cannot
  write a non-debuggable app's private files/repack-proxy. The current endpoint
  is baked into the APK.

## Verification and operator workflow

- [ ] Add real-app action/capture adapters and repeatable post-startup checks.
  Current runtime auto-pass is limited to the owned marked fixture; manual
  real-app packets remain inconclusive in that verifier.
- [ ] Add Burp/Caido evidence adapters when needed. Preserve endpoint/window/PID/
  app-response binding and reject CONNECT-only or unrelated traffic.
- [ ] Promote useful orchestration under ignored .work into maintained reusable
  commands, including startup-search winner to interception-build handoff.
  Keep credentials and captured data local.

## Release and maintenance

Delivered in the guided workflow: localhost browser UI, APK/split/container
selection, installed-app name/package search with immediate version strings and
background icons, automatic local tool/key preparation,
SDK discovery and hash-pinned helper setup, automatic Burp-certificate retrieval,
PEM/DER input normalization, build/download/install, scoped replacement confirmation,
proxy/app details and build deletion in history, named build steps, a single APK-set
download with installation instructions, per-build destination selection/retry with
device-scoped replacement consent, loading-only automatic preparation, adaptive
checksum-verified APK reads over unstable transports, and a reproducible source-bundle builder. See
[guided workflow](guided-workflow.md). Broader packaging/platform work below
remains separate.

- [ ] Reproduce guided setup/patching on a clean second physical host. The current lock includes
  workspace paths and dependencies live in ignored caches. Guided setup already
  regenerates local paths without stale device/server settings and passed an
  isolated no-Git SDK/helper bootstrap; another physical host remains untested.
- [ ] Include/locate sibling configs, Java/native sources and assets in standalone
  wheel/installer packaging. The source bundle already includes these resources;
  a Python wheel alone remains incomplete.
- [ ] Validate additional host OS and Python/JDK versions. The resource compiler
  and analyzer have Linux-specific assumptions; current Dart setup wheels target
  Linux x86_64/CPython3.14.
- [ ] Decide distribution/version and repository license, audit third-party
  notices/artifact rights, and publish a reviewed release. The source-bundle
  builder already passed reproducibility checks.
  Package version remains0.1.0.dev0; the guided source bundle does not publish
  itself or resolve the repository-license decision.
- [ ] Reconcile stale progress/support-matrix target summaries with latest
  observations, retaining immutable history rather than overwriting it.

## Architectural limits, not promised features

APK edits cannot forge server-verified Play Integrity or keystore attestation,
change the installed certificate seen by other processes, or satisfy externally
bound OAuth/API registrations through local identity spoofing. Packed/encrypted
code, commercial RASP and PairIP/Play protection may need per-target research;
there is no generic removal claim. Unmodified system/WebView providers and other
apps are outside edits to the input APK.

Keep these limits in user documentation. More pattern matching is not a promise
that every app will work.

## References

- [Plan](../PLAN.md), [architecture](ARCHITECTURE.md) and
  [later packets](implementation/LATER.md).
- [Startup search](startup-search.md), [Java patches](pinning-patches.md) and
  [additional pinning modes](pinning-expansion.md).
- [Recorded evidence](implementation/progress.md) and
  [Midway observations](targets/midway-pinning.md).
