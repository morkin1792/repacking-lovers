# Deferred work — do not implement until RELEASE-1 is accepted

This preserves later technical requirements without putting them in the M0/M1a working context.
Select one extension after first-release acceptance. PLAN §1/§7/§8 and CONTRACT still own shared
rules and evidence. Any new command option is added only when its owning extension is accepted.

## M4 — original-byte read experiments

Prerequisites: RELEASE-1 accepted, retained-original provisioning from T-A05, and appropriate native
build/device cells. Read Architecture's B rationale and build/sign section.

1. **Files:** `native/` hook smoke fixture, version lock, file-import inventory and runner.
   **Steps:**

   1. Start with ByteHook; pin a released revision/build, dependencies and license. Measure
      required import hooking, delayed library loading, libc-internal calls, loader namespaces,
      platform API/ABI compatibility and 4/16 KB packaging before writing redirects. Inventory
      `open`/`open64`, `__open_2`, `openat`/`openat64`, `__openat_2`, `fopen`/`fopen64` plus observed
      additional symbols per fixture; do not assume aliases share a hooked PLT import. Bionic public
      wrappers can call internal __openat directly, so one public openat hook is insufficient.

   **Check:** `python scripts/acceptance.py run T-B00 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-B00.json`.

   **Pass:**

   - an actual per-import/per-library coverage map, no path redirection yet, and delayed
     loads reported correctly. A missing required import path is a concrete unsupported observation.

   **Fail→:** if attributable to the selected hooking library rather than misuse, trial one
   alternative against the same smoke fixture. Do not build several hook adapters or label a
   missed path supported. Exhausted alternatives use PLAN §8.

   **Stop:** choose/pin one tested hook mechanism before task 2.

   **Interpretation:** Import-hook success is scoped to the recorded library, API and ABI.

2. **Files:** original-byte storage/mapping, scoped read prototype, fixture read scenarios.
   **Steps:**

   1. Retain every base/split original with hashes, provision before supported checks,
      handle update invalidation, storage limits, reentrancy and cleanup. Inventory dirfd/relative
      paths, flags/errors, offsets, read/mmap/ZIP behavior, pre-opened and duplicated descriptors,
      stat/fstat metadata and readlink(/proc/self/fd/N). Opening an original supplies some consistent
      metadata naturally; add metadata interception only for a demonstrated necessary case.

   **Check:** `python scripts/acceptance.py run T-B01 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-B01.json`.

   **Pass:**

   - supported checks observe exact original bytes/metadata with correct fd semantics;
     arbitrary unrelated reads are unchanged. Direct syscalls/static libc copies remain gaps.

   **Fail→:** reduce to one named read pattern; no generic proc concealment framework.

   **Stop:** task 3 before any B path is advertised.

   **Interpretation:** Original-byte consistency on a read pattern does not prove patched runtime loading.

3. **Files:** lazy patched-resource/class/split fixtures and read-provenance evidence.
   **Steps:**

   1. Combine integrity reads with a resource intentionally changed by the patch, a newly
      loaded patched class, on-demand split loading and fresh ApkAssets/ZIP-backed resource reads.
      Exercise shared app/framework ZipFile paths after initialization and after delayed native loads.

   **Check:** `python scripts/acceptance.py run T-B02 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-B02.json`.

   **Pass:**

   - original integrity bytes AND patched runtime behavior in the same run. A resource
     returned from the original is failure even if CRC/signing-block tests pass.

   **Fail→:** record unsupported path if caller filtering cannot distinguish the two uses. Path
   matching sourceDir alone is never enough. Do not repair this by loading unpatched code.

   **Stop:** no release of that B path until both sides pass.

   **Interpretation:** Both original integrity reads and patched runtime behavior must succeed in the same run.

4. **Files:** ABI/split-packaging cases and optional archive-parser case.
   **Steps:**

   1. Preserve original ABI selection/bitness; inspect libraries in base and config splits.
      For pure-Java apps explicitly record added ABIs. Validate compression/extraction/linker behavior
      and every existing/new native dependency on 16 KB devices, including ELF segments and APK entries.
      After alignment and signing, verify alignment without changing the archive:

      ```sh
      "$REPACK_TOOLS/zipalign" -c -P 16 -v 4 .work/outputs/native/patched.apk
      "$REPACK_TOOLS/apksigner" verify --verbose --print-certs .work/outputs/native/patched.apk
      python scripts/acceptance.py run T-B03 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-B03.json
      ```

   **Pass:**

   - 32-bit-only target stays 32-bit; added hook loads on the named cell; incompatible
     original ELF dependencies are identified rather than allegedly repaired by zipalign. Scoped
     getPackageArchiveInfo support, if claimed, has a distinct actual parser fixture.

   **Fail→:** block only the affected ABI/page-size/path and retain diagnostics.

   **Stop/next:** `gate M4` requires T-B00–03 for each shipped path; expose only
   `--integrity <tested-path>`, with its recorded prerequisites.

   The implemented public candidate is `native-base-bytes:libCaller.so[,libOther.so]` on API30
   ARM32/ARM64. T-B04 additionally exercises actual public patch/verify, early original provisioning,
   imported/constructor read hashes, unchanged ABI choice and ARM64 A/Java/split composition.
   Gate M4 joins T-B00–04 plus current T-A03/T-P12 default regressions. Shared file-import thunks
   are compiled into both the smoke bridge and persistent loader. Public mapping remains base-only;
   every-member split reads are retained as separate experiments, with their FD-path/raw-call gaps.

   **Interpretation:** ZIP alignment cannot fix incompatible ELF segments or establish unsupported parser behavior.

**Rationale:** ART, resources, ZIP readers and checks can share libraries and filenames. Caller
filtering is an experiment, not a universal separator. A memfd variant is a later experiment
requiring independent metadata, parser, lifecycle and observable-state tests.

**DO:** prove original-byte and patched-runtime coexistence. **DON'T:** redirect every sourceDir
read, promise raw-syscall coverage or hide hook artifacts generically.

## M5 — input containers, when an actual input requires them

1. **Files:** container selector, bundletool lock, archive fixtures, runner.
   **Steps:**

   1. Use bundletool/device spec for a compatible subset of multi-device .apks; parse .xapk
      metadata separately and identify unsupported expansion/asset requirements. Preserve the archive
      inventory separately from selected members. Device pull provides installed dynamic features
      only, not every possible feature.

   **Check:** `python scripts/acceptance.py run T-I50 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-I50.json`.

   **Pass:**

   - valid compatible subset with P0 dependency validation; conflicting/missing members
     rejected; no install-all behavior. Missing device targeting is an unmet prerequisite.

   **Fail→:** record that container unsupported; existing selected-set support stays separate.

   **Stop/next:** `gate M5` before adding container/device-spec public options.

   **Interpretation:** Container inventory is distinct from a validated device-compatible selected set.

**DO:** reuse M1b-3 member validation. **DON'T:** merge all ABIs/configs or reinterpret archive
presence as evidence that every dynamic feature is installed.

## M6 — native pinning and managed-stack extensions

1. **Files:** `signatures/`, per-ABI patcher/scanner, stack fixtures and dependency lock.
   **Steps:**

   1. Use the pinned official Flutter3.10.6 ARM64 engine and its known AOT build for T-U60. The first measured mode is an exact third-party reFlutter engine replacement, with its license and binary hash recorded separately from own-tool transforms.
      Record reFlutter's fixed-route/version constraints and verify the chosen loopback route actually
      works. Use a curated symbol/byte-pattern database and LIEF per-ABI edits only after exact build
      identification and unique match validation. Use rizin/radare2+capstone, or Ghidra headless, for
      candidate finding rather than guessing a patch. Pin the selected tools; no universal engine layer.

   **Check:** `python scripts/acceptance.py run T-U60 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-U60.json`.

   **Pass:**

   - known marked decrypted payload and app response; exact build/ABI, original bytes,
     matches/edits and packaging evidence recorded. Different/ambiguous builds remain unpatched.

   **Fail→:** manual candidate review, not an unconditional native return stub.

   **Interpretation:** A unique known build match and marked request support only that binary/ABI.

2. **Files:** function contracts and custom native/managed candidates.
   **Steps:**

   1. Determine success semantics per function and build; for example SSL_get_verify_result
      expects X509_V_OK=0, while some session_verify_cert_chain versions use 1. Confirm the exact
      source/binary contract before choosing a stub. Account for a library's own checksum and redundant
      checks. Xamarin managed DLL rewriting is a separate pinned-assembly fixture, not native coverage.

   **Check:** `python scripts/acceptance.py run T-U61 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-U61.json`.

   **Pass:**

   - supported function/assembly contract and runtime request pass, unrelated behavior
     remains correct; human-confirmed patches retain the confirming evidence.

   **Fail→:** leave a candidate for assisted RE, not a fabricated generic success.

   **Stop/next:** T-U62 exercises the explicit public `--native-tls reflutter-3.10.6-arm64` mode; `gate M6` joins T-U60/T-U61/T-U62 before release claims. Other functions and managed DLLs remain unsupported.

   **Interpretation:** Function success conventions are build-specific and cannot be inferred from a generic TLS name.

**DO:** separate routing, trust, native patching and self-integrity failures. **DON'T:** assume all
BoringSSL/Flutter versions use one signature or return convention.

## M7 — explicit gadget fallback

1. **Files:** optional gadget packager, dependency/ABI lock and detectability fixture.
   **Steps:**

   1. Add opt-in Frida gadget only for a named native case static methods cannot reach.
      Record runtime footprint/anti-Frida behavior, library packaging and target-device support.

   **Check:** `python scripts/acceptance.py run T-G70 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-G70.json`.

   **Pass:**

   - known request evidence and separately named gadget mode; ordinary patch paths do
     not inject a gadget or require its tools.

   **Fail→:** record fallback failure and use PLAN §8; no promise that gadget solves RASP.

   **Stop/next:** `gate M7` before exposing --gadget.

   **Interpretation:** Gadget results carry their own runtime footprint and compatibility scope.

**DO:** keep dependency optional. **DON'T:** select it silently or report static-mode success.

## M8 — verification automation and report presentation

1. **Files:** app-specific action hooks, proxy evidence adapters, human report renderer.
   **Steps:**

   1. Extend existing verification, not replace PLAN §7's schema/enums. Add one named real-app
      action at a time; manual triggers record endpoint/action/window/evidence explicitly. Keep
      triage confidence, patch status and runtime outcome independent. Add Burp/Caido adapters only
      when needed; the mitmproxy fixture remains the reference oracle.

   **Check:** `python scripts/acceptance.py run T-V80 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-V80.json`.

   **Pass:**

   - missing/unrelated/CONNECT-only traffic cannot become success; equivalent reports
     have stable semantic diffs; sensitive target payloads stay in operator-controlled artifacts.

   **Fail→:** preserve raw evidence and classify the action, rather than adding another status.

   **Stop/next:** `gate M8` for the specific adapters/actions delivered.

   **Interpretation:** Presentation consumes observed evidence; it cannot create a successful traffic observation.

**DO:** reuse existing acceptance contracts. **DON'T:** postpone basic evidence/verification until M8.

## Other deferred decisions

Static call-site anti-tamper rewriting is a separate partial mode with reflection/JNI/Binder gaps;
test receiver/null/range/exception semantics and helper footprint before adding its flag. User-store
trust and installer override need explicit behavior/provenance fixtures. Lower-target experiments
record both targets and behavioral/installation changes. None is a silent fallback.

Side-by-side rename needs its own work packet: resource/manifest edits, provider-authority and
permission collision handling, component/reference updates and package-name tamper fixtures.
Deep links, OAuth/API registration and backend identity can fail; renamed apps do not inherit
original private data. Do not introduce --side-by-side as a first-release data-recovery promise.

Runtime proxy reconfiguration is a later optional work packet. A non-debuggable app's private
files/repack-proxy cannot be written directly by ordinary adb shell; define a scoped delivery
mechanism before offering that feature. The baked endpoint remains the current implementation plan.
