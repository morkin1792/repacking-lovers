# M1a — bootstrap first, then the identity spike

Open only after M0 acceptance. Read PLAN §1/§3/§7/§8 and Architecture's A, bootstrap, hidden-access,
signing and build sections. Stay in M0's locked cell. Commands naming new scripts/cases below
become runnable only after the owning task implements them.
Execute tasks 1–2 first and accept BOOTSTRAP. The default schedule then runs the interception
track before returning to identity tasks 3–6. Identity inventory/T-A06 open only in task 3; they are not prerequisites for tasks 1–2. Do not introduce A dependencies in the
bootstrap-only build mode.

## 1. Manifest factory bootstrap (T-A01)

**Files:** `shim/src/dev/repack/shim/{RepackFactory,Bootstrap,Hidden}.java`, `repack/shim.py`,
binary manifest edit in `repack/rebuild.py`, `scripts/spike.py` and runner.

**Steps:**

1. Read the original binary manifest factory name. Compile our RepackFactory, Bootstrap and
   generated original-factory configuration against public android.jar. RepackFactory extends
   the public AppComponentFactory; its constructor calls idempotent Bootstrap.initEarly before
   constructing the original factory. Append helper DEX at the next contiguous classesN.dex index.
2. Set only android:appComponentFactory to dev.repack.shim.RepackFactory with a binary manifest
   attribute edit; retain other attributes/resource references. Pin the chosen manifest editor
   when implementing this task. This edit does not require a full resource-table rebuild.
3. Compose with the original factory loaded by name through the supplied app loader, falling back
   to the platform factory only when the original attribute was absent. Delegate instantiateActivity,
   instantiateApplication, instantiateProvider, instantiateReceiver, instantiateService and (API29+)
   instantiateClassLoader with the original arguments, result and exception semantics. Preserve a
   custom returned loader. The wrapper works with final original factories because it does not
   subclass them. Call initLate at instantiateApplication entry before delegating; routing belongs
   there, after the platform's proxy/NSC setup. Record ApplicationInfo paths at class-loader entry.
4. Test own/final/custom-loader/exception factories, the absent-factory platform fallback and
   the AndroidX CoreComponentFactory fixture flavor.
   Capture first launch and cold relaunch after recorded `cmd package compile -m speed -f PACKAGE`.
   Compare original DEX payloads/names, unedited ZIP contents, delegate markers and startup order.

**Check:**

```sh
python scripts/spike.py patch --input .work/inputs/original.apk \
  --out .work/outputs/bootstrap --key .work/keys/repack.p12 --mode bootstrap
python scripts/acceptance.py run T-A01 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A01.json
```

**Pass:**

- Wrapper early/late completion and delegate behavior appear once per PID in the expected order.
- Manifest factory resolves; original DEX entries are unchanged and helper indices contiguous.
- Own/final/AndroidX/custom-loader variants launch before and after compilation with matching
  component construction, returned loader and exception behavior.

**Fail→:** isolate binary-manifest, loader or delegation failure. Record the failed variant. The
separately tested shadow bootstrap is the fallback for --dex-only; its instructions live in
Architecture's bootstrap/DEX section and need their own T-A01 strategy result.

**Interpretation:** manifest bootstrap is the default. Shadowing remains for --dex-only and M3
class patches. Factory timing reduces the window; custom code can still run before late setup.

## 2. Build the signed no-identity-change control (T-A02)

**Files:** extend the shared `repack/rebuild.py`, digest-expectation scenario and runner. Reuse
task 1's minimal builder rather than adding a second ZIP/signing implementation.

**Steps:**

1. Sign the manifest-factory bootstrap round-trip with the persistent repack key, without A.
   Use explicit output names and never sign the original in place. For these owned fixtures, export
   the original signing certificate directly from its keystore, then verify it matches the APK:

   ```sh
   "$REPACK_TOOLS/apksigner" verify --verbose --print-certs .work/inputs/original.apk
   if ! test -e .work/inputs/original-cert.der; then
     "$REPACK_JDK/bin/keytool" -exportcert -alias original -keystore .work/keys/original.p12 \
       -storepass:file .work/keys/fixture.pass -file .work/inputs/original-cert.der
   fi
   sha256sum .work/inputs/original-cert.der
   "$REPACK_TOOLS/apksigner" verify --verbose --print-certs .work/outputs/bootstrap/patched.apk
   python scripts/acceptance.py run T-A02 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A02.json
   ```

   The DER hash must match the original APK's signer SHA-256 digest after normalizing hex formatting.
   Reuse existing exported DER only when its hash matches; never overwrite an unrelated artifact.
   This fixture needs no APK signing-block parser or apksig helper. General APK input extraction,
   including supported apksigner PEM output and verified history handling, belongs to M1b-3's P0.

   In the internal rebuild path, copy unedited ZIP entries using their original compression method.
   For target30+, resources.arsc must be STORED and four-byte aligned. Native .so entries must remain
   compatible with extractNativeLibs and their existing storage policy; compressed extracted libraries
   are not universally invalid. Remove obsolete signing artifacts, align, then sign. Use the modern
   alignment form in the internal pipeline, with separate fresh input/output paths:

   ```sh
   "$REPACK_TOOLS/zipalign" -P 16 -f -v 4 .work/outputs/bootstrap/unsigned.apk .work/outputs/bootstrap/aligned.apk
   "$REPACK_TOOLS/zipalign" -c -P 16 -v 4 .work/outputs/bootstrap/aligned.apk
   ```

   These are intermediate artifacts produced by spike.py, not commands to rerun against the signed
   output. The runner inspects compression/alignment before install and verifies the final signature
   after signing. Include an intentionally recompressed resources.arsc control that preflight rejects.
   This packaging contract is required in T-A02, even before native injection is implemented.

**Pass:**

- patched installed signer equals repack key and differs from original; unchanged
  direct/reflective self checks detect that mismatch, while unrelated-package results remain true.
  The fixture logs the mismatch and continues for measurement; it does not substitute expected data.

**Fail→:** if the negative control reports the original identity without A, repair the oracle or
artifact selection before proceeding. If install/launch fails, isolate rebuild from proxy behavior.

**Stop/next:** retain this control and run the new BOOTSTRAP gate:

```sh
python scripts/acceptance.py gate BOOTSTRAP --reports .work/evidence --out .work/evidence/BOOTSTRAP.json
```

It requires accepted M0 plus passing T-A01/T-A02 and minimal artifact/preflight records, without A
publication or bypass. Open M1b-5 now by default; identity task 3 is independently eligible.

**Interpretation:** The repack signer must remain externally visible without A; this negative control does not claim identity handling.

## 3. Establish the single pinned process-local access mode

**Files:** create `shim/.../PlatformAccess.java`; extend the selected API's inventory
(`tests/platform/api30-members.json` for the current phone; keep API35 observations separately).

**Steps:**

1. Pin one released AndroidHiddenApiBypass revision/artifact with hashes, Apache-2.0 license and
   required notices. Vendor the required helper classes/dependency closure, not just the named source
   file. Use the process-local exemption prefix "L" and record it; initialize it in initEarly before hidden access in
   identity-enabled builds. Keep bootstrap-only and initial routing builds without A free of this
   dependency; M1b-5 owns any explicit optional persistence experiment that also uses it.
   Keep one production access mode and claim only measured cells.

2. Complete the identity inventory below, then use its observed members to resolve ActivityThread and existing PackageManager
   references without substituting them yet. Distinguish ContextImpl's cached manager from the
   IPackageManager interface it holds. Capture actual classes/identities and available caches.
   Record ServiceManager/raw-Binder as separate acquisition paths.
   For the API-35 spike, capture sPackageManager as the primary real interface. Inspect known context
   fields without calling Context.getPackageManager to manufacture a new manager. The controlled
   factory fixture expects zero observed existing ApplicationPackageManager instances; record any
   nonzero result and its reachable context rather than asserting universal zero or scanning the heap.
   If sPackageManager is null, call ActivityThread.getPackageManager once to initialize/capture the
   real interface, then wrap that reference; do not warm public self-getPackageInfo to initialize it.
   Review T-A06's full descriptors and framework canaries before publishing the wrapper. Validate actual forwarding and framework canaries as the functional oracle.

3. Rerun the identity-only T-A06 probe with member/access/canary outcomes under the pinned
   process-local configuration. The scenario is now `identity-access`; keep this packet's `ordinary-probe`
   diagnostic immutable. Have the runner select the matching fixture build and report mode explicitly:

   ```sh
   python scripts/acceptance.py run T-A06 --scenario identity-access --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A06-identity.json
   ```

**Pass:**

- all members required by the selected first path are accessible, with original
  references captured. No optional-member exception is swallowed into a successful capability.

**Fail→:** remove an unnecessary optional dependency or repair use of the pinned implementation;
if required access/generation/forwarding still fails, stop A and apply PLAN §8. Keep the target/device policy and selected process-local implementation fixed during the trial.

**Stop/next:** freeze the measured access strategy before task 4. If it fails, identity remains
blocked/unsupported while accepted BOOTSTRAP and interception work remain usable.

**Interpretation:** ordinary T-A06 remains a diagnostic; functional acceptance covers only the
recorded process-local configuration and cell, without an ordinary-access release matrix.

### Identity inventory and ordinary diagnostics (T-A06)

**Files:** create `tests/platform/api30-members.json` and a release fixture probe class.

**Steps:**

1. For the current phone, download the API30 file from
   `https://dl.google.com/developers/android/rvc/non-sdk/hiddenapi-flags.csv` into
   `.work/inputs/api30-hiddenapi-flags.csv`. The rechecked SHA-256 is
   `a19d839f4f61dc9c94960ae977b2e0f3eb30f880ba1ffe5108e790010b477a56`;
   verify it rather than trusting the filename. Pin the platform source revision matching the test image as closely as
   available; note discrepancies. Inspect these starting points with full descriptors:
   `ActivityThread.sPackageManager`, `ActivityThread.currentActivityThread`,
   `ContextImpl.mPackageManager`, `ApplicationPackageManager.mPM`, `ServiceManager.sCache`,
   `ActivityThread.getPackageManager()`, `PackageManager.sPackageInfoCache`,
   `Proxy.sDefaultProxySelector`, `IPackageManager` method descriptors and applicable
   `PropertyInvalidatedCache` users. Record optional vs required-for-spike members.

   API30 getPackageInfo has descriptor `(Ljava/lang/String;II)Landroid/content/pm/PackageInfo;`
   and CSV flag greylist. Measure its ordinary access; a blocked API35 expectation does not apply.
   The following table is a separately verified API35 reference, not the current phone inventory.
   Its vic/non-sdk CSV hash is 40134e205e58922a708c453726b279a296e6a1f34a988abd90cec0f3432ea5a9:

   | Member | CSV policy flag | Ordinary probe expectation |
   |---|---|---|
   | IPackageManager.getPackageInfo(String,long,int) | blocked | Direct app reflection lookup is filtered; forwarding through that lookup cannot complete. Record the exact failed phase, not an implementation bug to chase. |
   | ActivityThread.sPackageManager | unsupported | Candidate for ordinary access; measure actual read/write behavior. |
   | ApplicationPackageManager.mPM | unsupported | Candidate for ordinary access; instance-final write behavior still needs testing. |
   | ActivityThread.getPackageManager() | unsupported | Candidate for ordinary access; record actual lookup/call. |
   | PackageManager.sPackageInfoCache | blocked | Ordinary direct lookup expected unavailable; optional clearing belongs to M1b-1. |
   | Proxy.sDefaultProxySelector | max-target-o (also lo-prio) | Ordinary direct lookup expected unavailable at target35; static-final persistence experiment remains separate. |

   The pinned process-local bypass is the selected functional access path for these members;
   measure its reachability and behavior in this identity packet/M1b, not as a preaccepted result. `unsupported`
   is an Android CSV flag here, distinct from PLAN §7's transformation status of the same name.

2. Create the CONTRACT inventory skeleton, then write the CSV-derived `expected_flags` and
   `csv_match` fields before running app probes. Record source/image mismatch explicitly. For a
   changed first API, fetch its official flag file into a separately named inventory; do not label
   it API35. For the current API30 cell, this command populates the API30 skeleton:

   ```sh
   python - <<'PY'
   import csv, hashlib, json
   from pathlib import Path
   needles = ('Landroid/app/ActivityThread;->sPackageManager:',
              'Landroid/app/ActivityThread;->currentActivityThread(',
              'Landroid/app/ActivityThread;->getPackageManager(',
              'Landroid/app/ContextImpl;->mPackageManager:',
              'Landroid/app/ApplicationPackageManager;->mPM:',
              'Landroid/os/ServiceManager;->sCache:',
              'Landroid/content/pm/PackageManager;->sPackageInfoCache:',
              'Landroid/net/Proxy;->sDefaultProxySelector:',
              'Landroid/content/pm/IPackageManager;->')
   flags = Path('.work/inputs/api30-hiddenapi-flags.csv')
   flags_sha256 = hashlib.sha256(flags.read_bytes()).hexdigest()
   if flags_sha256 != 'a19d839f4f61dc9c94960ae977b2e0f3eb30f880ba1ffe5108e790010b477a56':
       raise SystemExit('Wrong API30 flag-file hash')
   inventory = Path('tests/platform/api30-members.json')
   data = json.loads(inventory.read_text())
   if data['proxy_probe']['discovery'] != 'not-run':
       raise SystemExit('Preserve measured inventory; create a fresh revision before changing expectations')
   with flags.open(newline='') as f:
       rows = {row[0]: row[1:] for row in csv.reader(f) if row and row[0].startswith(needles)}
   members = {m['descriptor']: m for m in data['members']}
   for descriptor, expected in rows.items():
       m = members.setdefault(descriptor, {'descriptor': descriptor, 'role': 'inventory',
           'required': False, 'modifiers': None, 'ordinary_read': 'not-run', 'ordinary_write': 'not-run'})
       m.update(expected_flags=expected, csv_match='matched')
   for descriptor, m in members.items():
       if descriptor not in rows:
           m.update(expected_flags=[], csv_match='missing')
   data['members'] = [members[k] for k in sorted(members)]
   data['flags_sha256'] = flags_sha256
   inventory.write_text(json.dumps(data, indent=2) + '\n')
   print('Inventory written before runtime probes:', len(members))
   PY
   sha256sum .work/inputs/api30-hiddenapi-flags.csv
   ```

3. Run actual ordinary reflection read/write-access probes from
   the release fixture. A missing CSV match is an observation to investigate, not an allowed/blocked
   conclusion. Probe without changing live references; writes, if required to measure accessibility,
   use a fixture-owned sandbox object or write back the identical value and record it.
   Compile the fixture against public android.jar too: obtain hidden types with Class.forName and
   reflect using inventory descriptors, without imports of ActivityThread/IPackageManager or a
   hidden framework JAR. Record blocked direct getDeclaredMethod lookup as its negative subcheck.

4. Add a separate non-mutating probe to that release fixture: discover IPackageManager, enumerate
   its methods, call Proxy.newProxyInstance with its defining loader, and forward one known
   getPackageInfo query through the handler to the captured real interface. Select the actual
   String/int-flags/int-user descriptor from the API30 inventory (API35 widens flags to long). Publish/replace nothing.
   Log discovery, enumeration, generation, handler entry and forwarding separately, with actual
   returned signing digest checked against host truth. Run in a fresh probe process; later A tests
   must not reuse its frontend caches. Add `run T-A06` to the small runner with the `ordinary-probe`
   scenario. Use CONTRACT's event keys, descriptor query paths and intent extras.

   Record normalized full method descriptors, not just counts. Separate the published CSV inventory,
   app-visible interface enumeration and generated-proxy behavior; exclude fields/constructors,
   deduplicate inherited methods, and account for image/source differences. API35 ART treats Proxy
   specially in reflection-caller checks, so an app enumeration shortfall does not prove an incomplete
   proxy. Include getPackageInfo(String,long,int) and a framework-use canary such as getApplicationInfo
   in the inventory/forwarding probes. A generated proxy must survive the later post-publication
   createPackageContext path before claiming functional A support. Do not invoke arbitrary mutating
   interface methods merely to cover the inventory.

   On a separately tested API35 cell, expect the ordinary direct-method-lookup subcheck for its
   blocked getPackageInfo descriptor to fail. On API30, record its actual greylist lookup outcome. Keep this diagnostic ordinary; move functional access to the selected process-local case. Log generation and handler
   forwarding separately: a Method supplied by Proxy can follow a different access path from app
   getDeclaredMethod, so the CSV alone does not establish that every possible forwarding path
   fails. Any unexpected success records its actual acquisition path and image policy; it does
   not change the chosen process-local production mode.

   ```sh
   python scripts/acceptance.py run T-A06 --scenario ordinary-probe --device "$REPACK_SERIAL" --out .work/evidence/T-A06-ordinary.json
   ```

**Pass (observation task):**

- Inventory contains pre-probe CSV flags/hash/source revision, normalized descriptors and explicit
  missing matches; observed access is separate from the CSV-derived expectation.
- Every attempted phase records its outcome/exception. If forwarding succeeds, handler entry and
  the independently verified digest agree; if it fails, its verification remains failed.
- No injected reference replacement or bypass occurs; ordinary lazy initialization is recorded.
- Raw logs, fresh process/run identity and the complete T-A06 report are retained.
- Cell-specific expectations are explicit; an observed failed functional result stays failed
  while the complete ordinary observation task can pass.

**Fail→:** missing execution/unclassified evidence blocks the observation task. Record hidden
type/method failure at its precise phase rather than confusing it with Binder forwarding failure.
Keep this measurement free of exemptions. M1a task 3 uses the pinned process-local A mode regardless
of this diagnostic outcome; no ordinary-access production matrix is required.

**Stop/next:** proceed with complete observations, even if ordinary functional verification failed.

**Interpretation:** CSV flags and app-visible enumeration describe expectations/observations;
neither descriptor counts nor ordinary failure establish whether the configured A mode works.

Use the [official flag downloads](https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces).


## 4. Implement only the first signing path (T-A03)

**Files:** create `shim/.../PackageHandler.java` and generated `OriginalIdentity.java`;
extend `repack/shim.py`, `scripts/spike.py --mode identity`, and runner.

**Steps:**

1. Build the wrapper around the captured real interface for the selected cell. Use the API30
   String/int/int descriptor on the current phone and inspect its actual acquisition/cache paths;
   the pinned API35 cache/long-flags path below is a release-specific reference.
   Initially handle self `getPackageInfo` signing flags; forward every
   other method. Match method descriptor/argument contract and target package/user. Copy signing
   fields into a fresh result; preserve actual installed UID/paths and flags. The initial copy recipe
   is Parcel.obtain → original.writeToParcel(parcel, 0) → setDataPosition(0) →
   PackageInfo.CREATOR.createFromParcel(parcel), recycling in a finally block, then replacing public
   signatures/signingInfo on the copy. Verify non-signing field equality and installed paths; a
   successful parcel operation alone is insufficient. Unwrap InvocationTargetException and rethrow
   the original cause when forwarding. Do not fabricate a whole installed PackageInfo from an archive
   or mutate a shared result in place.
2. Publish the prepared wrapper in ActivityThread.sPackageManager before any shim self query.
   PackageManager.sPackageInfoCache recompute uses that reference. Patch mPM only on observed
   pre-existing ApplicationPackageManager instances; managers created later lazily capture the
   published interface. Existing-instance count is evidence, not a global heap claim.
   Publish before the shim performs any self query, keeping real-signer frontend entries out of setup. Read fixture
   identity from embedded host-verified data. T-A03 does not deliberately prewarm a self signing
   entry and does not require cache clearing. Capture the first self query after publication and
   require its descriptor/package/flags/user to reach the handler. Also test
   createPackageContext/getApplicationInfo after publication. An unexpected cache hit is a recorded
   scenario failure to investigate; observe earlier framework/custom-factory caches independently
   or silently clear the cache to manufacture the first-query observation. Deliberate prewarming,
   existing results and an optional one-shot scoped clear belong to M1b-1. Use the observed long-flags
   descriptor without narrowing to int; method name alone
   does not establish overload or argument correctness.

3. For the API35 cell, use public populated SigningInfo construction from verified original
   metadata as the bounded initial implementation. Generate public keys from the certificates and
   test legacy/current flags. No hidden SigningDetails constructor or universal API adapter is needed.
   If the first execution cell is API28–34, run M1b-1 task 3 / T-A16 after task 3's access probe and
   before this signing scenario; use its accepted metadata adapter instead. This is the named
   early subpacket, not acceptance of the full M1b-1 gate or a call to a missing API35 constructor.
   Add null/error forwarding and preserve original exception causes. Do not handle installer,
   hasSigningCertificate/checkSignatures, fresh Binder stubs or JNI yet; M1b owns those cases.

   ```sh
   python scripts/spike.py patch --input .work/inputs/original.apk \
     --out .work/outputs/identity --key .work/keys/repack.p12 --mode identity
   python scripts/acceptance.py run T-A03 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A03.json
   ```

**Pass:**

- actual installed signer still equals repack key; self direct/reflective observed
  digests equal original verified certs; other-package digests equal the unrelated app's true certs.
  Both paths agree on preserved installed non-signing fields. The host runner checks all comparisons.
  Framework-use canaries must complete without AbstractMethodError or a missing handler path. Compare
  the actual supported descriptors and behavior, not CSV row-count equality. Functional evidence
  uses the pinned process-local mode; the ordinary diagnostic is not a second required support run.

**Fail→:** retain method descriptor, receiver/reference class, flags, process and error. Repair
scope/access/copying within the selected path first; exhausted architecture failure invokes §8.

**Stop/next:** no broader APIs or cells until T-A03's controls pass.

**Interpretation:** First-query handler entry proves the controlled acquisition path; prewarmed and already-returned objects are later contracts.

## 5. Prove failure transparency (T-A04)

**Files:** extend Bootstrap/PlatformAccess and runner with a fixture-only failure injection.

**Steps:**

1. Force one recoverable initialization failure before publication. Verify forwarding or
   rollback leaves real references usable and that the capability reports failure, never completion.
   Include absent-package exceptions and unrelated calls. Failure injection belongs only to fixture
   builds and is not a public toolkit flag.

   ```sh
   python scripts/acceptance.py run T-A04 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A04.json
   ```

**Pass:**

- no partial accepted proxy state, host app can complete its diagnostic scenario,
  failure event is explicit, actual signer remains observable, exception contract is preserved.

**Fail→:** fix publication/rollback boundaries; do not suppress all errors and print success.

**Stop/next:** proceed to metadata experiment only after failure behavior is evidenced.

**Interpretation:** A failure event and usable original references prove this recovery case, not arbitrary rollback after partial publication.

## 6. Measure framework-parsed metadata independently of B (T-A05)

**Files:** add `shim/.../OriginalArchive.java` and fixture archive-parser scenarios.

**Steps:**

1. Carry the original fixture APK as retained bytes in the patched artifact, copy it to
   app-private storage after a valid context exists, verify its host-recorded hash, then call
   `getPackageArchiveInfo(path, GET_SIGNING_CERTIFICATES)` and legacy flags. Do not redirect any
   installed sourceDir read. Record provisioning time and parsed metadata. Checks scheduled before
   the context phase continue using task 4's embedded public metadata in this first cell. Schedule
   the context-dependent experiment with a main-looper post from initLate, explicitly obtain and
   validate a usable Application/context when it executes, and record its order against attach,
   providers and onCreate. Posting does not establish readiness before those synchronous startup
   callbacks; any earlier integrity check remains unsupported by this provisioning path.

   ```sh
   python scripts/acceptance.py run T-A05 --device "$REPACK_SERIAL" --replace-existing-and-wipe-data --out .work/evidence/T-A05.json
   python scripts/acceptance.py gate M1a --reports .work/evidence --out .work/evidence/M1a.json
   ```

**Pass:**

- exact byte/hash equality and parsed current signer set match host verification, or
  an explicit recorded parse limitation. The experiment must state availability before/after each
  check and make a concrete recommendation for M1b-1. Completion of an experiment is not acceptance
  of a missing metadata capability (CONTRACT). Keep this experiment scoped to archive parsing.

**Fail→:** fix provisioning/hash/flags first; if parsing cannot supply required metadata, retain
the API-35 public-construction result and record the unsupported extension for M1b-1.

**Stop/next:** accept M1a identity completion only with the functional identity evidence and
metadata experiment record. Continue to M1b-1. BOOTSTRAP/interception opened after task 2 already;
keep bootstrap/interception eligibility independent of tasks 3–6 and public CLI integration.

**Interpretation:** Archive parsing at the observed context phase does not establish metadata availability before providers or onCreate.

## DO / DON'T

DO retain the failing no-A control and compare fixture results to host/package state. DON'T add
network forcing, JNI, new API cells, split installs, raw Binder wrappers, B, native libraries,
gadget, resource edits, public CLI flags or a generalized report framework here.
