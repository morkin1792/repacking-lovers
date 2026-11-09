# Acceptance command and evidence contract

Shared rules/enums live in [PLAN.md §1/§7](../../PLAN.md). Commands below are interfaces to
implement where their gate has not opened. M0 commands are implemented; progress links their observations.

## Minimal runner

M0 creates one standard-library `scripts/acceptance.py`, one ordinary function per case and a
small dispatch table; no case hierarchy/plugin loader/workflow engine. Initially implement `host`,
`device`, and `run T-A00`; add `gate` after the reports exist. Add later case handlers only when
their task opens. Run from repository root; `python` means Python 3.

```text
python scripts/acceptance.py host --out .work/evidence/M0-host.json
python scripts/acceptance.py device --device SERIAL --out .work/evidence/M0-device.json
python scripts/acceptance.py run CASE_ID --device SERIAL --out .work/evidence/CASE_ID.json
python scripts/acceptance.py gate GATE_ID --reports .work/evidence --out .work/evidence/GATE_ID.json
```

T-A06 additionally requires `--scenario ordinary-probe` in M1a task 3 before bypass or `--scenario identity-access` in
M1a. The runner selects the matching unmodified-policy or pinned process-local fixture build;
it never infers this choice from a mutable progress document. Both use the same case ID and
retain separate immutable reports. Other cases add scenario parameters only when their task needs them.

`host` inventories files/versions/hashes, source-control state and KVM access without installing.
`device` reads only selected
device properties. `run` executes the case and R-INSTALL preflight before any write, captures raw
logs, and compares against that case's contract. `gate` checks the configured corpus/source/tool
hashes and each case's named cell; it does not rerun cases or accept stale reports. Multi-cell
gates retain a child report per cell. Cases need not share a run ID; the gate records their
immutable report paths and hashes.

Every invocation creates immutable `.work/evidence/runs/<run-id>/` artifacts. `--out` is an
atomically updated summary/index, not permission to overwrite raw evidence. A T-A01 rerun in a
later task preserves the earlier observations as well as the new ones.

`run` also accepts `--replace-existing-and-wipe-data` for only its inventoried fixture packages
on the selected test device. Examples that switch identities include this flag; without it,
a signature mismatch blocks installation. T-P11's deliberate negative control must still invoke
the installer without authorization internally. Never extend fixture authorization to user apps.

Print one summary (`PASS`, `FAIL`, `INCONCLUSIVE`, or `BLOCKED`) followed by the case/gate ID and
JSON path. These summaries map to PLAN §7 rather than creating new report enums. Return 0 for PASS and explicitly NOT-RUN cases; NOT-RUN never accepts a gate. A missing prerequisite leaves verification not-run; ambiguous observations are
inconclusive. A build/install/launch exit code alone cannot yield PASS.

## Paths and variables

M0 creates ignored `.work/` for local artifacts/tools/keys/evidence. Fixtures live in
`tests/fixtures/identity/`, with `app` and `other` modules. Packages are
`dev.repack.fixture.identity` and `dev.repack.fixture.other`; use Java and an ordinary Activity.
Choose scenarios through explicit intent extras. Only fixture launch components need exporting.

```sh
export REPACK_SDK="$HOME/Android/Sdk"
export REPACK_JDK="/usr/lib/jvm/java-27-openjdk"
export REPACK_TOOLS="$REPACK_SDK/build-tools/36.0.0"
export REPACK_ADB="$REPACK_SDK/platform-tools/adb"
export REPACK_SERIAL="THE_SELECTED_SERIAL"
```

Use the JDK resolved by the host report; the current Arch path is shown above. M0 resolves it and
stores non-secret paths/versions in `config/implementation-lock.json`. Set `JAVA_HOME` only for
individual tool commands; do not change shell profiles/system JDK. Select SERIAL from
`adb devices -l`, never assume `emulator-5554`.

Build original and repack artifacts into separate directories. Fixture original/unrelated/repack
keys differ. Keep credentials in local environment/password files, never printed reports.

## Gate ledger

| Gate | Required evidence |
|---|---|
| M0 | Host/device/primitive-build/T-A00 pass; no hidden-member inventory or T-A06 prerequisite |
| BOOTSTRAP | M0 accepted; T-A01 early/late hooks and T-A02 signed ZIP round-trip pass |
| M1a | BOOTSTRAP; pinned process-local identity access/forwarding, T-A03 first-query/framework canaries, T-A04 failures, T-A05 metadata experiment |
| M1b-1 | T-A10 signing/installer/list queries, T-A11 cache/results; conditional T-A16 for an API28–34 first/release target |
| M1b-2 | T-A12 JNI-to-Java, T-A13 fresh Java stub/raw transaction control |
| M1b-3 | T-P10 splits, T-P11 install/key lifecycle, T-P12 artifact/report/CLI |
| M1b-4 | T-A14 processes/startup, T-A15 release matrix |
| M1b-5 | T-N10 startup route and T-N12 control/cleanup pass; T-N11's measured transition scope |
| M2 | T-T19 resource screening report; T-T20 NSC variants and T-T21 anchors/pins pass on the first cell |
| M2-CT | M2 plus T-T22 on its additional API36 cell, only for corresponding CT claims |
| M2-DEX | M2 plus T-T23 in distinct runtime-nsc mode; optional, not a prerequisite of M3 or resource-nsc RELEASE-1 |
| M3 | T-U30 Java fixtures, T-U31 optimized builds, T-U32 ambiguity/control |
| RELEASE-1 | Both tracks accepted, with signing and HTTPS regressions on every claimed release cell |
| M4 | T-B00 import smoke, T-B01 original reads, T-B02 patched runtime, T-B03 native packaging, T-B04 public opt-in and default regressions |
| M5 | T-I50 actual/offline APKS targeting, explicit selected XAPK, refusals and public runtime |
| M6 | T-U60 exact Flutter/reFlutter request, T-U61 function/build refusals, T-U62 public default-off/opt-in |
| M7 | T-G70 explicit gadget mode |
| M8 | T-V80 action/evidence presentation |

Subchecks record expected/observed values individually. Identity inventory and ordinary T-A06
belong exclusively to M1a task 3. Its ordinary diagnostic failure stays failed while functional
A acceptance uses the pinned process-local mode with prefix ["L"]. CSV descriptors/flags and
runtime behavior are distinct observations; neither inventory nor bypass is part of M0.

T-N11 may record unsupported transitions while M1b-5 accepts named startup-only routing for
controlled M2 requests. Failed comparisons stay failed; missing execution or a broken startup
route cannot pass the gate. Do not infer persistence from startup acceptance.
T-N12's fresh proxy-down request must fail with no controlled-origin token observed for each
claimed covered client. Wireless-adb and reachable-remote cells are optional and separately named;
their absence does not erase this reference-path negative control or imply mobile-data support.

T-A05 can complete its experiment by
documenting an unavailable parse case; that is not acceptance of the missing capability. M1b-1
decides supported metadata cases. A documented limitation never becomes generic support.
An API28–34 first/release target activates T-A16 in M1b-1 task 3. It may run after M1a task 3's
access probe before full M1a solely to unblock a selected legacy initial signing path. T-A16 acceptance
alone does not accept M1b-1; T-A10/T-A11 and M1a remain required. If no API28–34 target is selected,
record the inactive condition rather than build speculative API adapters.

Eligibility follows PLAN §5's graph, not numeric row order. M1b-5/M2/M3 use BOOTSTRAP's
build, fixture preflight and minimal report helpers without waiting for M1b-3's public CLI/schema.
RELEASE-1 records both tracks' report hashes and reruns relevant signing and marked HTTPS cases
on each claimed production/physical cell. Later extensions require that release join.

## Fixture oracle and evidence

Emit one JSON object per log line under `REPACK_FIXTURE` or `REPACK_SHIM`, using the exact v1
keys below. Keep every key; use null for unavailable scalars and [] for an unperformed signer
query. Reject malformed/missing fields in the runner rather than guessing a successful event.
Pass a unique run token in intents/requests; preserve startup logs before filtering. Do not clear unrelated device logs.
Cross-check fixture results against host signing data, actual device package state/output hashes
and/or proxy captures. The original fixture works without the shim and is not its own sole oracle.

Signer digest means SHA-256 over each actual `Signature.toByteArray()`, encoded as 64 lowercase
hex characters without colons. For ordinary X.509 signatures these are certificate DER bytes;
this is not an APK hash, TLS SPKI pin or digest of a printed fingerprint. Compare current signer
sets after sorting/deduplicating. Preserve history ordering separately when M1b-1 introduces it.
The host obtains expected signer bytes from verified fixture artifacts/keystores independently.

### Fixture events and query paths

```json
{
  "schema_version": 1, "run_id": "EXAMPLE_NOT_EXECUTED", "case_id": "T-A03",
  "pid": null, "process": null, "event": "query", "scenario": "identity",
  "query_path": "direct-current", "package": "dev.repack.fixture.identity", "flags": 134217728,
  "actual_signer_sha256": [], "expected_signer_sha256": [], "comparison": "not-run",
  "response_marker": null, "error_class": null
}
```

`event` is query, response, marker or failure; `comparison` uses the verification enum. A query
exception records its class and failed comparison, not an empty signer-set success. Marker and
response events leave query-only fields null/empty. Expected digests never populate actual fields.

| query_path | Actual fixture operation | Opens in |
|---|---|---|
| direct-legacy | getPackageInfo(package, GET_SIGNATURES), then PackageInfo.signatures | M0 |
| direct-current | getPackageInfo(package, GET_SIGNING_CERTIFICATES), then signingInfo.getApkContentsSigners() | M0 |
| reflect-legacy | Method.invoke of the public String/int getPackageInfo overload, then signatures | M0 |
| reflect-current | Method.invoke of the same public overload with GET_SIGNING_CERTIFICATES, then getApkContentsSigners() | M0 |
| jni-legacy / jni-current | JNI calls the matching Java PackageManager path and extracts its actual result | M1b-2 |
| list-installed-legacy / list-installed-current | getInstalledPackages with the corresponding signing flag; locate self and unrelated PackageInfo entries | M1b-1 |
| list-permissions-legacy / list-permissions-current | getPackagesHoldingPermissions for the shared normal fixture permission and signing flag; inspect returned entries | M1b-1 |

Run each active path for self and unrelated package; M1b-1 adds typed flags, history and signing
predicates as named cases. Record the observed backend descriptor separately from these public
paths, including API35's String/long/int IPackageManager getPackageInfo contract.

For the scalar signing scenario, launch extras are exactly `run_id`, `case_id`, `scenario`, `query_path`, `query_package`, and
`expected_signer_sha256` (comma-separated normalized signer digests). The runner supplies the last
value from host truth; the fixture validates syntax and compares it only after querying. Invalid
or absent required extras fail the scenario. Example after the runner has prepared these values:

```sh
"$REPACK_ADB" -s "$REPACK_SERIAL" shell am start -W \
  -n dev.repack.fixture.identity/.ProbeActivity \
  --es run_id "$REPACK_RUN_ID" --es case_id T-A03 --es scenario identity \
  --es query_path direct-current --es query_package dev.repack.fixture.identity \
  --es expected_signer_sha256 "$REPACK_EXPECTED_SIGNERS"
```

The wrong-expected baseline control changes only the expectation, never the query or actual
digest. Its failed comparison is the expected negative-control observation, not overall success
without the runner checking both values against host truth.

### Signing-contract and cache packets

T-A10 uses `scenario=contract` and `contract_json`, a JSON array of `{id, operation, ...}`.
Operations are predicate-package/predicate-uid (package, base64 certificate or null, certificate_type),
compare-package/compare-uid (package, other_package, optional explicit UIDs), metadata (package, flags),
list-installed/list-permissions (flags), and installer (package). Actual results live in the existing
response_marker as JSON `{id, operation, value}`. List responses also carry list_count and
list_order_sha256: SHA-256 of all returned package names in order, UTF-8 with a newline after each.
Only the two fixture entries' metadata is emitted; unrelated app names are not included.
Exception events retain the actual error_class. The host compares these with genuine signed
reference installations, then joins each signed-list result to the shim operation/list_flags
and the Binder container's count/order. Reference installations use cryptographically verified
single, multi-v2 and rotated-v3 APKs. The public metadata-only controls contain no bypass dependency.

T-A11 uses a fixture-only deferred-publication asset plus `scenario=cache-state` for the Activity.
Provider observations use query_path before/publication/after and the Activity emits state.
response_marker contains measured snapshots, counters and installed fields. Cached-hit support
requires an observed hit; an unset/disabled nonce is recorded as a limitation. Publication patches
an explicitly supplied existing manager and the primary static reference. A one-shot cache clear
is process-local. Already-returned PackageInfo objects retain their original content. Compatible
same-key update checks include private sentinel, UID, fresh PID, changed original hash and changed
signing metadata. Normal bootstrap has no deferred-publication asset and publishes early.

### Shim events

T-A14 uses `scenario=process`, `run_id`, and `process_role=main|remote|isolated`.
The foreground Activity binds the selected service; each process emits its own13 query events:
six direct/reflection/JNI self/other paths plus a missing-package control. The host compares
actual digests and exceptions against genuine fixture installations and independently checks
installed UID/source/version. Process UID, loader, native ABI and X.509-provider invocation count
are JSON fields inside response_marker. Main/remote runs are restarted independently; isolated
process names include Android's service-class suffix and use a distinct isolated UID. A restricted
genuine baseline permits only an equivalent-error claim for that path. App-local provider and
caller-array mutation controls check that the private signing template never escapes. Forced
Binder failure occurs after actual cache publication, with cache/PM restoration verified before
ordinary queries. These are fixture observations, not claims about external/GMS/WebView processes.
T-A14 extends scalar getPackageInfo to those observed processes. Predicate, list and fresh-Binder
operation claims retain T-A10/T-A13's main-process scope; their success is not inferred in services.

```json
{
  "schema_version": 1, "run_id": null, "case_id": null, "pid": null, "process": null,
  "event": "entry", "phase": "initEarly", "access_mode": "none", "packaging": "shadow",
  "descriptor": null, "endpoint": null, "reference_replaced": false, "error_class": null,
  "details": {}
}
```

`event` is entry, complete, forward or failure; `phase` is initEarly, initLate, context or query.
`access_mode` is none, ordinary-diagnostic or process-local-bypass; other named fallback modes
are introduced only by PLAN §8's separate experiment. `packaging` is manifest, shadow or rewrite.
`endpoint`, when present, is an object with host and port. Query details contain package, flags
and user; access details identify the member/prefix and outcome. Record actual exceptions and
replacement state. A complete event denotes completed capability setup, not just method entry.
Bootstrap details record early_hook (manifest-factory, factory-clinit, factory-classloader or application-ancestor)
and the observed loader/path metadata for the alternate hook. Trust events record trust_mode
(resource-nsc or runtime-nsc) and publication state; capability completion is per component, not
an extra bootstrap completion. connectFailed events use failure/query with endpoint/error details
without implying that every client's failure invokes that callback.
Do not log certificate private keys, keystore passwords or target payloads.

Early hooks run before Activity intent extras exist. Keep run_id/case_id null until legitimately
available; never invent a startup token. The host joins startup events to the freshly launched
PID/process, launch window and installed artifact hash, then to the fixture's intent token.
Retain full logs and ordering evidence; an old init event cannot satisfy a current run.

On a gate failure retain raw logs/reports, update progress with the smallest failing case, and
stop dependent tasks. Fix mistakes within the current experiment first, then follow its named
branch. Exhausted architecture branches invoke PLAN §8; missing tools/devices block acceptance.

## Minimal JSON examples

These are valid shape examples, not checked-in configuration or observed results. Replace EXAMPLE
values/null measurements only with actual data. Extend fields when the active gate needs them;
M1b-3 freezes the public schema. Schema validity alone cannot satisfy functional acceptance.

`config/implementation-lock.json`:

```json
{
  "schema_version": 1,
  "cell": {"id": "api35-target35-x86_64", "api": 35, "target_sdk": 35, "min_sdk": 28, "abi": "x86_64", "page_size": 4096},
  "build": {"jdk_major": 27, "java_release": 8, "compile_sdk": 36, "target_sdk": 35, "build_tools": "36.0.0"},
  "sdk_path": "EXAMPLE_RESOLVE_LOCALLY",
  "tools": {},
  "identity_access": {"mode": "process-local-bypass", "revision": null, "sha256": [], "license": "Apache-2.0", "prefixes": ["L"]},
  "image": {"revision": null, "fingerprint": null, "ro_debuggable": null},
  "release_target": {"serial": null, "api": null, "abi": null, "page_size": null, "availability": "not-run"},
  "measurements_complete": false
}
```

Each resolved tool needs version, absolute path, SHA-256 and launch outcome. Image properties
come from the actual device/image, not the selected cell name.

`tests/corpus.json`:

```json
{
  "schema_version": 1,
  "fixtures": [{"id": "identity-original", "package": "dev.repack.fixture.identity", "apk": ".work/inputs/original.apk", "sha256": null, "signer_sha256": []}],
  "cases": [{"id": "T-A00", "fixture": "identity-original", "oracle": "host-exported-cert-and-apk-signer", "expected": "self-and-other-match-their-own-original-identities"}],
  "source_revision": null
}
```

`tests/platform/api35-members.json`:

```json
{
  "schema_version": 1,
  "api": 35,
  "aosp_revision": "android-15.0.0_r1",
  "flags_sha256": null,
  "members": [{"descriptor": "Landroid/app/ActivityThread;->sPackageManager:Landroid/content/pm/IPackageManager;", "role": "primary-swap", "required": true, "modifiers": null, "expected_flags": [], "csv_match": "not-run", "ordinary_read": "not-run", "ordinary_write": "not-run"}],
  "proxy_probe": {"case_id": "T-A06", "discovery": "not-run", "direct_lookup": "not-run", "enumeration": "not-run", "generation": "not-run", "forwarding": "not-run", "references_replaced": false}
}
```

Access/probe outcomes use the verification enum. Record exceptions, declaring class, modifiers
and full descriptors in observations. Populate expected_flags from the CSV before probing;
csv_match is not-run, matched or missing. An empty expected_flags list is not proof of unrestricted access.
Record discrepancies between the source revision and actual image explicitly.
Add normalized descriptor sets, inventory differences, phase completion and the diagnostic or
pinned functional mode ID when executing T-A06. These are measured observations, not a count-based
completeness proof. Retain distinct scenario reports, not two ordinary/process-local support matrices.

Evidence JSON, using PLAN §7's existing enums:

```json
{
  "schema_version": 1, "run_id": "EXAMPLE_NOT_EXECUTED", "case_id": "T-A06",
  "cell": {"api": 35, "target_sdk": 35, "min_sdk": 28, "abi": "x86_64", "page_size": 4096, "fingerprint": null, "ro_debuggable": null},
  "process": {"name": null, "pid": null}, "inputs": [], "outputs": [], "signer_sha256": [],
  "command": {"argv": [], "exit_status": null},
  "transformation": "skipped", "verification": "not-run", "enforcement": "unknown",
  "comparisons": [], "prerequisite_failures": [], "device_mutations": [], "cleanup": [],
  "logs": [], "evidence_refs": []
}
```

Executed comparisons include expected/observed values, result and independent oracle. Nulls and
empty collections above are deliberate unexecuted examples, never evidence of a passing case.

### Resource screening row and stage counts

T-T19 adds rows to corpus evidence, not a new report framework. Use the existing transformation/
verification enums; a stage result never implies completion of a later stage:
Append later insertion/runtime observations as new per-run records referencing the screening
report; preserve accepted/raw artifacts rather than editing their results in place.

```json
{
  "input_id": "EXAMPLE_NOT_EXECUTED", "members": [],
  "engine": {"name": "apktool", "version": null, "sha256": null},
  "stages": {"rebuild": "not-run", "insertion": "not-run", "install": "not-run", "launch": "not-run", "https": "not-run"},
  "logs": [], "prerequisite_failures": [], "fallback_reason": null
}
```

For each stage report selected, attempted, passed, failed, inconclusive and not-run counts;
pass rate is passed/attempted, with attempted = passed + failed + inconclusive. A zero denominator
is null, not 100%. List excluded/not-run inputs and reasons. Retain immutable input-member hashes
and stage logs, plus whether the row is a single APK or a validated selected split set.

## Minimal module interfaces

Create only the active row's functions. Implemented rows below describe the actual callable boundary; consult the function declaration for explicit keyword options. Use ordinary functions, pathlib paths and JSON-compatible
dict/list values; do not add service classes, adapters or schema generators for this table.
Return dictionaries carry PLAN §7's statuses and evidence paths. A path means a local filesystem
path, and functions never install unless they belong to verify. Read tool paths from the explicit
lock dictionary, not assumed executables on PATH.

| Module | Initial function signatures | First task |
|---|---|---|
| repack/rebuild.py | `copy_archive(original, unsigned, replacements=None, additions=None) -> list[dict]`; `align_sign(unsigned, out, key, lock, evidence) -> None` | implemented SDK/ZIP primitives |
| repack/shim.py | `build_bootstrap(original, out, key, lock, evidence, **explicit_options) -> dict` | implemented manifest factory; identity/routing options |
| repack/shim.py | `parse_proxy(endpoint: str) -> dict` returning normalized host/port under PLAN §6 | M1b-5; reused by M1b-3 CLI |
| repack/verify.py | `preflight(artifact, serial, replace_existing, lock, evidence, label) -> dict`; `install(artifact, serial, plan, lock, evidence, label, mutations) -> None` | implemented fixture-only path; M1b-3 generalizes it |
| repack/trust.py | `apply_trust(original: Path, ca: Path, out: Path, lock: dict) -> dict` | M2 |
| repack/patches.py | `find_candidates(inventory) -> dict`; `patch_apk(original, out, key, lock, evidence) -> dict` | implemented M3 shadow definitions |
| repack/recon.py | `inspect_input(input_ref: str, serial: str | None, lock: dict) -> dict` | M1b-3; earlier calibration uses only its needed subset |
| repack/report.py | `write_report(report: dict, out: Path) -> None` | M1b-3; earlier scripts use stdlib JSON directly |
| repack/pipeline.py | `patch(input_ref: str, options: dict, lock: dict) -> dict` | M1b-3 |
| repack/cli.py | `main(argv: list[str] | None = None) -> int` | M1b-3 |

`build_bootstrap` returns manifest packaging, original factory, appended DEX, preserved entry
hashes and selected public configuration. `patch_apk` returns shadow descriptors, contiguous
original-entry mapping and payload hashes for M3. `copy_archive` preserves unedited payloads and
ZIP storage; resource-engine rebuilds use the same align_sign stage. If a rewrite fallback is accepted, add its one named
function then; do not implement a generic backend interface in advance. Preconditions/evidence
must bind install to the same selected serial and unchanged artifact hashes; caller-made PASS
strings are not preflight authorization. `key` holds local credential references, never log values.

## Owned fixture keys and certificate truth

Run only as implementation tasks after validating REPACK_JDK. Preserve existing keys. This local
password setup prints no secret; these fixture identities are separate from production keys.

```sh
umask 077
mkdir -p .work/keys .work/inputs
python - <<'PY'
from pathlib import Path
import os, secrets
p = Path('.work/keys/fixture.pass')
if not p.exists():
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(secrets.token_urlsafe(32) + '\n')
PY
for REPACK_KEY_NAME in original other repack; do
  if test -e ".work/keys/$REPACK_KEY_NAME.p12"; then
    continue
  fi
  "$REPACK_JDK/bin/keytool" -genkeypair -alias "$REPACK_KEY_NAME" -keyalg RSA -keysize 2048 \
    -validity 3650 -storetype PKCS12 -keystore ".work/keys/$REPACK_KEY_NAME.p12" \
    -dname "CN=Repack fixture $REPACK_KEY_NAME" \
    -storepass:file .work/keys/fixture.pass -keypass:file .work/keys/fixture.pass
done
if ! test -e .work/inputs/original-cert.der; then
  "$REPACK_JDK/bin/keytool" -exportcert -alias original -keystore .work/keys/original.p12 \
    -storepass:file .work/keys/fixture.pass -file .work/inputs/original-cert.der
fi
sha256sum .work/inputs/original-cert.der
```

Before reuse, verify existing key aliases/credentials instead of replacing keys/passwords after
an error. An existing exported DER is reused only if its hash matches. Match DER hashes against
apksigner's signer digests for all fixtures, including other; the three identities must differ.
General arbitrary-APK extraction belongs to M1b-3 P0, not this fixture-specific keystore path.
See the [keytool contract](https://docs.oracle.com/en/java/javase/17/docs/specs/man/keytool.html).

## Manual log capture

The runner owns durable per-run capture. For manual inspection, start full capture before fixture
launch in a separate terminal, using a new evidence directory:

```sh
export REPACK_LOG_DIR="$(mktemp -d .work/evidence/manual.XXXXXXXX)"
"$REPACK_ADB" -s "$REPACK_SERIAL" logcat -v threadtime > "$REPACK_LOG_DIR/startup-full.log"
```

Stop capture with Ctrl-C after the case. A second terminal can display selected tags:

```sh
"$REPACK_ADB" -s "$REPACK_SERIAL" logcat -v threadtime \
  -s REPACK_FIXTURE:I REPACK_SHIM:I '*:S'
```

Do not use filtered display as the only evidence or clear unrelated logs. Correlate by fresh
run/case token, PID/process and timestamps; old log messages are not current observations.

## RELEASE-1 join

Implement this gate handler only when both tracks are accepted. The command is:

```sh
python scripts/acceptance.py gate RELEASE-1 --reports .work/evidence --out .work/evidence/RELEASE-1.json
```

Require accepted M0, BOOTSTRAP/M1a, M1b-1 through -5, M2 and M3 against current source/tool locks.
M2-CT is required only for matching API36 CT claims; API35 acceptance does not wait for an API36
image. M2-DEX is required only if runtime-nsc trust is explicitly included in the release claim;
it does not substitute for resource-nsc results. Selected legacy target claims require T-A16 and the normal
signing regressions on that cell. Carry narrower routing transition and list-query scope into
the release claim explicitly.
Each claimed release cell needs fresh relevant signing and HTTPS/Java-pinning regression evidence;
do not join an emulator-only interception result to an unrelated physical-device signing result
and call that combined physical support. Capture per-capability scope and excluded cells. If a
claimed cell is missing evidence, block release or explicitly revise its declared scope before
acceptance. The earlier API35 HTTPS proof remains valid for its own controlled cell.

## Execution glossary

M4's public T-B04 packet joins module-off/on builds on ARM32 and ARM64. It uses the actual public
patch/verify path, requires constructor and imported-read hashes to match host original truth,
checks setup before the original factory in the same captured PID, preserves input ABI selection,
and exercises A/Java/split composition on ARM64. Bad caller names, missing callers, platform
callers and callers without supported imports must fail without output or device mutation.
The native module registers future-load import tasks: an armed state with pending libraries is
setup evidence, not an observed byte-read success. Public runtime verdicts remain independent.
Gate M4 also requires current T-A03/T-P12 regressions. Its bounded native scope does not replace
the frozen RELEASE-1 packet or widen any untested API/firmware/page-size claim.

`--integrity native-base-bytes:libCaller.so[,libOther.so]` is the accepted interface only after M4
passes. Original storage uses a marked private namespace, hash verification, atomic publication,
a one-GiB base limit, a free-space guard and cleanup of the module's prior hash-named archives.
Normal processes can provision from ApplicationInfo.sourceDir/dataDir before the original
factory runs; isolated-process storage and unknown loader namespaces are excluded.

- Scope/install/key/input/evidence/failure rules are PLAN §1's canonical rules; tasks refer to IDs.
- BLOCKED means a missing prerequisite; FAIL means an observed mismatch. Neither is a success.
- A source/CSV/build/init event supports only that observation; runtime claims require their oracle.
- Add at most three explicit DON'T prohibitions per task; put shared restrictions here/PLAN §1.
- Fixture cleartext is restricted to its controlled origin; target NSC policies remain P1's work.
- Source `. /home/water/workspace/Projects/pentest/tools/configure` before ADB discovery/commands.
  The configured ADB server sees the phone; an unconfigured local server can report no devices.

## Proxy oracle and early logs

M1b-5 creates scripts/mitm_oracle.py. Its request hook writes JSONL keys token, host, path, tls
and returns HTTP200 application/json `{"token": "TOKEN"}` for `/repack/TOKEN`. `tls` is actual client-side TLS
establishment; CONNECT alone is not a request observation. Use a new immutable log per run:

```sh
export REPACK_ORACLE_LOG="$REPACK_LOG_DIR/proxy.jsonl"
mitmdump --listen-host 127.0.0.1 -p 8080 -s scripts/mitm_oracle.py --set connection_strategy=lazy --set upstream_cert=false
```

The addon sets a response before upstream connection; disabling upstream certificate lookup
keeps this controlled HTTPS oracle independent of an origin service. T-N12 instead uses an independently reachable origin: `python -m http.server 18081
--bind 127.0.0.1` in its dedicated serving directory plus a separately owned reverse mapping.
Serve a token-named file and retain HTTP access logs for the no-origin-hit comparison.

Record device launch time before `am start -W`, then read `pidof PACKAGE` and capture
`logcat -d --pid=PID -T 'DEVICE_LAUNCH_TIME'`. Correlate PID/window/artifact with the fixture token.
A missing PID/crash retains the full launch-window log. The M0 runner bounds the -W UI wait to
five seconds and records exit124 on timeout; actual token-matched query observations still
determine signing acceptance. UI draw/launch-wait completion is not accepted by that result.

## Incremental evidence binding

Original fixture builds record fixture_source_sha256 in addition to the complete source revision.
Harness-only changes can reuse an artifact when its build fingerprint and APK hash still match.
Gates resolve summaries to immutable per-run records and freeze those paths/hashes; an index field
is informational. M0's evidence-contract version2 joins these immutable child references.

Android may recreate an Activity with the same intent. launch_query accepts repeated observations
only when all recorded fields agree, retains every raw event and writes identical_observation_count.
A conflicting duplicate, stale token, wrong case/process or missing event remains a failure.

## Public artifact version1

The public command is `python -m repack` from this checkout; the editable-install console entry is
`repack`. Public CLI operations print an EVIDENCE path for their immutable command report.
`triage` is read-only and may inspect an already patched APK/set. It records that state and
excludes shim/dependency classes from advisory signing references. `patch` requires clean input.
DEX-only mode returns transformation unsupported (exit4). Missing prerequisites return exit3;
invalid/build/verification failures return nonzero. No unsupported mode publishes an artifact.

`patch` publishes a single `.apk` with a `.artifact.json` sidecar, or a directory containing only
selected final APKs plus manifest.json. Intermediate/aligned APKs stay in private staging.
Version1 root fields are schema_version, artifact_type, package, version_code, semantic, outputs,
transformation, host_verification, verification and runtime_verification. artifact_type is apk or
selected-set. A build has transformation applied and host_verification passed; verification and
runtime_verification remain not-run. Runtime verdicts belong to separate measured reports.

The semantic object contains artifact_build_id, package/version, input_members (split/hash/signers),
configuration (requested/selected A, reason, trust_only, dex_only, proxy and CA fingerprint),
operator_signer_sha256, original_identity (metadata API, exact original base hash, current/history
fingerprints and scheme), provenance, transforms, source_sha256, tools and runtime_scope. Public
CA bytes and signer certificates are permitted; private keys/passwords are never embedded.
Original identity binds to original bytes before trust/Java/bootstrap transforms. Signer views
are SDK-specific; SDK verifier output with multiple API ranges is not a simultaneous signer set.
Split signing verification inherits the base minimum SDK. Actual API35 execution remains a
separate cell from host metadata extraction for API35.

Each outputs row has path (relative and contained), split (null for the unique base), sha256 and
signer_sha256. The signed base contains assets/repack/artifact.json with exactly schema_version
and semantic. Verify checks file hashes, marker equivalence and actual APK signing/manifest data.
Duplicate JSON keys, escaping/duplicate paths, inconsistent declarations and hand-edited runtime
pass statuses are rejected. Semantic comparisons use only the semantic object; output byte hashes
remain separately mandatory and may differ across builds with generated ZIP timestamps.

Public verify currently performs artifact/install checks, with runtime_verification not-run.
Its exact requested package binding is distinct from the fixture runner's two-package allowlist.
A mismatched installed signer requires the explicit wipe flag. System/shared-UID or another-user
replacement is unsupported. Known installer-of-record is captured and preserved with -i;
initiating/originating values remain independent. No install failure implies data recovery.
M8 extends measured runtime verification through the same interface.

## M5 container contract

`triage` and `patch` accept `.apks`/`.xapk` with exactly one `--device` or `--device-spec`.
Only containers accept the offline spec flag. The spec requires `sdkVersion`, `screenDensity`,
`supportedAbis` and `supportedLocales`; its API governs signer verification. A supplied spec
records offline selection and makes no runtime claim. Bundletool1.18.3/default install-time module
selection is pinned in config/bundletool-dependency.json. Remote ADB discovery uses an owned
host-loopback relay for the child process; it never restarts the operator daemon.

Version-2 XAPK requires matching package_name/version_code and split_apks file/id records,
where the base id is `base`. It represents one already selected set, with no unlisted APKs,
multi-ABI/density ambiguity or expansion delivery. P0 validates actual signed manifests,
signers, dependencies and effective ABI after selection. APKS requires toc.pb. Asset-pack and
OBB delivery is unsupported. Archive count is capped at20,000, total expanded size at2GiB and
an individual member at1GiB. Unsafe/duplicate ZIP paths, symbolic links and encrypted entries
are refused. Extraction snapshots and hashes bind selected bytes to original archive entries.
The artifact's signed semantic.input_container binds kind/hash/spec/selection and selected
entry hashes. Full archive inventory remains separate in the per-run container.json.

## M6 exact native TLS mode

`patch --native-tls reflutter-3.10.6-arm64` is explicit third-party reFlutter mode.
It accepts only the pinned official ARM64 engine SHA-256, the two matching VM/isolate full-AOT
snapshot headers and the measured API30 target. It preserves libapp.so and replaces the engine
member while retaining its ZIP storage method. The binary release, source contracts and license
are pinned in config/flutter-dependency.json. Unknown hashes/ABIs/snapshot layouts are unsupported.
A separate loopback8083 listener must accept raw TLS without CONNECT; Java routing retains its
configured HTTP proxy endpoint. Artifact metadata records both. Verify refuses other API/ABI/page
cells before installation. This mode does not match the retained Midway engine and adds no generic
SSL_get_verify_result patch or managed DLL coverage.

## M8 runtime evidence

`verify --runtime-evidence packet.json` performs read-only assessment instead of installation.
`--replace-existing-and-wipe-data` conflicts with this mode. All input file hashes and the actual
installed APK member bytes must match; a valid capture for a different installed artifact blocks
without installing anything. The artifact manifest always retains runtime_verification=not-run.
Measured results are separate reports. `--review fresh.md` writes a new human review without raw
payloads. A known failed runtime observation returns1; passed/inconclusive assessment returns0,
and callers must inspect runtime_verification rather than equate exit0 with interception success.

A packet uses these exact fields (replace every sample value with captured data):

```json
{
  "schema_version": 1,
  "adapter": "fixture-https-v1",
  "serial": "5c94c0e5",
  "package": "dev.repack.fixture.identity",
  "artifact_sha256": "<APK or selected-set fingerprint, 64 lowercase hex>",
  "token": "fresh-controlled-token",
  "process": {"pid": 12345, "name": "dev.repack.fixture.identity"},
  "action": {"name": "controlled-fixture-HTTPS", "trigger": "adb-am-broadcast", "component": "dev.repack.fixture.identity/dev.repack.fixture.common.NetworkReceiver", "start_epoch_s": 1793950000.0, "end_epoch_s": 1793950060.0},
  "endpoint": {"scheme": "https", "host": "127.0.0.1", "port": 18443, "method": "GET", "path": "/repack/fresh-controlled-token"},
  "references": {"proxy_log": {"path": "proxy.jsonl", "sha256": "<64 lowercase hex>"}, "app_log": {"path": "app.log", "sha256": "<64 lowercase hex>"}}
}
```

References remain inside the packet directory, are capped at16MiB each, and must match their hashes.
The capture window is bounded to one hour. Proxy JSONL records must contain kind=http,
timestamp_start, scheme=https, exact host/port/method/path and tls=true. CONNECT/error/plain HTTP
rows do not establish decrypted HTTPS. The fixture adapter additionally needs a matching
REPACK_FIXTURE response with the same token/package/PID and the actual `{token,via:proxy}` body;
a caller-supplied comparison=passed has no authority. Conflicting observations fail. Identical
recreation events are counted. Only the owned NetworkReceiver action can use this automatic adapter.

`manual-https-v1` records a manual trigger/action/window and matching decrypted metadata, but stays
inconclusive about automatic app-process/response attribution. It cannot turn arbitrary real-app
traffic into fixture success. Semantic results omit PID, token and capture-time noise; fixture paths
normalize to /repack/{token}. The report is evidence for that recorded window, not a claim about a
fresh current action. scripts/mitm_capture.py records metadata without request/response bodies,
headers or query strings; an identifying header is added only when explicitly configured through
REPACK_IDENTIFYING_HEADER. Use the operator's chosen/waived header policy before target traffic.
