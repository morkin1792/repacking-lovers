# Technical guide

This guide keeps environment setup, advanced modes and verification details out
of the [user README](../README.md). The [future-work list](FUTURE-WORK.md) separates
missing features, untested configurations and deliberate limits.

## Guided setup

The [browser workflow](guided-workflow.md) prepares SDK/helpers and a persistent
operator key without running fixture gates or requiring Git initialization.
Use `./repack.sh` for the common workflow. The manual developer setup below
remains useful for reproducing historical fixture evidence.

## Checkout and host setup

Run from the repository root. This is currently a source-checkout workflow; the
Python package alone does not include the sibling Java/native sources, configs
or cached tools. A portable wheel/standalone installer is future work.

The measured host is Linux x86_64 with Python 3.14, JDK 27, Android SDK platform 36
and build-tools 36.0.0. Python metadata permits 3.11+, but that alone does not
establish all-host compatibility. Public Android builds use javac `--release 8`,
not Gradle/AGP. The current resource compiler is a Linux binary. Native extensions
add their own NDK and ABI requirements.

1. Install Python 3.11+, a JDK providing `java`, `javac` and `keytool`, Android SDK
   platform-tools, platform 36 and build-tools 36.0.0. Put the selected JDK and
   `adb` on PATH; set `ANDROID_SDK_ROOT` if the SDK is outside `~/Android/Sdk`.
2. Use an editable installation from the checkout:

   ```sh
   python -m venv .venv
   . .venv/bin/activate
   python -m pip install -e .
   python -m repack --help
   ```

3. Ensure this checkout is the Git root (`git init` if necessary), then record
   the local SDK/JDK paths and hashes:

   ```sh
   python scripts/acceptance.py host --out .work/evidence/host-setup.json
   ```

   This command probes ADB discovery but does not install or launch apps. It
   rewrites the ignored local `config/implementation-lock.json`. An existing
   workspace lock can contain absolute paths and an external ADB server; inspect its
   `adb_server_socket` and retained device/resource fields before reusing it on
   another machine. The host probe preserves some previous values. Merely copying
   that file is not host setup.

4. Normal DEX inspection/patching needs the hash-pinned `smali` suite in
   `config/java-dependencies.json`. Download each matching row's `jar` and `pom`
   from its `source_url` to its `path`, verifying `sha256` before use. This minimal
   preparation runs from the checkout and downloads only that suite:

   ```sh
   python - <<'PYTOOLS'
   import hashlib, json, pathlib, urllib.request
   for row in json.loads(pathlib.Path('config/java-dependencies.json').read_text())['artifacts']:
       if row['suite'] != 'smali':
           continue
       for kind in ('jar', 'pom'):
           pin = row[kind]
           path = pathlib.Path(pin['path'])
           data = path.read_bytes() if path.exists() else urllib.request.urlopen(pin['source_url'], timeout=60).read()
           if hashlib.sha256(data).hexdigest() != pin['sha256']:
               raise SystemExit('Checksum mismatch: ' + str(path))
           path.parent.mkdir(parents=True, exist_ok=True)
           path.write_bytes(data)
   PYTOOLS
   ```

   Apktool 3.0.3 and ARSCLib 1.4.0 are fetched and checksum-checked on first use.
   Identity mode additionally needs the artifacts in
   `config/hiddenapi-dependency.json`; optional native/Gadget modes need their
   corresponding dependency locks and caches. Missing prerequisites produce a
   failure report. These optional modes are not all installed by `pip install`.

5. For device operations, enable USB debugging, authorize the host, and choose
   the serial from `adb devices -l`. A remote ADB server needs a route back to the
   machine running the proxy; the local `adb reverse` example in the README
   assumes the proxy and ADB server share a host. Record a selected device when
   needed with:

   ```sh
   python scripts/acceptance.py device --device SERIAL --out .work/evidence/device-setup.json
   ```

The setup process has not yet been reproduced as an unattended installation on
a clean second host. See [release portability work](FUTURE-WORK.md#release-and-maintenance).

## Operator key and proxy

Keep one signing key across rebuilds so subsequent patched versions can update
an installed patched copy. Create the password file privately, restrict its
permissions, and use it for an existing key or generate a key once:

```sh
chmod 600 /path/to/keystore-password.txt
keytool -genkeypair -keystore /path/to/operator.p12 -storetype PKCS12 \
  -alias repack -keyalg RSA -keysize 2048 -validity 3650 \
  -storepass:file /path/to/keystore-password.txt \
  -keypass:file /path/to/keystore-password.txt -dname 'CN=Repack operator'
export REPACK_KEYSTORE_PASSWORD_FILE=/path/to/keystore-password.txt
export REPACK_KEY_ALIAS=repack
```

Use `REPACK_KEY_PASSWORD_FILE` only when the private key has a different password.
Normal patching never generates a replacement key. The fixture-key shortcut in
later examples belongs to the development workspace, not a distributed default.

Use the public CA certificate exported by the proxy that will intercept the app.
PEM and binary DER inputs are accepted and normalized automatically. Never
supply its private key. Without `--ca`, patching checks
`~/.mitmproxy/mitmproxy-ca-cert.pem`; an explicit path is clearer. Configure the
proxy listener before launching the patched app. `--proxy` bakes an endpoint into
the APK; `verify --proxy` only asserts that endpoint. It cannot change it.

## Command results

| Command/result | Meaning |
| --- | --- |
| `triage` / `TRIAGED` | Read-only inventory; references alone do not prove a check is enforced |
| `patch` / `BUILT` | Signed output and artifact manifest; no installation or runtime proof |
| `startup` / `STARTUP passed` | Candidate survived two observed startup windows; account functionality untested |
| `verify` / `PASS artifact/install; runtime not-run` | Artifact checks and installation passed; app behavior untested |
| `verify --runtime-evidence` | Assesses supplied observations; manual captures may remain inconclusive |
| `BLOCKED` (exit3) | Missing prerequisite |
| `UNSUPPORTED` (exit4) | Requested unsupported operation |
| `FAIL` (exit1) | Failed operation or exhausted startup search |

A CLI invocation prints its `EVIDENCE` report path. Build reports and runtime
results are separate. Use fresh output paths and retain manifests alongside APKs.
The following sections preserve the development commands and measured boundaries;
[the latest progress entry](implementation/progress.md) supersedes historical notes.

## Implementation, validation and advanced modes

Android repackaging experiments for authorized testing on an ordinary device. M0, the manifest
bootstrap, startup HTTP routing and embedded-CA HTTPS trust are accepted on the Redmi K20 (API30).
Java pinning is accepted for the tested OkHttp4.12.0 and direct/inherited custom-verifier fixtures,
including named R8, near-limit, preservation and refusal cases. API30 signing predicates, comparisons, lists and genuine multi-signer/rotation metadata are also
accepted, with cache/update controls and explicit coverage limits. JNI-to-Java and fresh Java Binder acquisition are accepted on that cell. Split-set validation, install/key lifecycle and the public artifact CLI are accepted on that cell.
Process coverage, RELEASE-1 and the optional M4 native module are accepted on the recorded phone cell. M5 targeted container inputs are accepted; M6 exact reFlutter mode is accepted; M7 owned-fixture Gadget mode and M8 evidence assessment are accepted; the actual Midway1.53.0 target trial observed two stable launches and decrypted primary API traffic; its update-required screen blocked login validation. See [progress](implementation/progress.md) and [PLAN](../PLAN.md).

Midway1.85.0 now also has a verified APK pinning/interception patch on top of its
standalone startup repair: normal welcome screen and primary API GraphQL HTTP200
through the proxy on fresh and cold launches. See
[current artifact, controls and operator command](targets/midway-pinning.md).

The additional Java patch families also passed original/patched Android fixtures
on API30: older OkHttp checks, appmattus CT, CT interceptor delegation, two Flutter
plugin Java/Kotlin helpers, and bundled Conscrypt2.5.2 on both Android socket
backends. [Reproduction and precise coverage](pinning-patches.md#android-acceptance-api30-arm64-target35).

Additional APK modes now cover owned Chromium/Cronet (including configured
public-key pins), optional standard hostname relaxation, offline ARM64 native
TLS, and typed synchronous Dart certificate-pin predicates. See
[commands, contracts and coverage](pinning-expansion.md). Foreign-runtime
markers are diagnostics; they are not advertised as generic bypasses.

### Fixture checks and workspace transport

The following commands reproduce the original workspace fixture checks. The
sourced configuration path is specific to that workspace:

```sh
. /home/water/workspace/Projects/pentest/tools/configure
adb devices -l
python scripts/acceptance.py host --out .work/evidence/M0-host.json
python scripts/acceptance.py device --device SERIAL --out .work/evidence/M0-device.json
python scripts/build_fixtures.py --out .work/evidence/M0-build.json
python scripts/acceptance.py run T-A00 --device SERIAL --out .work/evidence/T-A00.json
python scripts/acceptance.py gate M0 --reports .work/evidence --out .work/evidence/M0.json
```

The builder uses the installed JDK and SDK primitives, with persistent ignored fixture keys.
Both own-factory and pinned AndroidX factory APKs are built. The runner installs only the two
named fixtures, refuses a conflicting signer without explicit replacement authorization, and
retains raw per-command/per-run evidence under ignored `.work/`. Gate summaries bind those
observations to the current sources and selected device. Commands return nonzero for a failure
or missing prerequisite.

The internal bootstrap/routing builder never installs an APK:

```sh
python scripts/spike.py patch --input ORIGINAL.apk --out .work/outputs/my-routing-spike \
  --key .work/keys/repack.p12 --mode routing --proxy 127.0.0.1:8080
```

This interface is an experiment runner with the persistent fixture key; the public operator CLI
is documented in the user README and below. App-local routing covers the tested implicit HttpURLConnection path and supplies
no direct fallback. Direct sockets, other network stacks and OS proxy-transition persistence retain
their separate coverage status. A remote proxy needs independently verified reachability.

For the current workspace, the ADB server runs at 10.20.30.1 while this workspace runs at
10.20.30.2. Routing cases use `--proxy-bind 10.20.30.2`; their owned phone-loopback reverse mappings
point explicitly to that workspace interface. The runner preserves existing mappings and the
operator's global proxy, and cleans up only its own mappings/processes. On a local ADB setup, the
ordinary oracle bind defaults to 127.0.0.1. Proxy CA private material stays under ignored .work/keys.

The runner's `--replace-existing-and-wipe-data` authorizes replacement of its two owned fixtures
only. It never authorizes replacing an installed user app. A missing ADB server/device blocks runtime
acceptance; partial and failed runs remain available under .work/evidence/runs. `NOT-RUN` records
an untested optional case rather than a pass.

### Public CLI and startup search

The public CLI is available from this checkout with `python -m repack` (or the `repack` console
entry point after an editable install). Its current version is a development build:

```sh
python -m repack triage pkg:PACKAGE --device SERIAL
python -m repack patch ORIGINAL.apk --out .work/outputs/patched.apk \
  --key .work/keys/repack.p12 --ca PUBLIC_PROXY_CA.pem --antitamper --device SERIAL
python -m repack patch SELECTED_APK_DIRECTORY --out .work/outputs/patched-set \
  --key .work/keys/repack.p12 --ca PUBLIC_PROXY_CA.pem --antitamper --device SERIAL
```

`patch` builds artifacts. It does not install or launch an app. A single APK has a `.artifact.json`
sidecar; a set has `manifest.json`. Each manifest binds output hashes and configuration to metadata
inside the signed base. `--antitamper` is explicit opt-in, currently API30 only. The default baked
proxy is 127.0.0.1:8080. `--trust-only` changes trust alone; `--dex-only` is explicitly unsupported.
Read-only `triage` can inspect an already patched package; a new `patch` requires original inputs.
Static signing references are advisory and never automatically enable A.

Additional Java patch rules cover older OkHttp checks, the two recognized Flutter
Android pinning plugins, application CT selectors/interceptors, and app-owned
Conscrypt callbacks. They use explicit replacement contracts, including false
returns and request-preserving interceptor delegation. See
[coverage, fixture commands and device-validation limits](pinning-patches.md).

For plain repacking and automated startup repair, use the separate experimental
`startup` command. It tests an immutable resource-rebuild baseline, discovers the
supported signer-string encoding family from the input APK, and tries applicable
repairs and combinations on the selected device without an AI. Each distinct
trial clears the explicitly authorized target's data. A surviving candidate needs
a second cold-launch confirmation; this verifies startup liveness only.
See [the command, search rules and limits](startup-search.md).

```sh
python -m repack startup ORIGINAL_APK_OR_SELECTED_DIRECTORY \
  --out .work/outputs/startup-search-01 --key .work/keys/repack.p12 \
  --device SERIAL --replace-existing-and-wipe-data --max-trials 8
```

### Original-byte integrity module

The M4 native module is explicit opt-in (its acceptance is tracked in progress):

```sh
python -m repack patch ORIGINAL.apk --out .work/outputs/native-patched.apk \
  --key .work/keys/repack.p12 --ca PUBLIC_PROXY_CA.pem --device SERIAL \
  --integrity native-base-bytes:libCaller.so
```

Select one or two app library basenames. The module supports the measured API30 ARM32/ARM64
paths, preserves existing ABI selection, and maps absolute read-only base-APK opens in those
callers to the verified original. Provisioning and task registration precede the original factory.
Other callers keep reading the patched APK. Descriptor paths disclose the retained file; direct
syscalls, dlsym, preopened descriptors and relative dirfd paths remain uncovered. A caller that
mixes integrity and legitimate APK reads cannot be separated by its library name. Split-original
mapping is currently an internal experiment. `--trust-only` conflicts with this module. Missing
callers, native backend-name collisions and unsupported cells are refused before publishing.

### Containers and installation

Container selection uses pinned bundletool1.18.3. `.apks` inputs select an install-time subset
with exactly one of `--device SERIAL` or `--device-spec SPEC.json`. Offline selection is host-only.
Version-2 `.xapk` inputs require an explicit `split_apks` list describing one selected set; expansion
files and ambiguous multi-ABI/density sets are refused. Neither path installs every archived APK.
Full inventory and selected-member hashes are recorded separately; the signed artifact binds the
original archive hash and selection. See [bundletool targeting](https://developer.android.com/tools/bundletool).

```sh
python -m repack triage input.apks --device SERIAL
python -m repack patch input.xapk --device-spec device.json --out .work/outputs/container-set \
  --key .work/keys/repack.p12 --ca PUBLIC_PROXY_CA.pem
```

For another existing operator keystore, set `REPACK_KEYSTORE_PASSWORD_FILE` and `REPACK_KEY_ALIAS`.
Use `REPACK_KEY_PASSWORD_FILE` only for a different private-key password file. Credentials are
passed by file reference. Missing keys fail without creating a new key. The persistent fixture
repack key/password references above are recognized for this checkout's tests.

`python -m repack verify ARTIFACT_MANIFEST --device SERIAL` checks the signed marker, hashes,
signatures, member dependencies and install preflight, then installs a compatible artifact.
A signer mismatch requires its explicit `--replace-existing-and-wipe-data` flag. This currently
reports artifact/install verification separately from app runtime verification; M8 owns the latter.
`--proxy HOST:PORT` asserts the baked endpoint and cannot change it. Preserve the original app's
data by leaving a conflicting signer unapproved. Fixture-runner authorization never extends to
a user app. Current Midway startup/interception results are recorded in [the target guide](targets/midway-pinning.md); authenticated flows remain untested.

### Native TLS and Gadget

The earlier native TLS extension is the explicit third-party reFlutter mode.
The newer `offline-arm64` mode is documented in [pinning expansion](pinning-expansion.md):

```sh
python -m repack patch KNOWN_FLUTTER.apk --out .work/outputs/flutter.apk \
  --key .work/keys/repack.p12 --ca PUBLIC_PROXY_CA.pem --device SERIAL \
  --native-tls reflutter-3.10.6-arm64
```

Only the pinned official Flutter3.10.6 ARM64 engine and matching full-AOT snapshots are accepted.
This mode needs a separate raw-TLS listener on loopback8083, alongside Java's configured HTTP
proxy. It is measured only on API30/ARM64/4KB. Unknown builds, including Midway's retained engine,
are refused. Binary/source/license pins are recorded in config/flutter-dependency.json.

The optional `--gadget raw-apk-fixture` mode is limited to the exact owned API30 ARM64 native
fixture. It uses a pinned Frida script with no instrumentation listener, is detectable in maps,
and makes no Midway or generic RASP claim. Ordinary patches include no Gadget binary/assets.

### Runtime evidence

Runtime evidence can be assessed without reinstalling:

```sh
python -m repack verify artifact.json --device SERIAL \
  --runtime-evidence capture/packet.json --review review.md
```

This mode rechecks installed bytes and the packet's file hashes, endpoint, window, PID and app
response. It conflicts with replacement authorization. Only the owned marked NetworkReceiver
adapter can auto-pass; manual real-app captures remain inconclusive. The Markdown review omits
raw payloads. See [the packet contract](implementation/CONTRACT.md#m8-runtime-evidence).

### Target observations

Midway1.85 reached its normal welcome screen and returned primary API HTTPS
responses through the proxy in fresh and cold observations. Login and later
account flows remain untested. The historical1.53 trial had an update-required
screen and uncontrolled external-module state; it does not establish tool-only
compatibility. Current results and controls live in
[the Midway guide](targets/midway-pinning.md), with the full history in
[implementation progress](implementation/progress.md). Installed state and
private captures are local observations, not promises about another device.


## Interrupted APK downloads

The GUI and CLI share `repack/transfers.py`. Reads use no PTY and stream binary
stdout directly to staging files. Successful exit alone is insufficient: chunk
length, total length, and a SHA-256 computed on the device must all match. Retry
size shrinks automatically after a failed read; verified chunks already collected
within the operation are retained. If the bounded retry budget is exhausted,
staging files are discarded and installation is not attempted.

The recorded API30 Wi-Fi connection interrupted ordinary `adb pull`, uncompressed
`pull -Z`, and legacy `exec-out cat`. The latter returned zero with only 16,424,960
of 218,343,927 bytes. This identifies a bulk-transfer/transport problem but does
not establish a particular ADB daemon or Wi-Fi-driver defect. Small shell commands
can succeed between these interruptions. The recovery path stays on the explicit
serial and configured ADB server; it does not kill/restart the shared daemon.

See [ADB command documentation](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/docs/user/adb.1.md)
for shell/PTY and transfer command behavior.
