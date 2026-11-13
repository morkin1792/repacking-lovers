# Guided APK workflow

Run `./repack.sh` or `python -m repack ui` from the source checkout or extracted
release bundle. The browser opens automatically. Use `--no-browser` to print the
address without opening it, or `--port 0` to choose an available port.

## Requirements and first setup

The guided release supports Linux x86_64 with Python3.11+ and a JDK17+ already
installed. A Java runtime without `javac` is insufficient. Additional hosts remain
future work. The public APK builder still targets public Android APIs through
javac `--release 8` and d8; no Gradle/AGP installation is needed.

Installed JDK/SDK components are detected on startup. With all required SDK tools
installed, local preparation (helpers, cached metadata DEX and persistent key)
starts automatically; no setup-button click or SDK-license prompt is required.
While automatic preparation runs, the page shows only a loading message; JDK/SDK
fields appear when setup needs input or when the operator opens setup after loading.
Missing SDK downloads still require acceptance of the SDK license.
The setup screen allows overriding detected JDK/SDK locations. SDK discovery checks `ANDROID_HOME`,
`ANDROID_SDK_ROOT` (legacy), `STUDIO_SDK_PATH`, the SDK containing `adb` on PATH,
then common home/system locations such as `~/Android/Sdk`, `~/Library/Android/sdk`
and `/opt/android-sdk`. Partial SDKs are reused, adding missing components there.
`ANDROID_SDK_HOME` is normally a preferences directory and is accepted only when
it actually contains SDK components. The detected location and its source appear
in setup. You can change the folders before
preparing tools. It uses the existing Android platform36/build-tools36.0.0 where
available; missing components are downloaded from Google's official repository,
verified against `config/setup-dependencies.json`, and extracted locally. The
SDK-license checkbox applies to downloads under the linked Android SDK terms.
A working `adb` on PATH is reused; otherwise pinned platform-tools37.0.1 is
installed. Download archives are removed after successful SDK extraction.

Pinned smali helpers, Apktool and ARSCLib are prepared automatically. Signing-check
adaptation prepares its existing pinned HiddenApiBypass dependency on request.
The setup command does not install fixture apps or require Git initialization.
For headless preparation:

```sh
python -m repack setup --accept-sdk-license
```

Use `--sdk /path/to/sdk` and `--jdk /path/to/jdk` to select existing installations.
The local implementation lock is regenerated from this host, with the current
`ADB_SERVER_SOCKET`; stale device facts and another host's server socket are not
inherited. Source the operator's ADB configuration before starting the UI when
using a remote server. Remote ADB proxy reverse destinations need separate
configuration; the README's reverse example assumes a shared ADB/proxy host.

## Selecting input

- Files: one original APK, a directory selection of already compatible split
  APKs via multiple file selection, or one supported targeted container.
- Phone: enable USB debugging and authorize the host. Choose a serial, load apps,
  and search the display name or package name. System apps are omitted from the
  chooser. Only one app is selected; full installed base/config/feature members
  reported by `pm path` are pulled before any installation.

Containers require a selected phone for targeting in the GUI; the expert CLI
also accepts an offline `--device-spec`.

Display names, version names/codes and 64×64 PNG icons are obtained together
by a small cached Java/D8 helper run as an ordinary shell
process through `app_process`. It reads PackageManager metadata without pulling
every app's APK or installing a helper app. Its unique temporary device JAR is
removed afterward. The helper uses reflection only for obtaining the shell's
framework context. No device-wide hidden-API setting is changed. Missing icons use a letter tile;
one unavailable icon does not prevent listing the remaining apps. Names and
versions are returned first; icons load in batches of 20 on a separate endpoint.
The helper is compiled once per source/toolchain fingerprint. Background icon
requests do not occupy the build worker, and responses from an older phone/list
selection are ignored by the browser.

Inputs are validated by the existing selected-set/signature/version checks.
Previously tool-patched inputs are refused; use an original backup instead.
Uploads are streamed, bounded and isolated. The app list and labels are rendered
as text, including names containing HTML characters.

## Building and installing

**Rebuild only** (under **Repacking diagnostics**, previously **Plain repack**) performs the resource round trip, preserves DEX/native/opaque
payloads through the existing guards, then aligns and signs all selected members.
It injects no routing shim, CA or pinning changes. Its `plain-artifact.json` is a
GUI/plain-build record, distinct from the signed-marker manifests consumed by
expert `repack verify`.

The default, **Intercept HTTPS traffic**, calls the existing public patch pipeline with the selected
CA and endpoint. It publishes the existing portable artifact manifest. Supported
Java rules run automatically; signing-check adaptation remains opt-in/API30.
The browser probes `http://127.0.0.1:8080/cert` automatically. A successful public
certificate response is used directly; a Burp/PortSwigger server header identifies
Burp, otherwise it is labeled a proxy certificate. The operator can change the
URL or select **Use my certificate file**. Both PEM and binary DER are validated,
converted and fingerprinted by SHA-256 over DER bytes. `.pem`, `.der`, `.crt` and
`.cer` extensions are accepted; contents determine encoding. Downloads bypass
host proxy environment variables, have a three-second timeout and 1 MiB limit,
and refuse redirects and private/multiple certificates. Public certificate caches
live in `.work/gui/certificates/`. URL/endpoint preferences are kept in browser
storage. This probes the certificate endpoint rather than scanning running processes.

The certificate URL is fetched by the computer running the tool; the proxy endpoint
is used by the phone. A remote ADB server may need a different reachable endpoint.
A custom certificate URL does not implicitly change the phone's proxy endpoint.

**Work around supported in-app signing checks** is for an app that rejects the
replacement certificate or reports a modified app. On the supported API30 cell,
recognized queries inside the app receive the original signer. It does not change
the installed certificate or checks in Android/other processes. Other startup
failures require separate diagnosis.

The common browser workflow does not select experimental native/Dart/Gadget
modes silently. Those remain explicit CLI options with their existing limits.

Build cards show names, versions, available icons and named build steps. Uploaded
APK metadata is read from the APK; device selections initially reuse the app-list
metadata. Existing history is enriched from retained APKs when available.

With automatic installation enabled, a completed build is preflighted and
installed on the exact source phone captured when the job was created (or the
explicit installation phone for file inputs). Connecting another phone never
changes this target. Each completed build also has a destination-device selector,
including after an install or an installation failure. Unauthorized/offline devices
are disabled, and disappearing source phones are retained as disconnected choices;
the UI does not switch to another phone automatically.

Installation failures use `install_failed`, keeping outputs for retry. Every
attempt records its serial and evidence; replacement consent is scoped to both
package and serial and cannot transfer to another phone. Original split selection
is retained; each destination must pass the API/ABI/signature/dependency checks.
Identity-adapted builds are additionally restricted to their recorded API.

APK downloads use binary `adb -s SERIAL shell -T` reads, starting with 1 MiB chunks.
A failed/short read retries the same offset, shrinking toward 64 KiB, with up to
five attempts per chunk and a bounded wait for that selected transport to recover.
The entire APK must match the phone's reported size and SHA-256 before it is
published. Incomplete staging files are removed on failure. The implementation
avoids legacy `exec-out`, which returned success with truncated data in the recorded
failure, and uses the shell protocol's separate stdout/stderr and remote status.
No global ADB restart, reconnect-all, or change of target device is performed. Existing local originals/results may be reused
for a preflight backup only when a fresh `sha256sum` from that exact phone matches
the local bytes. Uninstall/install is never automatically retried after failure.

A signer conflict pauses at a target-specific confirmation, after the output is available for review. Approval names the exact
package/serial; installation reruns preflight against the current phone state.
System/shared-UID/multi-user restrictions remain enforced by the existing code.
Same-key updates use the existing update path. Installer failures retain their
observed outcome; a failed build never proceeds to installation.

A successful install is not a startup/login/interception verdict. The GUI does
not launch the app, run the startup repair search, create a proxy listener, change
global proxy/CA settings, or automatically establish an ADB reverse mapping.

## Files and storage

The GUI keeps state in ignored `.work/gui/`:

- `jobs/<id>/result/`: signed output APKs and build manifest.
- `jobs/<id>/originals/` and `originals.json`: hash-checked source APK backups.
- `jobs/<id>/installed-originals/`: installed APK copies backed up before an
  authorized uninstall, if replacement is required.
- `jobs/<id>/evidence/`: build logs and result/configuration records. Generated
  decoded trees, staging APK/DEX/native copies and huge DEX dumps are removed.
- `jobs/<id>/job.json`: operation status, artifact metadata and device mutations.

Build cards show the baked proxy host/port and public CA fingerprint/source.
**Delete APKs** removes the job's `result/` directory and disables downloads and
installation, keeping history, original APK backups and evidence. **Delete build**
removes the job, original backups, related retained uploads and installation logs.
Both actions require a browser confirmation and refuse while an operation is active.
They do not uninstall apps, delete tool caches, or change the per-user signing key.

Successful uploads are removed after originals have been copied and checked.
Interrupted or failed uploads/builds may retain data for diagnosis. Installed-app
backups contain APKs only, never a promise of private-data recovery. The browser offers one download: a streamed APK-set ZIP, also for single APKs.
It contains the verified APKs, `outputs.json`, and `INSTALL.txt` with an explicit
`adb -s SERIAL install` or `install-multiple` command. Extract the ZIP before
using ADB; Android’s ordinary file installer cannot install a split set by opening
the ZIP. Another device still needs compatible selected splits. No second ZIP
copy is retained on disk. Individual download endpoints remain for compatibility.

Browser disconnects during list loading or downloads are handled silently. They
do not trigger a second HTTP error response or cancel an already submitted build
or installation.

The generated operator identity is separate from fixture and expert-CLI keys:

```text
~/.local/share/repacking-lovers/keys/repack.p12
~/.local/share/repacking-lovers/keys/keystore.pass
```

With `XDG_DATA_HOME` set, that directory replaces `~/.local/share`. The identity
is per user and survives using another release folder. Earlier workspace-based
GUI keys are copied into the per-user location on first preparation, preserving
their identity; existing per-user keys are never overwritten.

Keep both files privately. They are reused across builds and release folders; they are never bundled
with downloads or release archives. Missing credentials for an existing key fail
instead of generating a replacement identity. The GUI-managed identity ignores
expert CLI password environment overrides. Expert commands can still use other
operator keys through their documented environment variables.

Closing the UI with Ctrl+C waits for an active operation to finish. Restarted
sessions mark unfinished jobs interrupted and retain available results; they do
not silently resume an installation.

## Local interface boundary

The server binds only `127.0.0.1`. API operations require a session token; Host
and Origin are checked, with no cross-origin API access. Downloads require the
same-site session cookie and recheck output hashes. Upload paths cannot select
arbitrary host files. Operation jobs are serialized. The workspace is intended
for one local operator, not shared/public hosting.

## Building the release bundle

```sh
python scripts/build_release.py --out dist/repacking-lovers.zip
```

This creates a deterministic source ZIP and SHA-256 sidecar. It includes the
launcher, Python/browser code, Java/native sources, dependency pins, tests and
docs. It excludes local configuration, keys, captured evidence, APKs, downloaded
tools and Python caches. SDKs are downloaded locally instead of redistributed.
Extract the archive and run `./repack.sh` from its top-level folder.

This is a source-bundle release, not a self-contained Python wheel or an app-store
binary. The editable-install CLI remains available; moving all build resources
inside a standalone wheel and supporting more host platforms remain future work.
