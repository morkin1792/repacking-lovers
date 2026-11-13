# repacking-lovers

Choose an Android app, generate a repacked copy, and install it on your phone.
Use original APK files or select an installed app by its name or package name.
No AI or root access is required.

## Start here

On **Linux x86_64**, install **Python 3.11+** and a **JDK 17+**, then extract the
source bundle or open this checkout and run:

```sh
./repack.sh
```

This opens a local browser interface. Installed tools are detected and prepared
automatically, so you can start without clicking a setup button. It finds an
Android SDK through `ANDROID_HOME`, `ANDROID_SDK_ROOT`, standard
installation paths, or `adb` on PATH. If SDK components are missing, it asks you
to accept the SDK license before downloading them. It also prepares the APK
tools and creates one persistent signing key that survives tool updates. No Gradle, Android Studio, or Python packages are required.

1. **Choose your app.** Select one APK, a complete set of split APKs, or a
   supported `.apks` / `.xapk` container (containers need a selected phone).
   Alternatively, connect a phone, enable
   USB debugging, and search its installed apps by name or package. The list
   shows names and versions first; icons load in the background while you choose.
2. **Choose the changes.** **Intercept HTTPS traffic** is selected by default.
   It adds your proxy's public certificate, routing, and supported Java pinning
   patches. **Repacking diagnostics → Rebuild only** checks whether rebuilding
   and signing alone causes a crash; use it to isolate repacking problems.
3. **Generate the APK.** Follow the build steps as they complete. Automatic
   installation goes to the source phone, or the installation phone selected for
   file inputs. You can also
   choose a destination device on any build card and install or retry later.
   Download **APK set (.zip)** for manual installation: extract it and follow
   `INSTALL.txt`, which gives the `adb -s SERIAL install` / `install-multiple` command.

If replacement requires uninstalling the original app, the interface asks you to
confirm **deleting that app's local data**, naming the package and phone. Original
APK backups cannot restore private app data. Compatible updates keep their data.

Files and keys stay on your computer. The interface listens only on localhost.
Originals, outputs and reports are retained; bulky build scratch is removed.
Build history shows the app name, version, available icon and proxy endpoint.
Unauthorized/disconnected phones cannot be selected as installation targets.
A failed installation keeps the finished build for retry on your chosen device.
**Delete APKs** frees the generated outputs while keeping backups/reports; **Delete build** removes the whole build
including its backups. Neither uninstalls the phone app or deletes your signing key.

## Intercepting traffic

Start your HTTP(S) proxy. The interface checks Burp's default certificate URL,
`http://127.0.0.1:8080/cert`, automatically. You can change the URL or upload a
public **PEM or binary DER** certificate (`.pem`, `.der`, `.crt`, `.cer`); conversion
is automatic. Never supply a private key.

The certificate URL is accessed by your computer; the **app's proxy endpoint**
is baked into the APK and must be reachable by the phone. Its default is
`127.0.0.1:8080`.
For a proxy on the same computer as the ADB server, connect phone loopback with:

```sh
adb -s SERIAL reverse tcp:8080 tcp:8080
```

If an app rejects its new certificate, try **App rejects being repacked? →
Work around supported in-app signing checks**, on **Android 11/API 30**. This
makes supported checks inside the app see its original signing certificate. It
does not change the identity Android or external services see, or fix every crash.

The proxy must remain reachable while you use the app. Some network stacks need
separate routing. Installation success alone does not confirm interception.

## Current limits

- The main device validation is Android 11/API 30 on an ARM64 phone. Other
  Android versions and devices are not broadly verified.
- Optional signing-check adaptation supports **API 30 only**. It cannot change
  the real installed signing identity seen outside the app.
- Plain repacking does not automatically run the experimental startup-repair
  search. Some apps still crash or reject modified APKs.
- The browser exposes the common workflow. Additional native/Dart modes and
  startup repair remain available through the command line.
- Login and other features need separate testing. Play Integrity, server checks
  and certificate-bound integrations can prevent a modified app from working.

Test only apps you own or are authorized to assess. Keep the signing key between
builds so future patched versions can update an installed patched copy.

## Command line and documentation

```sh
python -m repack --help
python -m repack ui --no-browser --port 8787
```

- [Guided workflow](docs/guided-workflow.md): setup, installation, backups and release bundles.
- [Technical guide](docs/technical-guide.md): CLI commands, advanced modes and validation.
- [Startup repair](docs/startup-search.md), [Java pinning](docs/pinning-patches.md), and [native/Dart modes](docs/pinning-expansion.md).
- [Future work](docs/FUTURE-WORK.md), [plan](PLAN.md), and [recorded results](docs/implementation/progress.md).
