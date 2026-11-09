# repacking-lovers

Repackage Android apps for authorized security testing: let supported apps trust
your proxy, remove recognized certificate pinning, and repair supported checks
that stop a repacked app from opening. No AI or root access is required to run
the tool.

You can inspect an app, build a patched copy, and install it on a test phone.
If you only want to find a repacked copy that opens, the separate `startup`
command tries supported repairs without changing proxy or pinning settings.

## Before you start

- Use original APKs or a complete, compatible set of split APKs from an app you
  are authorized to test. You can also read an installed app with `pkg:PACKAGE`.
- Use a persistent signing key. Replacing the original app with a copy signed by
  your key can require uninstalling it and **deleting its local data**.
- For traffic interception, have a running HTTP(S) proxy and its public CA
  certificate. The tool changes the app; it does not install a device-wide CA.

The current release runs from a source checkout. Set up Python, Java, the Android
SDK and the required tools using the [setup guide](docs/technical-guide.md#checkout-and-host-setup).
Then run commands from the repository root:

```sh
python -m repack --help
adb devices -l
```

Use your phone's serial wherever the examples say `SERIAL`. Signing-key setup is
covered in the [key guide](docs/technical-guide.md#operator-key-and-proxy).

## Patch an app for interception

Inspect the original app first:

```sh
python -m repack triage original.apk --device SERIAL
```

Build a copy using your signing key and your proxy's public CA:

```sh
python -m repack patch original.apk --out output/patched.apk \
  --key /path/to/operator.p12 --ca /path/to/proxy-ca.pem \
  --proxy 127.0.0.1:8080 --device SERIAL
```

This adds proxy trust and routing, applies recognized Java pinning patches, and
signs the output. It does not install or launch the app. Use a fresh output path.
For split APKs, replace `original.apk` with the directory containing the selected
set and use a directory such as `output/patched-set` for `--out`.

With a proxy listening on port 8080 on the same computer as your ADB server,
connect the phone to it:

```sh
adb -s SERIAL reverse tcp:8080 tcp:8080
```

Install the result using the manifest printed by `patch`:

```sh
python -m repack verify output/patched.artifact.json --device SERIAL
```

For split sets, use `output/patched-set/manifest.json`. If installation requires
removing an existing copy, the command stops. Add
`--replace-existing-and-wipe-data` only when you accept losing that app's local
data. After installation, open the app and check its traffic in your proxy.
Installation success alone does not confirm interception.

The proxy must stay reachable while you use the app. USB loopback requires the
ADB connection; another reachable endpoint can be baked in with `--proxy`.

## Find a plain repack that opens

Use this when you want to test repacking before working on interception:

```sh
python -m repack startup original.apk --out output/startup-search \
  --key /path/to/operator.p12 --device SERIAL \
  --replace-existing-and-wipe-data --max-trials 8
```

**This installs trial builds and clears the target app's data for each trial.**
It tries supported repairs automatically and confirms a surviving candidate with
a second cold launch. It leaves the last tested build installed. Passing means
the app stayed open during the checks; login and other features still need
testing. See [startup search](docs/startup-search.md) for its rules and outputs.

## Current limits

- The main device validation is Android 11/API 30 on an ARM64 phone. Other
  devices and Android versions are not broadly verified.
- Optional `--antitamper` handles supported app-local signing checks on
  **API 30 only**. It cannot change the real installed signing identity.
- Supported Java libraries are patched automatically. Native TLS and Dart
  pinning need explicit options and compatible code; see
  [additional pinning modes](docs/pinning-expansion.md).
- Some network stacks ignore the app's proxy settings. Removing their pinning
  alone does not send their traffic through your proxy.
- Some apps still crash, reject modified APKs, or refuse login. Server checks,
  Play Integrity and checks in other apps or system processes can prevent use.

## More information

- [Technical guide](docs/technical-guide.md): setup, advanced options, outputs and testing.
- [Pinning coverage](docs/pinning-patches.md) and [native/Dart modes](docs/pinning-expansion.md).
- [Future work](docs/FUTURE-WORK.md): missing features and remaining validation.
- [Implementation plan](PLAN.md) and [recorded results](docs/implementation/progress.md).
