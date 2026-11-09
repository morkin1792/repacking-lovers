# Midway plain repack startup

The plain-repack observations below are preserved as the baseline. The current
installed APK has advanced to the verified [pinning/interception patch](midway-pinning.md),
which reaches the normal welcome screen and decrypts primary API responses.

Midway1.85.0 (399590) now opens after a full resource decode/build, alignment and re-signing on the recorded API30/ARM64/4096-byte phone. Two60-second launches keep a stable foreground process with no target fatal: fresh data and a retained-data cold start with installed APK hashes verified. The app displays its maintenance/error screen. Normal service access and login remain unverified.

Two isolated configuration changes resolve the startup crashes:

1. Update the encoded expected signing-certificate SHA256 to the persistent operator key. Original MainApplication.onCreate deliberately divides by zero when its expected and actual identity states disagree. A branch-only diagnostic failed later because it preserved inconsistent seed state; the fingerprint change produces the normal state naturally.
2. Remove only QUERY_ALL_PACKAGES. An encrypted installed-package checker matches me.bmax.apatch at detectionCode29, stores its verdict in DocumentXActivity.cancelAll, then deliberately crashes the worker. CustomFcm reads the same cache and deliberately throws null. The original native matcher, observed cache transition and permission-only ablation establish this cause. Every original queries entry, including the launcher query, remains present.

All checker/reaction instructions remain. No native diagnostic helper, injected DEX, CA, identity proxy, routing configuration or pinning change is included. The final build retains six DEX members, all 50 original native library payloads and all6,779 original resource ID/name bindings (plus74 compiler placeholder IDs). Independent binary XML inspection confirms the original NSC/pin policy is preserved.

This is an exact-input target recipe, not generic coverage for another version or platform. Broad installed-app discovery changes when the permission is removed; other application integrations were not exhaustively exercised. Matching an installed APatch package is not proof that the checker tested actual root privileges.

The current artifact set and private runtime evidence are local:

- [Final artifact control](/home/water/workspace/Projects/repacking-lovers/.work/outputs/midway-H10-resource-roundtrip-minimal/plain-control.json)
- [Results, hypotheses and reproduction](/home/water/workspace/Projects/repacking-lovers/.work/targets/midway/plain-repack/RESULTS.md)
- [Machine-readable summary](/home/water/workspace/Projects/repacking-lovers/.work/targets/midway/plain-repack/investigation/final-summary.json)
- [Build recipe](/home/water/workspace/Projects/repacking-lovers/.work/targets/midway/setup/repack_startup_minimal.py)

```sh
. /home/water/workspace/Projects/pentest/tools/configure
python .work/targets/midway/setup/repack_startup_minimal.py
# Use the printed control path; this runner installs and clears the authorized target's test data.
python .work/targets/midway/setup/run_hypothesis.py /absolute/path/to/plain-control.json
# Repeat without reinstall/data reset:
REPACK_OBSERVE_INSTALLED=1 python .work/targets/midway/setup/run_hypothesis.py /absolute/path/to/plain-control.json
```

The H10 recipe above is the historical manual reproduction. The current installed
set comes from the standalone search described below. Other apps, root modules
and device proxy settings were preserved. Pinning remains out of scope.

## Standalone reproduction, without a target profile

The generic [startup search](../startup-search.md) now reproduces this repair:

```sh
. /home/water/workspace/Projects/pentest/tools/configure
python -m repack startup .work/targets/midway/play-1.85.0-module-off/original \
  --out .work/outputs/my-new-startup-search --key .work/keys/repack.p12 \
  --device 5c94c0e5 --replace-existing-and-wipe-data \
  --max-trials 4 --observe-seconds 60
```

Run20261107T032955-0db34c7c2c derived the payload location/constants from original
DEX and verified certificate metadata, then autonomously tested plain rebuild,
signer-only, and signer-plus-visibility. Trial 3 passed 60 seconds with fresh data;
the same artifact passed another 60 seconds after a cold launch with retained data.
Both windows checked installed hashes and contained no target fatal/ANR.

Current output: `.work/outputs/startup-generic-midway-02/startup-search.json`.
Its trial 3 `artifact.json` lists all four actual member paths/hashes. The four
APKs remained installed and force-stopped at that handoff. The maintenance/error screen remained;
functional service access is unverified. Independent comparison confirms the DEX,
manifest and NSC payloads match H10. This generalizes the recognized encoding and
experiment rules; encrypted-check attribution is still the earlier manual work.
