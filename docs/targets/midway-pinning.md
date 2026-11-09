# Midway APK pinning patch

Midway1.85.0 now reaches its normal welcome screen and sends decrypted primary API
traffic through the proxy after APK patching. The full patched set passed a
90-second fresh-data launch and a separate 90-second retained-data cold launch on
the recorded API30/ARM64 phone. Both captured
`POST https://api.bancomidway.com.br/channel-app-v1/graphql` with HTTP 200 and
`POST /prf-sdk/v1/log` with HTTP 201. No credentials or account actions were used.

The installed set is
[midway-pinning-extensions-host-v1/manifest.json](/home/water/workspace/Projects/repacking-lovers/.work/outputs/midway-pinning-extensions-host-v1/manifest.json).
It retains the verified [startup repair](midway-startup.md), embeds the selected
proxy CA, installs the app-local route to 127.0.0.1:8080, and uses the existing
generic matcher to replace two methods:

- `okhttp3.CertificatePinner.check$okhttp(String, Function0)`.
- Obfuscated TrustKit `o.isRtl.checkServerTrusted(X509Certificate[], String)`.

Own-process `REPACK_PATCH` markers confirm both replacements executed in the
fresh and cold observations. The TrustKit replacement returns before ordinary
chain validation as well as pin enforcement. Its hostname-context interceptor
remains intact and forwards the request unchanged. The identity proxy is disabled;
the startup payload already expects the persistent operator key.

## Controls and observations

| Build | Window | Primary API HTTPS | UI |
| --- | --- | --- | --- |
| Routing only; original trust and Java pins | 60 seconds | No decrypted response; proxy certificate rejected | Maintenance/error |
| Embedded CA with overridePins plus routing; original Java pins | 90 seconds | GraphQL200, SDK log201 | Normal welcome |
| Full CA/routing/Java APK patch, fresh data | 90 seconds | GraphQL200, SDK log201 | Normal welcome |
| Same full APK, cold launch with retained data | 90 seconds | GraphQL200, SDK log201 | Normal welcome |

The smaller CA/trust-policy control already suffices for these observed requests.
The experiment therefore does not establish that Java replacements are necessary
for this first-screen path. The full artifact additionally has verified execution
of those replacements; it is the current installed public artifact.

The generic patch retains all six startup DEX payloads byte-for-byte in shifted
slots, adds one DEX for the two shadowed classes and one for the routing bootstrap,
and preserves all 50 native libraries. The existing resource-binding guard passes;
the startup permission deletion remains present. The extension batch selects the
same two Midway methods; its new CT/plugin/Conscrypt rules passed
[separate Android fixtures](../pinning-patches.md#android-acceptance-api30-arm64-target35).
No identifying request header,
device-wide trust/proxy setting, root module, or other app was changed.

Current extension-build fresh run: 20261107T160300-9bba60500c, PID 28123.
Cold run: 20261107T160808-2d84d76012, PID 24085. Both ran 90 seconds,
showed the normal welcome screen, logged both patched methods in the app process,
and returned GraphQL200 and SDK log201. Reports are
`.work/targets/midway/pinning-20261107/extensions-device-{fresh,cold}.json`.
The older full-build runs were 20261107T041836-0215497af8 and
20261107T044311-6834b37c91. Machine-readable comparison and evidence
bindings: `.work/targets/midway/pinning-20261107/summary.json`. Static call-graph
notes and the matched classes are under that directory's `static/` subdirectory.
The original preservation check is recorded in
`.work/evidence/runs/20261107T044748-6ba9dadff3/report.json`. Current installed
hashes and cleanup are verified in
`.work/evidence/runs/20261107T162456-ddbf808100/report.json`.

## Use the installed APK

The baked endpoint needs the workspace proxy and its owned ADB reverse mapping.
This command verifies the installed APK hashes and CA, starts the forwarding
capture, and opens Midway without reinstalling or clearing data:

```sh
. /home/water/workspace/Projects/pentest/tools/configure
python .work/targets/midway/setup/pinning_proxy.py
```

Requests forward to the existing `PENTEST_PROXY`, with headers unchanged. The
default session budget is one hour; `--seconds N` selects 10–7200 seconds. Ctrl+C
stops the target and cleans only the session's proxy/reverse. A 15-second smoke
session passed. After verification, the patched APKs remain installed and stopped;
the temporary proxy and reverse are cleaned. Network access requires starting the
session again. The previous global proxy setting is preserved.

## Rebuild and repeat

Start from an accepted standalone startup-search result, collect every member
referenced by its winner, then run the existing public patch CLI. Use fresh
directories and the same persistent key:

```sh
. /home/water/workspace/Projects/pentest/tools/configure
python .work/targets/midway/setup/pinning_prepare.py \
  .work/outputs/startup-generic-midway-02/startup-search.json \
  --out .work/outputs/new-pinning-input
python -m repack patch .work/outputs/new-pinning-input \
  --out .work/outputs/new-pinning-apk-set --key .work/keys/repack.p12 \
  --ca .work/keys/mitmproxy/mitmproxy-ca-cert.pem \
  --proxy 127.0.0.1:8080 --device 5c94c0e5
python .work/targets/midway/setup/pinning_capture.py \
  .work/outputs/new-pinning-apk-set/manifest.json new-full-test --seconds 90
```

Add `--cold` for a repeat of those installed hashes without data clearing.
The target wrapper checks the recorded replacement/header authorization. The
public APK patch uses no Midway-specific method names or offsets; its generic
matchers select the two methods. These target wrappers provide device/capture
orchestration and do not require an AI.

This acceptance covers startup and the observed first-screen Java/API path.
Login, authenticated actions, Flutter/native TLS, and later Unico identity flows
remain untested. The phone is non-stock; the previously created external pinning
module was disabled by the operator, and its root-only state was not independently
read. No runtime hook or root command was used by this test.
