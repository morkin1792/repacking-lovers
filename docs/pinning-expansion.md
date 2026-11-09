# Additional APK pinning adaptations

This extends the [first Java batch](pinning-patches.md) with Chromium/Cronet,
optional hostname relaxation, offline native TLS edits and typed Dart predicates.
Everything runs through APK transformation; no Zygisk module or device-wide hook
is installed. Login remains outside these tests.

| Surface | Implementation | Boundary |
| --- | --- | --- |
| Bundled Chromium verifier | Adds the selected public proxy CA once, then delegates all original arguments to the actual verifier | Owned DEX, unique concrete verifier and public trust-store helper required; both three- and five-argument descriptors recognized |
| Cronet public-key pins | Returns an empty List from the owned builder's evidenced `publicKeyPins()` getter | Avoids native pin registration even when the app disables bypass for local anchors |
| Standard OkHttp hostname checks | Optional true-return bodies for recognized implementations | Enabled by `--relax-hostname` |
| Apache hostname checks | Optional method bodies plus rewritten calls in owned DEX | Call-site helpers also cover calls to a platform-loaded Apache implementation; reflective calls and checks wholly inside external code remain uncovered |
| Bundled OpenSSL/BoringSSL exports | ARM64 entry trampolines, with exact API return/callback contracts | Explicit `--native-tls offline-arm64`; no library is added or replaced with another version |
| Hidden/static BoringSSL, including Flutter | Bounded purpose-string/code/table/alert locator, then an original-call wrapper | Requires one unique verifier; source library bytes determine its address |
| Dart TLS rejection callback | Covered by the measured Flutter/BoringSSL wrapper | Original callback execution was retained in the fixture |
| Post-handshake Dart pin predicate | Snapshot-matched analysis identifies a synchronous bool predicate and returns the runtime's actual Dart true object | Explicit `--dart-pinning`; retained types and certificate/pin/comparison evidence required |
| Go, rustls, IL2CPP and Mono leads | Static runtime diagnostics in triage | The source catalog provides presence markers, not generic bypass implementations; none is claimed here |

## Operator commands

Chromium/Cronet recognition is included in the normal Java patch pass. Native,
Dart and general hostname changes are explicit options:

```sh
. /home/water/workspace/Projects/pentest/tools/configure
python -m repack patch ORIGINAL.apk --out .work/outputs/new.apk \
  --key .work/keys/repack.p12 --ca PUBLIC_PROXY_CA.pem --device SERIAL \
  --native-tls offline-arm64 --relax-hostname
```

For typed Dart predicates, prepare the matching analyzer once, then add
`--dart-pinning` to the patch command:

```sh
python -m scripts.setup_dart_analysis --apk ORIGINAL.apk --fetch
# For extracted/split libraries, use --libapp and --libflutter instead of --apk.
python -m repack patch ORIGINAL.apk --out .work/outputs/new-dart.apk \
  --key .work/keys/repack.p12 --ca PUBLIC_PROXY_CA.pem --device SERIAL \
  --native-tls offline-arm64 --dart-pinning
```

Native/Dart validation and native proxy routing are separate. Stacks that ignore
Java's ProxySelector still need an appropriate route; the loopback TLS fixtures
do not establish a generic native proxy route.

The setup command owns only its ignored `.work/` tool cache. Its source commit,
metadata-export patch, Python wheels and prepared analyzer binary are pinned.
The cached setup can be checked without `--fetch`. Normal APK patching never
fetches/builds a Dart VM or executes the generated Frida script. Current setup
wheels target Linux x86_64/CPython3.14; the measured Dart runtime is3.0.6. Blutter's
MIT license is retained in [the license file](licenses/Blutter-MIT.txt).

## Transformation contracts

Chromium gets the operator-selected CA, rather than each received leaf. A generated
class initializer installs it once per helper/class loader; verification still
produces the framework/library's real result and nonempty certificate chain.
The original OCSP/SCT parameters are forwarded. Missing, private, ambiguous or
external helpers and reserved helper-class collisions are refused.

The Cronet pin getter returns `Collections.emptyList()`, preserving its List
contract. Hostname call-site edits preserve invocation width, try/debug offsets,
other instructions and a null receiver's NullPointerException. Default patching
keeps ordinary hostname validation enabled.

The native adapter resolves ELF virtual/file mappings and RELA, Android APS2 and
RELR pointer relocations. Exported APIs use explicit contracts; the hidden
BoringSSL locator additionally requires both purpose references, a surrounding
function-pointer table and the alert prologue. Chromium native libraries are
excluded from this table adapter.

A new RX load segment contains trampolines and a relocated program-header table.
Existing load addresses and relocation destinations remain intact. Gateways
handle supported direct, conditional and address-forming entry instructions, with
BTI/PAC behavior retained. Original chain verifiers run before the result is
overridden. Verify-mode setters retain ordinary callback side effects; custom
verification callbacks are replaced with their API-specific success value.
Getter `SSL_get_verify_result` returns zero. Peer-chain/session state is checked
by real TLS fixtures. These edits bypass chain/endpoint validation as well as pins.
Independent digest comparisons remain separate. Injected wrappers have no
asynchronous unwind metadata.

Dart analysis exports normalized code/entry ranges, signatures, async flags and
snapshot-derived boolean/null-register information. Selection requires a named
pin/fingerprint predicate, an X509Certificate parameter, a nonnullable synchronous
bool result, a pin literal and comparison evidence. Dynamic equality dispatch is
accepted only when the matching snapshot identifies that String slot as equality.
Checked, unchecked and monomorphic entries are bounded and patched together.
A C boolean or a fabricated Future is never substituted for a Dart object.
Erased, shared, inlined, async or unrecognized predicates remain unsupported.

## Repeatable verification

The fixture runners create their own packages, verify installed hashes and clean
up only those packages and their loopback mappings. They preserve Midway, existing
proxy settings and root/module configuration. Fixture requests reach owned local
TLS origins; no account or external backend is exercised.

```sh
REPACK_TEST_SDK=1 python -m unittest discover -s tests -v
python -m scripts.pinning_expansion_cases --bind 10.20.30.2
python -m scripts.dart_pinning_cases --bind 10.20.30.2
python -m scripts.pinning_public_cases --bind 10.20.30.2
```

Use127.0.0.1 (the default) with a local ADB server. The workspace's remote ADB
server requires its reachable workspace bind10.20.30.2.

The direct Cronet fixture uses real119 native code, an intentionally wrong public
key pin and local-anchor bypass explicitly disabled. Its anchor-only control
isolates the native pin gate; the full patch must succeed, while a wrong hostname
still fails. Hostname fixtures exercise real OkHttp and Apache paths. OpenSSL3.0.16
and3.4.1 use real Android handshakes, ordinary/custom callbacks, peer certificates
and a response payload. The Flutter fixture separates callback rejection from
post-handshake comparison, with an unrelated boolean negative control. Public
composition additionally checks that default patching preserves native/AOT bytes.

Acceptance is limited to the recorded API30/ARM64, target35 phone and tested
libraries/runtime. Other releases, ABIs, external providers, mutual TLS and
arbitrary application checks need their own evidence. Runtime reports remain
separate from signed artifact manifests.

The Cronet fixture uses a `.localhost` hostname and its own resolver rule so the
operator's existing global proxy can remain untouched. Chromium documents these
[implicit loopback proxy bypasses](https://chromium.googlesource.com/chromium/src/+/refs/tags/138.0.7204.147/net/proxy_resolution/proxy_bypass_rules.cc).

## Recorded acceptance

- Host regression:126 tests passed, final log
  `.work/pinning-expansion-final-regression.stderr.log` (146.214s).
- Direct Android expansion:14 observations, including isolated CA rejection,
  real Cronet pin rejection, full success and retained wrong-host rejection:
  `.work/evidence/runs/20261107T233554-065035aad7/report.json`.
- Flutter/Dart controls:6 observations separating callback and post-handshake
  pin decisions, preserving the unrelated boolean control:
  `.work/evidence/runs/20261107T231933-fc947d79ea/report.json`.
- Public CLI composition:6 runtime observations and native/AOT default-byte
  preservation, with signed artifact metadata and installed-hash checks:
  `.work/evidence/runs/20261107T234046-743fbaf153/report.json`.
- Static native corpus:9 successful ELF rewrites (six BoringSSL libraries and
  three OpenSSL libraries); external Chromium was excluded. This is host-only:
  `.work/evidence/runs/20261107T234334-30d667799f/report.json`.
- Final state:both owned fixture packages, listener and reverse removed;
  Midway's installed hashes and the operator's global proxy preserved:
  `.work/evidence/runs/20261107T234857-6997f8cd13/report.json`.
- Bound handoff: `.work/evidence/PINNING-EXPANSION-handoff.json`.

The retained Midway libflutter image has no static purpose-string/pointer match
for this locator. No new native or Dart Midway patch is claimed. The installed,
previously verified Midway artifact remains unchanged; login was not exercised.
The expansion fixture's two OpenSSL input binaries are existing read-only local
test assets, pinned in `config/pinning-expansion-dependencies.json`. They and the
other fixture dependencies are not production patch prerequisites.
