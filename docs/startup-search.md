# Standalone plain-repack startup search

`python -m repack startup` rebuilds an APK or selected split set, runs bounded
startup experiments on the selected phone, and chooses the next experiment using
coded rules. It has no model, prompt, AI API, or target-profile dependency.
This command is separate from `patch`: it changes no proxy, CA, or pinning policy.

```sh
. /home/water/workspace/Projects/pentest/tools/configure
python -m repack startup ORIGINAL_APK_OR_SELECTED_DIRECTORY \
  --out .work/outputs/startup-search-01 --key .work/keys/repack.p12 \
  --device SERIAL --replace-existing-and-wipe-data \
  --max-trials 8 --observe-seconds 60
```

Use a fresh output directory and immutable original inputs. The replacement flag
authorizes clearing **this target's app data for every distinct trial**. All APKs
use the same persistent operator key. The ordinary keystore environment variables
documented in the [key guide](technical-guide.md#operator-key-and-proxy) apply.
`pkg:PACKAGE` pulls the installed selected set; use it
only when that installed set is the original input you intend to analyze.

The current rules are:

1. Verify original selected-member signatures and extract their actual certificate
   SHA-256 values, independent of distribution source stamps.
2. Inspect standard DEX instructions and their array payloads. Discover 64-character
   arrays passed to a char-array decoder that constructs a String, with a nearby
   String-array use. For each, solve and verify
   `C[i] = P[i] XOR ((i * multiplier) & 65535) XOR mask` for **every character** of
   the original signer fingerprint. Class names, method names, payload locations,
   and encoding constants come from the APK. This is one recognized encoding
   family, not a general Dalvik interpreter or proof of a check's whole semantics.
3. Create one signer-payload repair axis per recognized payload. Re-encode the
   replacement certificate fingerprint with the discovered parameters; preserve
   all instructions, payload size and other DEX bytes, except required DEX headers.
4. When declared, create a separate axis to remove only
   `android.permission.QUERY_ALL_PACKAGES`. Retain every explicit `<queries>` entry.
   This experiment changes package enumeration and can affect app functionality.
5. Decode/build the base resources once with the pinned resource engine. Preserve
   original resource bindings and opaque payloads using the existing rebuild
   checks. Construct every trial from that baseline; sign all selected splits.
6. Test the plain rebuild first. On an application-creation crash, prioritize a
   signer-payload change; on a later failure, prioritize the visibility experiment.
   Try untested combinations with a small best-first subset search. Classification
   controls order; it never proves which check caused a crash.
7. For each candidate, preflight, install, clear only the target's data, launch its
   resolved launcher, and capture live logs. Match Java crashes, native crashes and
   ANRs to the target package, including its colon-suffixed processes. Check main
   PID stability, foreground focus and actual installed member hashes. Retain a
   screenshot and a UI dump where available.
8. Confirm the first surviving candidate with a second cold launch, using its
   retained data and the same artifact hashes. Leave the final tested artifact
   installed and force-stopped. A successful observation means **startup liveness**
   for that window. A maintenance/error page can survive; login and service
   functionality remain `not-run`.

`startup-search.json` checkpoints each choice, observation, crash classification,
confirmation and artifact path. `analysis.json` records discovered parameters and
input-bound candidate offsets. These offsets are evidence generated from the
current input, not reusable hardcoded profiles. Each trial's `artifact.json` binds
all member paths and hashes. These internal plain-repack manifests use no injected
artifact marker and are distinct from `patch` manifests accepted by `verify`.

The default budget is eight distinct candidate combinations; `--max-trials` accepts
1–32. Confirmation launches are additional observations. At most six repair axes
are enumerated (64 combinations), with a 4,096 candidate-array inspection budget,
bounded subprocesses and 15–300-second observations in five-second increments.
Exhaustion reports attempted and remaining combinations; it never invents an
arbitrary branch patch. Infrastructure failures interrupt the run separately from
app crashes. Interrupted/exhausted runs retain their evidence and last installed
trial; there is no automatic restoration of Play provenance or lost app data.

The engine currently does not discover arbitrary encrypted containers, devirtualize
native checks, infer all encodings, or automatically identify a blacklist's exact
matched installed package. Those parts of the earlier Midway investigation remain
manual analysis. New recognizers and experiment rules can be added independently
of the search controller. The current visibility rule can test the useful ablation
without claiming it has reconstructed that encrypted check.

Host verification:

```sh
REPACK_TEST_SDK=1 python -m unittest discover -s tests -p test_startup.py -v
```

This includes real assembled DEX fixtures with renamed classes/methods, relocated
payloads, changed encoding parameters, an unrelated hash negative control, and
input-hash binding. Unit controls cover crash attribution, bounded/deduplicated
search, failure-guided combinations, failed confirmation and infrastructure errors.

## Measured standalone run

On 2026-11-07 the CLI processed the original four-member Midway1.85.0 set on
the connected API30/ARM64 phone, with no target profile supplied. It independently
derived one signer-payload location and its multiplier/mask, then chose:

| Trial | Selected changes | Observation |
| --- | --- | --- |
| 1 | Plain resource rebuild/re-sign | Application initialization crash |
| 2 | Discovered signer payload | Background Java crash |
| 3 | Signer payload plus permission removal | Stable foreground for 60 seconds |
| Confirmation | Same trial 3 APKs, retained data | Stable foreground for 60 seconds |

The two passing processes had PIDs 14776 and 14777. Installed APK hashes were
checked around both observations. The winner remains installed and force-stopped.
The screen still reports maintenance/error; service/login verification is not run.
The 91-test host suite passed with `REPACK_TEST_SDK=1`.

An independent comparison confirms all 6 DEX payloads, the manifest and the NSC
match the earlier manually measured H10 repair. Only the discovered 128-byte DEX
configuration region and standard headers differ from the original DEX; all 50
native libraries and 269 opaque entries retain their original bytes/storage.

Local evidence: `.work/outputs/startup-generic-midway-02/startup-search.json`,
`independent-preservation.json` in that directory, and
`.work/evidence/runs/20261107T032955-0db34c7c2c/report.json`.
An earlier run, `startup-generic-midway-01`, was interrupted to fix a missing
focus-field oracle in Android30's narrowed window dump. It is not acceptance
evidence. The corrected runner reads the full dump and treats an unavailable
focus field as an infrastructure prerequisite failure.
