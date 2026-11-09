"""The limited public CLI defined in PLAN section 6."""
import argparse
from pathlib import Path
import sys

from .rebuild import PrerequisiteError, load_lock, report, write_json
from .pipeline import UnsupportedOperation, patch, validate_toolchain
from .recon import triage
from .containers import ContainerUnsupported
from .report import write_report, render_review
from .runtime import verify_runtime
from .shim import parse_proxy
from .verify import verify_artifact
from .startup import startup


def proxy_argument(value):
    try: return parse_proxy(value)
    except ValueError as error: raise argparse.ArgumentTypeError(str(error)) from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='repack')
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('triage'); inspect.add_argument('input'); inspect.add_argument('--device'); inspect.add_argument('--device-spec', type=Path)
    build = commands.add_parser('patch'); build.add_argument('input'); build.add_argument('--out', type=Path, required=True)
    build.add_argument('--key', type=Path, required=True); build.add_argument('--device'); build.add_argument('--device-spec', type=Path)
    for flag in ('antitamper', 'dex-only', 'trust-only'): build.add_argument('--' + flag, action='store_true')
    build.add_argument('--ca', type=Path); build.add_argument('--proxy', type=proxy_argument)
    build.add_argument('--relax-hostname', action='store_true', help='Optional relaxation of recognized app-owned OkHttp/Apache hostname checks')
    build.add_argument('--dart-pinning', action='store_true', help='Optional typed ARM64 AOT pin predicates; requires a prepared matching Dart analyzer')
    build.add_argument('--gadget', choices=['raw-apk-fixture'], help='Explicit optional script-mode Gadget; owned API30 ARM64 fixture only')
    build.add_argument('--native-tls', choices=['reflutter-3.10.6-arm64', 'offline-arm64'], help='Explicit native TLS mode: exact reFlutter engine or app-owned ARM64 export/table edits')
    build.add_argument('--integrity', help='Opt-in native-base-bytes:libCaller.so[,libOther.so], measured API30 ARM callers only')
    start = commands.add_parser('startup', help='Bounded plain-repack/startup repair search, without proxy or pinning changes')
    start.add_argument('input'); start.add_argument('--out', type=Path, required=True)
    start.add_argument('--key', type=Path, required=True); start.add_argument('--device', required=True)
    start.add_argument('--replace-existing-and-wipe-data', action='store_true')
    start.add_argument('--max-trials', type=int, default=8)
    start.add_argument('--observe-seconds', type=int, default=60)
    verify = commands.add_parser('verify'); verify.add_argument('manifest', type=Path); verify.add_argument('--device', required=True)
    verify.add_argument('--proxy', type=proxy_argument); verify.add_argument('--replace-existing-and-wipe-data', action='store_true')
    verify.add_argument('--runtime-evidence', type=Path, help='Read-only assessment of an artifact-bound capture packet; skips installation')
    verify.add_argument('--review', type=Path, help='Write a new concise Markdown review without raw payloads')
    args = parser.parse_args(argv)
    result, evidence = report('cli-' + args.command); result['command']['argv'] = argv if argv is not None else sys.argv
    status = 0
    try:
        if args.command == 'verify' and args.review is not None and (args.review.exists() or args.review.is_symlink() or args.review.suffix.lower() != '.md'):
            raise ValueError('Choose a fresh .md review output path')
        if args.command == 'verify' and args.runtime_evidence is not None and args.replace_existing_and_wipe_data:
            raise ValueError('--runtime-evidence is read-only and conflicts with replacement authorization')
        lock = load_lock()
        if args.command == 'triage':
            validate_toolchain(lock, device=bool(args.device))
            inventory = triage(args.input, args.device, lock, evidence / 'triage', allow_patched=True, device_spec=args.device_spec)
            result.update(verification='passed', inventory=inventory, scope='read-only input/signature/typed-reference triage; enforcement unknown')
            print('TRIAGED', inventory['package'], len(inventory['members']), 'member(s)', evidence / 'report.json')
        elif args.command == 'patch':
            built = patch(args.input, vars(args), lock, evidence)
            result.update(transformation='applied', verification='not-run', artifact_manifest=built['manifest'],
                          scope='host-verified artifact build; runtime not-run', outputs=built['artifact']['outputs'])
            print('BUILT', built['manifest'], '(host verified; runtime not-run)')
        elif args.command == 'startup':
            searched = startup(args.input, vars(args), lock, evidence, result['device_mutations'])
            result.update(searched, transformation='applied',
                          verification='passed' if searched['startup_verification'] == 'passed' else 'failed')
            status = 0 if searched['startup_verification'] == 'passed' else 1
            if status: result['reason'] = 'Startup repair trial budget or applicable combinations exhausted; see startup-search.json'
            print('STARTUP', searched['startup_verification'], searched['manifest'])
        elif args.runtime_evidence is not None:
            assessed = verify_runtime(args.manifest, args.runtime_evidence, args.device, lock, evidence, proxy=args.proxy)
            result.update(assessed); status = 1 if assessed['runtime_verification'] == 'failed' else 0; print('RUNTIME', assessed['runtime_verification'], assessed['reason'], evidence / 'report.json')
        else:
            verified = verify_artifact(args.manifest, args.device, lock, evidence, proxy=args.proxy,
                                       replace_existing=args.replace_existing_and_wipe_data, mutations=result['device_mutations'])
            result.update(verified); print('PASS artifact/install; runtime not-run', evidence / 'report.json')
    except (UnsupportedOperation, ContainerUnsupported) as error:
        result.update(transformation='unsupported', error=str(error)); status = 4
    except PrerequisiteError as error:
        result['prerequisite_failures'].append(str(error)); status = 3
    except KeyboardInterrupt:
        result.update(verification='not-run', reason='Operator interruption; partial evidence retained'); status = 130
    except Exception as error:
        result.update(transformation='failed', verification='failed', error_class=type(error).__name__, error=str(error)); status = 1
    if args.command == 'verify' and args.review is not None and not args.review.exists():
        try: render_review(result, args.review); result['human_review'] = str(args.review.resolve())
        except Exception as error:
            result.update(verification='failed', error_class=type(error).__name__, error=str(error)); status = 1
    result['command']['exit_status'] = status; result['logs'].append(str(evidence))
    write_json(evidence / 'report.json', result)
    print('EVIDENCE', evidence / 'report.json')
    if status: print('BLOCKED' if status == 3 else 'UNSUPPORTED' if status == 4 else 'FAIL', result.get('error') or result.get('reason') or '; '.join(result['prerequisite_failures']), file=sys.stderr)
    return status
