#!/usr/bin/env python3
"""Internal gate-scoped patch experiments; this command never installs."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from repack.rebuild import ROOT, PrerequisiteError, badging, ensure_keys, load_lock, report, signer_digests, write_json
from repack.shim import build_bootstrap, parse_proxy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    patch = commands.add_parser('patch')
    patch.add_argument('--input', type=Path, required=True)
    patch.add_argument('--out', type=Path, required=True)
    patch.add_argument('--key', type=Path, required=True)
    patch.add_argument('--mode', choices=['bootstrap', 'routing', 'identity'], required=True)
    patch.add_argument('--proxy', type=parse_proxy)
    args = parser.parse_args()
    result, evidence = report('spike-' + args.mode)
    status = 'FAIL'
    try:
        if args.mode == 'bootstrap' and args.proxy is not None:
            raise ValueError('--proxy requires --mode routing')
        lock = load_lock()
        keys = ensure_keys(lock, evidence)
        if args.key.resolve() != Path(keys['repack']['path']).resolve():
            raise PrerequisiteError('The bootstrap spike uses the persistent repack fixture key')
        proxy = (args.proxy or parse_proxy('127.0.0.1:8080')) if args.mode == 'routing' else None
        identity = {}
        if args.mode == 'identity':
            info, _ = badging(args.input.resolve(), lock, evidence, 'identity-input')
            key_name = {'dev.repack.fixture.identity': 'original', 'dev.repack.fixture.other': 'other'}.get(info['package'])
            if key_name is None:
                raise PrerequisiteError('Identity spike accepts owned fixtures; general certificate extraction opens in M1b-3')
            actual = signer_digests(args.input.resolve(), lock, evidence, 'identity-input-signers')
            verified = (evidence / 'identity-input-signers.stdout.log').read_text()
            if actual != [keys[key_name]['sha256']] or 'Verified using v3 scheme (APK Signature Scheme v3): true' not in verified:
                raise PrerequisiteError('Input does not match the owned original fixture certificate and v3 signing truth')
            identity = {'identity_mode': 'identity', 'probe_token': result['run_id'],
                        'original_certificates': [Path(keys[key_name]['certificate']).read_bytes()], 'original_scheme': 3}
            proxy = args.proxy
        artifact = build_bootstrap(args.input.resolve(), args.out.resolve(), keys['repack'], lock, evidence, proxy=proxy, **identity)
        result.update(verification='passed', transformation='applied', outputs=[artifact],
                      scope='Host artifact build/signature verification only; no installation or runtime acceptance')
        status = 'PASS'
    except PrerequisiteError as error:
        result['prerequisite_failures'].append(str(error)); status = 'BLOCKED'
    except Exception as error:
        result.update(verification='failed', error_class=type(error).__name__, error=str(error))
    result['logs'] = [str(evidence)]
    write_json(evidence / 'report.json', result)
    print(status, result['case_id'], evidence / 'report.json')
    if status != 'PASS':
        print(result.get('error') or result['prerequisite_failures'], file=sys.stderr)
    return 0 if status == 'PASS' else 3 if status == 'BLOCKED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
