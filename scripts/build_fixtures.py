#!/usr/bin/env python3
"""Build M0 release fixtures with the installed SDK, without Gradle."""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import sys
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from repack.rebuild import (ROOT, build_fixture, ensure_keys, fixture_source_hash, load_lock, report, sha256, write_json)


def core_factory() -> tuple[Path, dict]:
    coordinate = 'androidx.core:core:1.15.0'
    base = 'https://dl.google.com/dl/android/maven2/androidx/core/core/1.15.0/core-1.15.0'
    directory = ROOT / '.work/tools/androidx-core-1.15.0'
    directory.mkdir(parents=True, exist_ok=True)
    for extension in ('aar', 'pom'):
        path = directory / ('core-1.15.0.' + extension)
        if not path.exists():
            data = urllib.request.urlopen(base + '.' + extension, timeout=60).read()
            temporary = path.with_suffix(path.suffix + '.download')
            temporary.write_bytes(data)
            temporary.replace(path)
    aar = directory / 'core-1.15.0.aar'
    lock_path = directory / 'artifact.json'
    digest = sha256(aar)
    if lock_path.exists() and json.loads(lock_path.read_text())['sha256'] != digest:
        raise RuntimeError('Pinned AndroidX artifact hash changed')
    extracted = directory / 'factory-classes.jar'
    with zipfile.ZipFile(aar) as archive:
        with zipfile.ZipFile(io.BytesIO(archive.read('classes.jar'))) as classes:
            names = sorted(name for name in classes.namelist()
                           if name.startswith('androidx/core/app/CoreComponentFactory') and name.endswith('.class'))
            if 'androidx/core/app/CoreComponentFactory.class' not in names:
                raise RuntimeError('AndroidX factory class missing')
            with zipfile.ZipFile(extracted, 'w') as target:
                for name in names:
                    target.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), classes.read(name))
    metadata = {'coordinate': coordinate, 'source_url': base + '.aar', 'sha256': digest,
                'pom_sha256': sha256(directory / 'core-1.15.0.pom'),
                'license': 'Apache-2.0', 'selected_classes': names,
                'extracted_sha256': sha256(extracted)}
    write_json(lock_path, metadata)
    return extracted, metadata


def build() -> tuple[dict, Path]:
    result, evidence = report('M0-build')
    try:
        lock = load_lock()
        keys = ensure_keys(lock, evidence)
        core, dependency = core_factory()
        lock['tools']['androidx-core-factory'] = dependency
        write_json(ROOT / 'config/implementation-lock.json', lock)
        entries = []
        for module, identity in [('app', 'original'), ('other', 'other')]:
            for variant in ('own', 'androidx'):
                name = module + '-' + variant
                entries.append(build_fixture(module, variant, keys[identity], core, lock,
                               ROOT / '.work/outputs/fixtures' / result['run_id'] / name, evidence / name))
        result.update(verification='passed', transformation='applied', outputs=entries,
                      fixture_source_sha256=fixture_source_hash(),
                      signer_sha256=sorted(key['sha256'] for key in keys.values()),
                      dependency=dependency, keys={k: {'sha256': v['sha256'], 'certificate': v['certificate']}
                                                 for k, v in keys.items()})
        result['comparisons'].append({'name': 'independent-cert-and-APK-signer', 'result': 'passed'})
    except Exception as exc:
        result.update(verification='failed', error_class=type(exc).__name__, error=str(exc))
    result['logs'] = [str(evidence)]
    write_json(evidence / 'report.json', result)
    return result, evidence / 'report.json'


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result, immutable = build()
    result['evidence_refs'] = [str(immutable)]
    write_json(args.out, result)
    passed = result['verification'] == 'passed'
    print(('PASS' if passed else 'FAIL') + ' M0-build ' + str(args.out))
    if not passed:
        print(result.get('error', 'Build failed'), file=sys.stderr)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
