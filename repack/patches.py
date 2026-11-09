"""Conservative Java pinning matches and one complete-class shadow DEX."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile

from .rebuild import (ROOT, PrerequisiteError, align_sign, badging, environment, execute, sha256, tool, write_json)
from .pin_families import additional_match, known_shape, chromium_match, hostname_match, CHROMIUM_OWNER


class UnsupportedJavaPatch(ValueError):
    """A validly inspected input has no supported patch boundary."""


def java_dependencies(suite: str) -> list[dict]:
    selected = json.loads((ROOT / 'config/java-dependencies.json').read_text())
    result = []
    for artifact in selected['artifacts']:
        if artifact['suite'] != suite: continue
        for kind in ('jar', 'pom'):
            path = ROOT / artifact[kind]['path']
            if not path.is_file() or sha256(path) != artifact[kind]['sha256']:
                raise PrerequisiteError('Pinned Java dependency missing/changed: ' + artifact['coordinate'])
        result.append({**artifact, 'path': str(ROOT / artifact['jar']['path'])})
    if not result: raise PrerequisiteError('Java dependency suite missing: ' + suite)
    return result


def dex_tool(lock: dict, evidence: Path) -> list[str]:
    dependencies = java_dependencies('smali')
    classpath = ':'.join(item['path'] for item in dependencies)
    classes = evidence / 'dex-tool-classes'; classes.mkdir()
    execute([tool(lock, 'javac'), '--release', '8', '-classpath', classpath, '-d', str(classes),
             str(ROOT / 'tools/DexPatch.java')], evidence, 'dex-tool-javac', env=environment(lock))
    write_json(evidence / 'dex-tool-dependencies.json', {'artifacts': dependencies})
    return [tool(lock, 'java'), '-classpath', str(classes) + ':' + classpath, 'DexPatch']


def extract_dex(apk: Path, out: Path, *, allow_patched=False) -> list[Path]:
    out.mkdir()
    with zipfile.ZipFile(apk) as archive:
        if len(archive.namelist()) != len(set(archive.namelist())): raise ValueError('Duplicate ZIP members')
        if 'assets/repack/java-patches.json' in archive.namelist() and not allow_patched: raise ValueError('Previously Java-patched input')
        names = [name for name in archive.namelist() if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex', name)]
        names.sort(key=lambda name: 1 if name == 'classes.dex' else int(name[7:-4]))
        expected = ['classes.dex'] + [f'classes{i}.dex' for i in range(2, len(names) + 1)]
        if names != expected: raise ValueError('Non-contiguous/missing original DEX inventory')
        for name in names: (out / name).write_bytes(archive.read(name))
    return [out / name for name in names]


def inspect_dex(directory: Path, command: list[str], api: int, evidence: Path) -> dict:
    completed = execute([*command, 'inspect', str(api), str(directory)], evidence, 'dex-inspect', env=None)
    classes = {}; duplicates = []
    current = None
    for line in completed.stdout.splitlines():
        fields = [base64.b64decode(value, validate=True).decode() for value in line.split('\t')]
        if fields[0] == 'class' and len(fields) == 7:
            _, dex, descriptor, parent, interfaces, flags, field_types = fields
            current = {'dex': dex, 'descriptor': descriptor, 'superclass': parent,
                       'interfaces': interfaces.split(',') if interfaces else [], 'access_flags': int(flags),
                       'field_types': field_types.split(',') if field_types else [], 'methods': []}
            if descriptor in classes: duplicates.append(descriptor)
            else: classes[descriptor] = current
        elif fields[0] == 'method' and len(fields) == 8 and current is not None:
            _, owner, descriptor, flags, implementation, strings, refs, literals = fields
            if owner != current['descriptor']: raise RuntimeError('Invalid inspector class/method join')
            current['methods'].append({'descriptor': descriptor, 'access_flags': int(flags),
                'implementation': implementation, 'strings': strings.split('\0') if strings else [],
                'references': refs.split('\0') if refs else [], 'literals': [int(value) for value in literals.split(',')] if literals else []})
        else: raise RuntimeError('Invalid typed DEX inspector row')
    return {'classes': classes, 'duplicate_classes': sorted(set(duplicates))}


def find_candidates(inventory: dict, *, chromium_anchor=False, relax_hostname=False) -> dict:
    classes = inventory['classes']; accepted = []; rejected = []
    duplicate = set(inventory['duplicate_classes'])
    chromium_classes = {owner: cls for owner, cls in classes.items() if owner not in duplicate}
    def ancestors(name):
        seen = set(); pending = [name]
        while pending:
            current = pending.pop()
            if current in seen: continue
            seen.add(current)
            item = classes.get(current)
            if item: pending.extend(item['interfaces'] + ([item['superclass']] if item['superclass'] else []))
        return seen
    inherited = {}
    for cls in classes.values():
        types = ancestors(cls['descriptor'])
        for interface, prefix in [('Ljavax/net/ssl/X509TrustManager;', 'checkServerTrusted('),
                                  ('Ljavax/net/ssl/HostnameVerifier;', 'verify(')]:
            if interface not in types: continue
            current = cls
            seen = set()
            resolved = set()
            while current and current['descriptor'] not in seen:
                seen.add(current['descriptor'])
                for method in current['methods']:
                    name = method['descriptor']
                    if name.startswith(prefix) and name not in resolved:
                        inherited.setdefault((current['descriptor'], name), set()).add(cls['descriptor'])
                        resolved.add(name)
                current = classes.get(current['superclass'])
    for cls in classes.values():
        class_strings = {value for method in cls['methods'] for value in method['strings']}
        for method in cls['methods']:
            desc = method['descriptor']; owner = cls['descriptor']; strings = method['strings']; refs = method['references']
            # Field references enrich P0 triage; they are not evidence of an invoked exception
            # or certificate method for the accepted pinning matcher.
            refs = [ref for ref in refs if '->' not in ref or '(' in ref]
            hierarchy = sorted(inherited.get((owner, desc), []))
            kind = replacement = None
            okhttp_shapes = {
                '(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V': 'okhttp4-lazy-check',
                '(Ljava/lang/String;Ljava/util/List;)V': 'okhttp-list-check',
                '(Ljava/lang/String;[Ljava/security/cert/Certificate;)V': 'okhttp-array-check',
            }
            okhttp_shape = next((value for suffix, value in okhttp_shapes.items() if desc.endswith(suffix)), None)
            if (okhttp_shape
                    and any('Certificate pinning failure!' in value for value in class_strings)
                    and any('SSLPeerUnverifiedException;' in ref for ref in refs)
                    and any('pinning failure' in value.lower() for value in strings)
                    and 'Ljava/util/Set;' in cls['field_types']): kind = okhttp_shape
            elif hierarchy and re.fullmatch(r'checkServerTrusted\(\[Ljava/security/cert/X509Certificate;Ljava/lang/String;(?:Ljava/net/Socket;|Ljavax/net/ssl/SSLEngine;)?\)V', desc):
                if any(re.search(r'\bpin(?:s|ned|ning)?\b', value, re.I) for value in strings) and any('CertificateException;' in ref for ref in refs):
                    kind = 'x509-pinning-trust-manager'
            elif hierarchy and desc == 'verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z':
                if any(re.search(r'\bpin(?:s|ned|ning)?\b', value, re.I) for value in strings) and any('->getPeerCertificates()' in ref for ref in refs):
                    kind = 'pinning-hostname-verifier'
            if kind:
                replacement = 'return-void' if desc.endswith(')V') else 'return-true'
            else:
                extra = additional_match(cls, method, ancestors)
                if extra: kind, replacement = extra['kind'], extra['replacement']
            extension = chromium_match(cls, method, chromium_classes) if chromium_anchor else None
            if not extension and relax_hostname and not kind: extension = hostname_match(cls, method)
            if extension: kind, replacement = extension['kind'], extension['replacement']
            suspicious = bool(hierarchy or owner == CHROMIUM_OWNER or known_shape(cls, method) or any('pinning failure' in value.lower() or 'pin mismatch' in value.lower() for value in strings))
            candidate = {'class': owner, 'method': desc, 'dex': cls['dex'], 'kind': kind,
                         'replacement': replacement,
                         'hierarchy_evidence': hierarchy, 'access_flags': method['access_flags'],
                         'signals': {'strings': strings, 'references': refs}}
            if kind and owner not in duplicate and not desc.startswith('<') and method['implementation'] == 'present' and not method['access_flags'] & (0x100 | 0x400) and (not method['access_flags'] & 0x8 or replacement in ('chromium-anchor', 'hostname-callsite')):
                accepted.append(candidate)
            elif suspicious:
                candidate['reason'] = ('duplicate-class' if owner in duplicate else 'constructor-or-class-initializer' if desc.startswith('<') else 'native-or-abstract' if
                        method['implementation'] == 'absent' else 'insufficient-signals-or-unsupported-contract')
                rejected.append(candidate)
    selectors = {row['class'] for row in accepted if row['kind'] == 'ct-policy-selector'}
    selected = []
    for row in accepted:
        covered = sorted(selectors.intersection(ancestors(row['class']))) if row['kind'] == 'ct-interceptor' else []
        if covered:
            rejected.append({**row, 'reason': 'covered-by-ct-selector', 'covered_by': covered})
        else: selected.append(row)
    return {'accepted': selected, 'rejected': rejected}


def dex_counts(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 112 or not data.startswith(b'dex\n'): raise ValueError('Invalid standard DEX header')
    return {name: struct.unpack_from('<I', data, offset)[0] for name, offset in
            [('strings', 56), ('types', 64), ('fields', 80), ('methods', 88), ('classes', 96)]}


def patch_apk(original: Path, out: Path, key: dict, lock: dict, evidence: Path, *, chromium_ca=None, relax_hostname=False) -> dict:
    out.mkdir(parents=True, exist_ok=False)
    directory = out / 'original-dex'; dex = extract_dex(original, directory)
    command = dex_tool(lock, evidence)
    api = lock['cell']['api']; inventory = inspect_dex(directory, command, api, evidence)
    candidates = find_candidates(inventory, chromium_anchor=chromium_ca is not None, relax_hostname=relax_hostname); write_json(out / 'candidates.json', candidates)
    if not candidates['accepted']: raise UnsupportedJavaPatch('No supported Java pinning matches; see candidates.json')
    selection = out / 'selection.tsv'
    selection.write_text(''.join(item['class'] + '\t' + item['method'] + '\t' + item['replacement'] + '\n' for item in candidates['accepted']))
    shadow = out / 'classes.dex'
    context = []
    if chromium_ca is not None:
        anchor = out / 'chromium-anchor.der'; anchor.write_bytes(chromium_ca); context = [str(anchor)]
    execute([*command, 'shadow', str(api), str(directory), str(selection), str(shadow), *context], evidence, 'dex-shadow')
    counts = dex_counts(shadow)
    if counts['methods'] > 65535 or counts['types'] > 65535 or counts['fields'] > 65535:
        raise PrerequisiteError('Injected DEX exceeds the supported reference budget')
    unsigned = out / 'unsigned.apk'; mapping = []
    names = {path.name: ('classes' + str(index + 2) + '.dex') for index, path in enumerate(dex)}
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(unsigned, 'w') as target:
        target.writestr('classes.dex', shadow.read_bytes(), compress_type=zipfile.ZIP_STORED)
        for item in source.infolist():
            name = item.filename
            if name.startswith('META-INF/') and name.upper().endswith(('.SF', '.RSA', '.DSA', '.EC', 'MANIFEST.MF')): continue
            data = source.read(name); updated = copy.copy(item)
            if name in names:
                updated.filename = names[name]
                mapping.append({'original': name, 'output': updated.filename, 'sha256': hashlib.sha256(data).hexdigest(),
                                'counts': dex_counts(directory / name)})
            target.writestr(updated, data)
        target.writestr('assets/repack/java-patches.json', json.dumps({'schema_version': 1,
            'input_sha256': sha256(original), 'selection': candidates['accepted']}).encode())
    apk = out / 'patched.apk'; align_sign(unsigned, apk, key, lock, evidence)
    with zipfile.ZipFile(apk) as archive:
        for entry in mapping:
            if hashlib.sha256(archive.read(entry['output'])).hexdigest() != entry['sha256']:
                raise RuntimeError('Original DEX payload changed')
    info, _ = badging(apk, lock, evidence, 'java-patched-badging')
    result = {**info, 'apk': str(apk), 'sha256': sha256(apk), 'signer_sha256': [key['sha256']],
              'input': str(original), 'input_sha256': sha256(original), 'packaging': 'shadow',
              'dex_mapping': mapping, 'injected_dex_counts': counts, 'patches': candidates['accepted'],
              'rejected': candidates['rejected']}
    write_json(out / 'artifact.json', result)
    return result
