"""Typed, snapshot-bound ARM64 Dart pin predicates; no C-ABI boolean guesses.

The optional analyzer is a pinned Blutter build with a metadata-only exporter.
Normal patching never builds/downloads a Dart VM, runs Frida, or loads target code.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile

from .elf_tls import Elf
from .native_tls import aot_snapshots
from .rebuild import ROOT, PrerequisiteError, execute, sha256, write_json


class DartPinningUnsupported(ValueError):
    pass


def identity(data):
    elf = Elf(data); elf.symbols()
    snapshots = [s for s in elf.dynsymbols.values() if s['name'] == '_kDartVmSnapshotData' and s['defined']]
    if len(snapshots) != 1: raise DartPinningUnsupported('Dart VM data symbol is absent/ambiguous')
    offset = elf.offset(snapshots[0]['value'], 52)
    snapshot_hash = data[offset + 20:offset + 52].decode('ascii', errors='replace')
    if not re.fullmatch('[0-9a-f]{32}', snapshot_hash): raise DartPinningUnsupported('Unknown Dart snapshot header')
    aot_snapshots(data, snapshot_hash)
    flags = data[offset + 52:offset + 1076].split(b'\0', 1)[0].decode('ascii', errors='strict')
    if not flags or 'arm64' not in flags or 'android' not in flags or 'product' not in flags:
        raise DartPinningUnsupported('Only Android ARM64 product AOT snapshots are supported')
    return {'snapshot_hash': snapshot_hash, 'flags': flags, 'abi': 'arm64-v8a'}


def read_metadata(path):
    rows = path.read_text().splitlines(); header = {}; functions = []
    for line in rows:
        fields = line.split('\t')
        if len(fields) == 2 and fields[0] in ('bool_true_from_null', 'null_register', 'string_equality_gdt_zero'):
            if fields[0] in header: raise DartPinningUnsupported('Duplicate Dart ABI metadata')
            header[fields[0]] = int(fields[1]); continue
        if len(fields) != 9: raise DartPinningUnsupported('Invalid typed Dart metadata row')
        addresses = [int(value,16) for value in fields[:5]]
        decoded = [bytes.fromhex(value).decode('utf-8') for value in fields[6:]]
        functions.append(dict(zip(('entry', 'unchecked', 'monomorphic', 'payload', 'size'), addresses),
                              async_function=fields[5] != '0', return_type=decoded[0], parameters=decoded[1], name=decoded[2]))
    if set(header) != {'bool_true_from_null', 'null_register', 'string_equality_gdt_zero'} or not 0 < header['bool_true_from_null'] < 4096 or not 0 <= header['null_register'] < 31 or header['string_equality_gdt_zero'] not in (0, 1):
        raise DartPinningUnsupported('Missing/unsupported snapshot-derived Dart boolean ABI')
    return header, functions


def bodies(directory):
    result = {}
    for path in sorted(directory.rglob('*.dart')):
        text = path.read_text(errors='strict')
        for match in re.finditer(r'// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)\n(.*?)^  }', text, re.S | re.M):
            entry = int(match[1],16)
            if entry in result: raise DartPinningUnsupported('Ambiguous Dart assembly function identity')
            result[entry] = {'text':match[3], 'path':str(path), 'sha256':sha256(path)}
    return result


def select(functions, assembly, abi):
    accepted = []; rejected = []; by_payload = {}
    for row in functions: by_payload.setdefault(row['payload'], set()).add(row['name'])
    for row in functions:
        name = row['name']; code = assembly.get(row['entry'], {}).get('text', '')
        words = re.sub(r'([a-z])([A-Z])',r'\1 \2',name).replace('_',' ')
        if not re.search(r'\b(?:pin(?:s|ned|ning)?|fingerprint)\b', words, re.I) or 'X509Certificate' not in row['parameters']: continue
        reason = None
        if row['return_type'] != 'bool' or row['async_function']: reason = 'requires-synchronous-nonnullable-bool'
        elif len(by_payload[row['payload']]) != 1: reason = 'shared-code-identity'
        elif not row['name'].startswith('[package:'): reason = 'not-application-or-package-code'
        elif not re.search(r'"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|sha256/[A-Za-z0-9+/]{43}=)"', code): reason = 'missing-pin-literal'
        elif not re.search(r'::(?:==|equals)|StringBase.*equals|String.*_equals', code):
            # AOT may dispatch String.== through the GDT rather than a named BL.
            # The exporter proves the zero-offset String slot is actually == in
            # this snapshot. Do not infer its meaning from a register sequence.
            dispatch = re.search(r'mov\s+lr,\s*x\d+.*?ldr\s+lr,\s*\[x21,\s*lr,\s*lsl #3\].*?blr\s+lr', code, re.S)
            if not abi['string_equality_gdt_zero'] or not dispatch: reason = 'missing-string-comparison'
        if reason: rejected.append({**row, 'reason':reason})
        else: accepted.append(row)
    return {'accepted':accepted, 'rejected':rejected}


def rewrite(data, abi, functions):
    elf = Elf(data); output = bytearray(data); changes = {}; selected = []
    instruction = 0x91000000 | (abi['bool_true_from_null'] << 10) | (abi['null_register'] << 5)
    for row in functions:
        if row['return_type'] != 'bool' or row['async_function']: raise DartPinningUnsupported('Dart predicate return contract mismatch')
        low, high = row['payload'], row['payload'] + row['size']
        entries = sorted({row['entry'],row['unchecked'],row['monomorphic']})
        if not entries or entries[0] < low or entries[-1] + 8 > high or any(e % 4 for e in entries):
            raise DartPinningUnsupported('Dart entry points are not bounded by their code payload')
        words = {}
        for entry in entries:
            words[entry] = instruction
            words.setdefault(entry + 4, 0xd65f03c0)
        edits = []
        for address,value in sorted(words.items()):
            offset = elf.offset(address,4,True)
            if offset in changes and changes[offset] != value: raise DartPinningUnsupported('Conflicting Dart function edits')
            changes[offset] = value; payload = struct.pack('<I',value)
            output[offset:offset + 4] = payload
            edits.append({'address':address,'file_offset':offset,'original_hex':data[offset:offset+4].hex(),'replacement_hex':payload.hex()})
        selected.append({**row,'replacement':'dart-synchronous-bool-true','edits':edits})
    if not selected: raise DartPinningUnsupported('No typed synchronous Dart pin predicate matched')
    return bytes(output), selected


def analyze(data, evidence):
    evidence.mkdir(); ident = identity(data)
    config = ROOT / 'config/dart-analysis-dependency.json'
    if not config.is_file(): raise PrerequisiteError('Prepare the optional Dart analyzer with scripts/setup_dart_analysis.py')
    registry = json.loads(config.read_text())
    matches = [r for r in registry['runtimes'] if r['snapshot_hash'] == ident['snapshot_hash'] and r['flags'] == ident['flags']]
    if len(matches) != 1: raise DartPinningUnsupported('No unique prepared analyzer for this Dart snapshot/flags; run scripts/setup_dart_analysis.py for the input')
    runtime = matches[0]; binary = ROOT / runtime['analyzer']['path']
    if not binary.is_file() or sha256(binary) != runtime['analyzer']['sha256']: raise PrerequisiteError('Prepared Dart analyzer hash changed')
    original = evidence / 'libapp.so'; original.write_bytes(data); directory = evidence / 'analysis'
    execute([str(binary), '-i',str(original),'-o',str(directory)],evidence,'dart-analyzer',timeout=180)
    abi, functions = read_metadata(directory / 'repack-functions.tsv')
    assembly = bodies(directory / 'asm'); candidates = select(functions,assembly,abi)
    write_json(evidence / 'candidates.json',candidates)
    output, edits = rewrite(data,abi,candidates['accepted'])
    return output, {'mode':'dart-typed-arm64','input_sha256':hashlib.sha256(data).hexdigest(),
        'output_sha256':hashlib.sha256(output).hexdigest(), **ident,'dart_abi':abi,'functions':edits,
        'analyzer_sha256':runtime['analyzer']['sha256'],'analyzer_path':runtime['analyzer']['path'],
        'analyzer_metadata_sha256':sha256(directory/'repack-functions.tsv'),
        'dependency_pin_sha256':sha256(config),'runtime_verification':'not-run',
        'limitations':['Retained synchronous bool signatures and explicit certificate/pin/comparison evidence required',
                       'Async, erased, inlined, shared-code and unrecognized predicates remain unsupported',
                       'No C bool stub is applied to Dart objects or Future-returning methods']}


def plan(source,evidence):
    if source.get('effective_abi') != 'arm64-v8a': raise DartPinningUnsupported('Dart pinning requires an existing selected ARM64 ABI')
    found = []
    for member in source['members']:
        with zipfile.ZipFile(member['apk']) as archive:
            entry = 'lib/arm64-v8a/libapp.so'
            if entry in archive.namelist(): found.append((member.get('split') or 'base',entry,archive.read(entry)))
    if len(found) != 1: raise DartPinningUnsupported('AOT input is absent/ambiguous')
    member,entry,data = found[0]; output,transform = analyze(data,evidence)
    return output, {**transform,'member':member,'entry':entry}
