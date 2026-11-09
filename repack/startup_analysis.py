"""Discover a bounded signer-string encoding family from verified input certificates.

The known plaintext is the APK's signer SHA-256, not a target-specific constant.
All 64 characters must match, and a typed local use must pass the array to a
char-array decoder that builds a String. Trial execution establishes usefulness.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re
import struct
import zlib

from .patches import extract_dex, java_dependencies
from .rebuild import ROOT, environment, execute, sha256, tool, write_json


def fingerprint(value: str) -> str:
    if not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError('Expected lowercase SHA-256 certificate fingerprint')
    return value


def infer_affine_xor(values: list[int], plaintext: str) -> dict | None:
    """Solve C[i] = P[i] XOR ((i * multiplier) mod 65536) XOR mask."""
    fingerprint(plaintext)
    if len(values) != 64 or any(not 0 <= v <= 65535 for v in values): return None
    mask = values[0] ^ ord(plaintext[0])
    multiplier = values[1] ^ ord(plaintext[1]) ^ mask
    if not all(v ^ ord(p) == ((i * multiplier) & 65535) ^ mask
               for i, (v, p) in enumerate(zip(values, plaintext))): return None
    return {'multiplier': multiplier, 'mask': mask, 'verified_characters': 64}


def encode_affine_xor(plaintext: str, parameters: dict) -> bytes:
    fingerprint(plaintext)
    return struct.pack('<64H', *(ord(c) ^ ((i * parameters['multiplier']) & 65535) ^ parameters['mask']
                               for i, c in enumerate(plaintext)))


def check_dex(data: bytes) -> None:
    if len(data) < 112 or not re.fullmatch(rb'dex\n0(?:35|37|38|39|40)\x00', data[:8]):
        raise ValueError('Expected supported standard DEX version 035–040')
    if struct.unpack_from('<I', data, 32)[0] != len(data) or struct.unpack_from('<I', data, 40)[0] != 0x12345678:
        raise ValueError('Invalid DEX size/endianness')
    if hashlib.sha1(data[32:]).digest() != data[12:32] or zlib.adler32(data[12:]) & 0xffffffff != struct.unpack_from('<I', data, 8)[0]:
        raise ValueError('DEX checksum/signature mismatch')


def discover_signer_payloads(apk: Path, original_signers: list[str], api: int, lock: dict, evidence: Path) -> dict:
    evidence.mkdir(parents=True, exist_ok=False)
    for signer in original_signers: fingerprint(signer)
    dex_paths = extract_dex(apk, evidence / 'dex')
    for path in dex_paths: check_dex(path.read_bytes())
    dependencies = java_dependencies('smali'); cp = ':'.join(row['path'] for row in dependencies)
    classes = evidence / 'classes'; classes.mkdir()
    execute([tool(lock, 'javac'), '--release', '8', '-cp', cp, '-d', str(classes), str(ROOT / 'tools/StartupDex.java')],
            evidence, 'compile', env=environment(lock))
    output = execute([tool(lock, 'java'), '-Xmx768m', '-cp', str(classes) + ':' + cp, 'StartupDex', str(api), str(evidence / 'dex')],
                     evidence, 'inspect', env=environment(lock), timeout=120).stdout
    accepted = {}; examined = 0
    for line in output.splitlines():
        fields = [base64.b64decode(v, validate=True).decode() for v in line.split('\t')]
        if len(fields) != 8: raise RuntimeError('Invalid typed startup inspector row')
        dex, caller, offset, values, decoder, reads, builds, string_array = fields
        examined += 1
        if reads != 'true' or builds != 'true' or string_array != 'true': continue
        values = [int(v) for v in values.split(',')]; offset = int(offset)
        raw = (evidence / 'dex' / dex).read_bytes()
        if offset < 120 or raw[offset - 8:offset] != struct.pack('<HHI', 0x300, 2, 64):
            raise RuntimeError('Typed payload offset/header mismatch')
        if raw[offset:offset + 128] != struct.pack('<64H', *values): raise RuntimeError('Typed payload bytes mismatch')
        for signer in original_signers:
            params = infer_affine_xor(values, signer)
            if params is None: continue
            identity = (dex, offset)
            if identity in accepted:
                accepted[identity]['uses'].append({'caller': caller, 'decoder': decoder})
                continue
            accepted[identity] = {'id': f'{dex}:{offset}', 'dex': dex, 'offset': offset, 'size': 128,
                'dex_sha256': sha256(evidence / 'dex' / dex), 'old_hex': raw[offset:offset + 128].hex(),
                'original_signer': signer, 'family': 'char64-affine-xor', 'parameters': params,
                'uses': [{'caller': caller, 'decoder': decoder}], 'string_array_after_decoder': True,
                'interpretation': 'Exact signer plaintext plus decoder use; runtime trial required'}
    result = {'schema_version': 1, 'apk_sha256': sha256(apk), 'examined_decoder_uses': examined,
              'candidates': sorted(accepted.values(), key=lambda v: (v['dex'], v['offset'])),
              'families': ['char64-affine-xor'], 'native_or_encrypted_payload_analysis': 'not-implemented'}
    write_json(evidence / 'analysis.json', result)
    return result


def rewrite_signer_payloads(data: bytes, candidates: list[dict], replacement: str) -> bytes:
    check_dex(data); fingerprint(replacement)
    changed = bytearray(data); used = set()
    for item in candidates:
        offset = item['offset']; old = bytes.fromhex(item['old_hex'])
        if item['dex_sha256'] != hashlib.sha256(data).hexdigest() or item['size'] != 128 or len(old) != 128:
            raise ValueError('Signer candidate belongs to different DEX bytes')
        if offset < 120 or offset + 128 > len(data) or used.intersection(range(offset, offset + 128)):
            raise ValueError('Invalid/overlapping payload range')
        if data[offset - 8:offset] != struct.pack('<HHI', 0x300, 2, 64) or data[offset:offset + 128] != old:
            raise ValueError('Signer payload changed after discovery')
        if infer_affine_xor(list(struct.unpack('<64H', old)), item['original_signer']) != item['parameters']:
            raise ValueError('Signer decoding parameters no longer match')
        changed[offset:offset + 128] = encode_affine_xor(replacement, item['parameters'])
        used.update(range(offset, offset + 128))
    if not candidates: return data
    changed[12:32] = hashlib.sha1(changed[32:]).digest()
    struct.pack_into('<I', changed, 8, zlib.adler32(changed[12:]) & 0xffffffff)
    result = bytes(changed); check_dex(result)
    if any(a != b and i not in used and not 8 <= i < 32 for i, (a, b) in enumerate(zip(data, result))):
        raise RuntimeError('Bytes outside discovered payload/checksum changed')
    return result
