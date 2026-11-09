"""Standalone startup repair: discovery, negative controls, and bounded search."""
import hashlib
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

from repack.rebuild import environment, execute, load_lock, tool
from repack.patches import java_dependencies
from repack.startup import classify_log, search, startup, window_focus
from repack.startup_analysis import (discover_signer_payloads, encode_affine_xor,
                                    infer_affine_xor, rewrite_signer_payloads)


ORIGINAL = hashlib.sha256(b'operator-owned original certificate').hexdigest()
REPLACEMENT = hashlib.sha256(b'persistent replacement certificate').hexdigest()


class EncodingControls(unittest.TestCase):
    def test_parameters_are_induced_and_every_character_checked(self):
        rng = random.Random(50)
        for _ in range(100):
            p = {'multiplier': rng.randrange(65536), 'mask': rng.randrange(65536)}
            values = list(struct.unpack('<64H', encode_affine_xor(ORIGINAL, p)))
            found = infer_affine_xor(values, ORIGINAL)
            self.assertEqual(found, {**p, 'verified_characters': 64})
            values[63] ^= 1
            self.assertIsNone(infer_affine_xor(values, ORIGINAL))

    def test_wrong_certificate_and_bad_fingerprint_do_not_match(self):
        values = list(struct.unpack('<64H', encode_affine_xor(ORIGINAL, {'multiplier': 17, 'mask': 503})))
        self.assertIsNone(infer_affine_xor(values, REPLACEMENT))
        with self.assertRaises(ValueError): infer_affine_xor(values, ORIGINAL.upper())
        self.assertIsNone(infer_affine_xor(values[:-1], ORIGINAL))


class SearchControls(unittest.TestCase):
    def setUp(self):
        self.axes = [{'id': 's', 'kind': 'signer-payload'}, {'id': 'v', 'kind': 'package-visibility'}]

    def test_failure_guided_combination_and_separate_confirmation(self):
        calls = []; checkpoints = []
        def trial(selected, number, confirm=None):
            calls.append((selected, bool(confirm)))
            phase = 'application-init' if 's' not in selected else 'java-background' if 'v' not in selected else None
            return {'artifact': '/immutable/' + str(number), 'observation': {
                'startup_liveness': 'failed' if phase else 'passed', 'failure_phase': phase}}
        result = search(self.axes, trial, 4, checkpoints.append)
        self.assertEqual(calls, [((), False), (('s',), False), (('s', 'v'), False), (('s', 'v'), True)])
        self.assertEqual(result['status'], 'passed'); self.assertEqual(result['winner'], 3)
        self.assertEqual(result['functional_verification'], 'not-run')

    def test_budget_and_exhaustion_never_mean_success(self):
        for budget, count in [(1, 1), (4, 4), (9, 4)]:
            calls = []
            def fail(selected, number, confirm=None):
                calls.append(selected)
                return {'artifact': str(number), 'observation': {'startup_liveness': 'failed', 'failure_phase': 'unknown'}}
            result = search(self.axes, fail, budget, lambda state: None)
            self.assertEqual(result['status'], 'exhausted'); self.assertEqual(len(calls), count)
            self.assertEqual(len(set(calls)), count)

    def test_confirmation_failure_or_different_artifact_is_not_a_pass(self):
        for different in (False, True):
            def trial(selected, number, confirm=None):
                return {'artifact': 'changed' if confirm and different else 'original', 'observation': {
                    'startup_liveness': 'failed' if confirm and not different else 'passed', 'failure_phase': None}}
            result = search([], trial, 1, lambda state: None)
            self.assertEqual(result['status'], 'exhausted')

    def test_infrastructure_error_stops_without_labeling_app_failure(self):
        def offline(*args, **kwargs): raise RuntimeError('device offline')
        with self.assertRaisesRegex(RuntimeError, 'device offline'):
            search(self.axes, offline, 4, lambda state: None)

    def test_no_device_mutation_without_explicit_data_clear_flag(self):
        with patch('repack.startup.validate_toolchain') as validate:
            with self.assertRaisesRegex(RuntimeError, 'wipe-data'):
                startup('unused', {'replace_existing_and_wipe_data': False}, {}, Path('/unused'), [])
            validate.assert_not_called()


class CrashAttributionControls(unittest.TestCase):
    def test_unavailable_focus_field_is_infrastructure_failure(self):
        self.assertEqual(window_focus('  mCurrentFocus=Window{1 u0 example.app/.Main}\n'),
                         ['mCurrentFocus=Window{1 u0 example.app/.Main}'])
        with self.assertRaisesRegex(RuntimeError, 'inconclusive'):
            window_focus('mObscuringWindow=Window{1 u0 example.app/.Main}')

    def test_unrelated_crashes_and_package_prefix_do_not_count(self):
        raw = 'FATAL EXCEPTION: main\nProcess: other.app, PID: 1\njava.lang.RuntimeException: boom\n'
        raw += 'FATAL EXCEPTION: main\nProcess: example.app.other, PID: 2\njava.lang.ArithmeticException: boom\n'
        self.assertIsNone(classify_log(raw, 'example.app')['failure_phase'])

    def test_main_service_native_and_anr(self):
        for suffix, message, expected in [('', 'Unable to create application', 'application-init'),
                (':push', 'Unable to create service', 'service-init'), ('', 'bad division', 'java-background')]:
            raw = f'FATAL EXCEPTION: worker\nProcess: example.app{suffix}, PID: 54\njava.lang.RuntimeException: {message}\n'
            got = classify_log(raw, 'example.app')
            self.assertEqual(got['failure_phase'], expected); self.assertEqual(got['java_crashes'][0]['pid'], 54)
        self.assertEqual(classify_log('>>> example.app:worker <<<', 'example.app')['failure_phase'], 'native-crash')
        self.assertEqual(classify_log('ANR in example.app (pid 5)', 'example.app')['failure_phase'], 'anr')
        self.assertIsNone(classify_log('ANR in example.app.other (pid 5)', 'example.app')['failure_phase'])


@unittest.skipUnless(os.environ.get('REPACK_TEST_SDK') == '1', 'Set REPACK_TEST_SDK=1 for pinned smali/SDK integration')
class RealDexControls(unittest.TestCase):
    def build(self, root, *, owner, multiplier, mask, padding):
        params = {'multiplier': multiplier, 'mask': mask}
        def body(plain):
            return '\n'.join('        ' + str(v) for v in struct.unpack('<64H', encode_affine_xor(plain, params)))
        text = f'''.class public L{owner};
.super Landroid/app/Application;
.method public onCreate()V
    .registers 6
    {'nop' + chr(10) if padding else ''}
    const/4 v0, 0x0
    const/4 v3, 0x1
    new-array v2, v3, [Ljava/lang/Object;
    const/16 v3, 64
    new-array v1, v3, [C
    fill-array-data v1, :payload
    const v3, {multiplier}
    invoke-static {{v3, v1, v2}}, L{owner};->renamed(I[C[Ljava/lang/Object;)V
    aget-object v4, v2, v0
    check-cast v4, Ljava/lang/String;
    filled-new-array {{v4}}, [Ljava/lang/String;
    move-result-object v4
    return-void
    :payload
    .array-data 2
{body(ORIGINAL)}
    .end array-data
.end method
.method public negativeControl()V
    .registers 6
    const/4 v0, 0x0
    const/4 v3, 0x1
    new-array v2, v3, [Ljava/lang/Object;
    const/16 v3, 64
    new-array v1, v3, [C
    fill-array-data v1, :unrelated
    const v3, {multiplier}
    invoke-static {{v3, v1, v2}}, L{owner};->renamed(I[C[Ljava/lang/Object;)V
    aget-object v4, v2, v0
    check-cast v4, Ljava/lang/String;
    filled-new-array {{v4}}, [Ljava/lang/String;
    move-result-object v4
    return-void
    :unrelated
    .array-data 2
{body(REPLACEMENT)}
    .end array-data
.end method
.method public static renamed(I[C[Ljava/lang/Object;)V
    .registers 9
    const/4 v0, 0x0
    :loop
    array-length v1, p1
    if-ge v0, v1, :done
    aget-char v2, p1, v0
    mul-int v3, v0, p0
    xor-int/2addr v2, v3
    const v4, {mask}
    xor-int/2addr v2, v4
    int-to-char v2, v2
    aput-char v2, p1, v0
    add-int/lit8 v0, v0, 1
    goto :loop
    :done
    new-instance v1, Ljava/lang/String;
    invoke-direct {{v1, p1}}, Ljava/lang/String;-><init>([C)V
    const/4 v0, 0
    aput-object v1, p2, v0
    return-void
.end method
'''
        src = root / 'src'; src.mkdir(); (src / 'fixture.smali').write_text(text)
        lock = load_lock(); cp = ':'.join(a['path'] for a in java_dependencies('smali'))
        dex = root / 'classes.dex'
        execute([tool(lock, 'java'), '-cp', cp, 'com.android.tools.smali.smali.Main', 'assemble', '--api', '30',
                 '-o', str(dex), str(src)], root, 'smali', env=environment(lock))
        apk = root / 'fixture.apk'
        with zipfile.ZipFile(apk, 'w') as z: z.write(dex, 'classes.dex')
        return apk, dex, lock

    def test_names_offsets_and_encoding_constants_are_discovered(self):
        offsets = []
        with tempfile.TemporaryDirectory() as tmp:
            for n, (owner, multiplier, mask) in enumerate([('alpha/First', 51, 4301), ('totally/different/Second', 31973, 55111)]):
                root = Path(tmp) / str(n); root.mkdir()
                apk, dex, lock = self.build(root, owner=owner, multiplier=multiplier, mask=mask, padding=n)
                result = discover_signer_payloads(apk, [ORIGINAL], 30, lock, root / 'analysis')
                self.assertEqual(len(result['candidates']), 1)
                candidate = result['candidates'][0]; offsets.append(candidate['offset'])
                self.assertEqual(candidate['parameters'], {'multiplier': multiplier, 'mask': mask, 'verified_characters': 64})
                before = dex.read_bytes(); after = rewrite_signer_payloads(before, [candidate], REPLACEMENT)
                at = candidate['offset']
                self.assertEqual(after[at:at + 128], encode_affine_xor(REPLACEMENT, candidate['parameters']))
                self.assertEqual(before[32:at], after[32:at]); self.assertEqual(before[at + 128:], after[at + 128:])
                # A candidate is bound to the exact input, not a reusable numeric offset.
                bad = bytearray(before); bad[-1] ^= 1
                bad[12:32] = hashlib.sha1(bad[32:]).digest(); struct.pack_into('<I', bad, 8, zlib.adler32(bad[12:]) & 0xffffffff)
                with self.assertRaisesRegex(ValueError, 'different DEX'):
                    rewrite_signer_payloads(bytes(bad), [candidate], REPLACEMENT)
            self.assertNotEqual(offsets[0], offsets[1])


if __name__ == '__main__': unittest.main()
