import copy
from pathlib import Path
import struct
import tempfile
import unittest
from repack.dart_pinning import select, rewrite, read_metadata, identity, DartPinningUnsupported
from repack.elf_tls import ElfTlsUnsupported
from test_elf_tls import minimal_elf

ABI={'bool_true_from_null':32,'null_register':22,'string_equality_gdt_zero':1}


def predicate():
    return {'entry':256,'unchecked':272,'monomorphic':256,'payload':256,'size':100,
            'async_function':False,'return_type':'bool','parameters':'X509Certificate;bool;',
            'name':'[package:sample/pins.dart] ::verifyPeerCertificatePin'}


def code():
    return {'text':'r1 = "'+'0'*40+'"\n mov lr, x1\n ldr lr, [x21, lr, lsl #3]\n blr lr'}


class DartPredicateControls(unittest.TestCase):
    def test_typed_certificate_pin_and_snapshot_proven_equality_are_required(self):
        row=predicate();result=select([row],{256:code()},ABI)
        self.assertEqual(result['accepted'],[row])
        for change in ('async','future','certificate','literal','equality','shared'):
            row=predicate();assembly={256:code()};abi=dict(ABI);functions=[row]
            if change=='async':row['async_function']=True
            elif change=='future':row['return_type']='Future<bool>'
            elif change=='certificate':row['parameters']='String;bool;'
            elif change=='literal':assembly[256]['text']='StringBase::=='
            elif change=='equality':abi['string_equality_gdt_zero']=0
            else:functions.append({**row,'name':'[package:sample/other.dart] ::unrelated'})
            self.assertFalse(select(functions,assembly,abi)['accepted'],change)

    def test_pin_substrings_do_not_match_shipping_or_skipping(self):
        for name in ('ShippingCertificate','SkippingCertificate','CertificateSupplier'):
            row=predicate();row['name']='[package:sample/main.dart] ::'+name
            self.assertFalse(select([row],{256:code()},ABI)['accepted'])

    def test_dart_object_return_uses_snapshot_null_register_and_every_entry(self):
        original=bytes(minimal_elf());patched,rows=rewrite(original,ABI,[predicate()])
        for offset in (256,272):
            self.assertEqual(struct.unpack_from('<II',patched,offset),(0x910082c0,0xd65f03c0))
        self.assertEqual(patched[:256],original[:256]);self.assertEqual(patched[280:],original[280:])
        self.assertEqual(rows[0]['replacement'],'dart-synchronous-bool-true')

    def test_unbounded_or_async_entry_cannot_be_patched_as_c_boolean(self):
        for key,value in [('unchecked',900),('entry',257),('return_type','Future<bool>'),('async_function',True)]:
            row=predicate();row[key]=value
            with self.assertRaises((DartPinningUnsupported,ElfTlsUnsupported)):rewrite(bytes(minimal_elf()),ABI,[row])

    def test_adjacent_entries_keep_a_complete_return_path(self):
        row=predicate();row['unchecked']=260
        patched,_=rewrite(bytes(minimal_elf()),ABI,[row])
        self.assertEqual(struct.unpack_from('<III',patched,256),(0x910082c0,0x910082c0,0xd65f03c0))

    def test_missing_abi_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'functions.tsv';path.write_text('bool_true_from_null\t32\n')
            with self.assertRaises(DartPinningUnsupported):read_metadata(path)

    def test_elf_marker_alone_is_not_a_dart_snapshot(self):
        with self.assertRaises(DartPinningUnsupported):identity(bytes(minimal_elf())+b'Dart peerCertificate pinning')


if __name__=='__main__':unittest.main()
