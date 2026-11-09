import struct
import unittest
from repack.elf_tls import Elf, ElfTlsUnsupported, branch, gateway_words, relocated, sign, adr_pair


def minimal_elf():
    data = bytearray(1024); data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH',data,16,3,183); struct.pack_into('<Q',data,32,64)
    struct.pack_into('<HHHHHH',data,52,64,56,1,0,0,0)
    struct.pack_into('<IIQQQQQQ',data,64,1,5,0,0,0,len(data),len(data),4096)
    return data


class OfflineElfControls(unittest.TestCase):
    def test_file_mapping_requires_unique_backing_and_execute_permissions(self):
        elf=Elf(bytes(minimal_elf())); self.assertEqual(elf.offset(300,4,True),300)
        with self.assertRaises(ElfTlsUnsupported): elf.offset(1022,4)
        data=minimal_elf(); struct.pack_into('<I',data,68,4)
        with self.assertRaises(ElfTlsUnsupported): Elf(bytes(data)).offset(300,4,True)

    def test_wrong_abi_truncation_and_rwx_fail(self):
        for change in ('arch','truncated','rwx'):
            data=minimal_elf()
            if change=='arch': struct.pack_into('<H',data,18,62)
            elif change=='truncated': data=data[:90]
            else: struct.pack_into('<I',data,68,7)
            with self.assertRaises(ElfTlsUnsupported): Elf(bytes(data))

    def test_branch_ranges_and_signed_pc_semantics(self):
        for source,target in [(0x1000,0x4000),(0x800000,0x2000)]:
            instruction=branch(source,target)
            self.assertEqual(source+(sign(instruction&0x3ffffff,26)<<2),target)
        for target in (0x100000000,3):
            with self.assertRaises(ElfTlsUnsupported): branch(0,target)

    def test_conditional_gateway_keeps_both_original_paths(self):
        # CBZ x0 to original+0x28, widened to CBNZ +8 / B original-target.
        original=0xb4000140; words=gateway_words(original,0x1000,0x900000)
        self.assertEqual(words[0]&0xff00001f,0xb5000000)
        self.assertEqual(sign(words[0]>>5&0x7ffff,19)*4,8)
        self.assertEqual(0x900004+(sign(words[1]&0x3ffffff,26)<<2),0x1028)

    def test_adrp_gateway_preserves_absolute_page(self):
        old=0x10234; target=0x35110; instruction=adr_pair(8,old,target)[0]
        new=0x900000; moved=relocated(instruction,old,new)
        immediate=sign(((moved>>5&0x7ffff)<<2)|(moved>>29&3),21)
        self.assertEqual((new&~4095)+(immediate<<12),target&~4095)
        self.assertEqual(moved&31,8)

    def test_indirect_entry_is_not_silently_treated_as_prologue(self):
        for instruction in (0xd65f03c0,0xd61f0200,0xd63f0200):
            with self.assertRaises(ElfTlsUnsupported): relocated(instruction,0x1000,0x2000)


if __name__ == '__main__': unittest.main()
