"""Offline ARM64 TLS edits: ELF addresses/relocations, bounded locators and call wrappers.

Only the input library is rewritten. New code and relocated program headers live
in a new RX PT_LOAD; original verifier bodies execute through a gateway. No
device/global hooks, process addresses, guessed return conventions or RWX pages.
"""
import hashlib
import struct


class ElfTlsUnsupported(ValueError):
    pass


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def sign(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def align(value, boundary):
    return (value + boundary - 1) & -boundary


class Elf:
    def __init__(self, data):
        self.data = data
        if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<HH', data, 16) != (3, 183):
            raise ElfTlsUnsupported('Offline TLS requires a little-endian ARM64 shared ELF')
        self.phoff, self.shoff = struct.unpack_from('<QQ', data, 32)
        phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', data, 54)
        if phsize != 56 or not 0 < phnum < 1024 or self.phoff + phnum * 56 > len(data):
            raise ElfTlsUnsupported('Invalid ELF program headers')
        self.phdrs = [list(struct.unpack_from('<IIQQQQQQ', data, self.phoff + i * 56)) for i in range(phnum)]
        self.loads = [p for p in self.phdrs if p[0] == 1]
        if not self.loads or any(p[2] + p[5] > len(data) or p[5] > p[6] or p[1] & 3 == 3 for p in self.loads):
            raise ElfTlsUnsupported('Truncated, overlapping or writable-executable ELF loads')
        for a, b in zip(sorted(self.loads, key=lambda p: p[3]), sorted(self.loads, key=lambda p: p[3])[1:]):
            if a[3] + a[6] > b[3]: raise ElfTlsUnsupported('Overlapping virtual load segments')
        self.sections = []
        if self.shoff and shnum:
            if shsize != 64 or self.shoff + shnum * 64 > len(data): raise ElfTlsUnsupported('Truncated section headers')
            self.sections = [struct.unpack_from('<IIQQQQIIQQ', data, self.shoff + i * 64) for i in range(shnum)]
        self.dynamic = {}
        for p in self.phdrs:
            if p[0] != 2: continue
            if p[2] + p[5] > len(data) or p[5] % 16: raise ElfTlsUnsupported('Malformed dynamic segment')
            for off in range(p[2], p[2] + p[5], 16):
                tag, value = struct.unpack_from('<QQ', data, off)
                if not tag: break
                if tag in (1, 0x7ffffffd, 0x7fffffff): continue
                if tag in self.dynamic and self.dynamic[tag] != value: raise ElfTlsUnsupported('Ambiguous dynamic tag')
                self.dynamic[tag] = value

    def offset(self, address, size=1, executable=False):
        matches = [p[2] + address - p[3] for p in self.loads
                   if p[3] <= address and address + size <= p[3] + p[5] and (not executable or p[1] & 1)]
        if len(matches) != 1: raise ElfTlsUnsupported('Address is not uniquely file-backed in the required segment')
        return matches[0]

    def executable(self, address):
        return any(p[1] & 1 and p[3] <= address < p[3] + p[5] for p in self.loads)

    def word(self, address):
        return struct.unpack_from('<Q', self.data, self.offset(address, 8))[0]

    def symbols(self):
        tables = []
        for sec in self.sections:
            if sec[1] not in (2, 11): continue
            if sec[6] >= len(self.sections) or sec[9] != 24 or sec[5] % 24:
                raise ElfTlsUnsupported('Unsupported ELF symbol table')
            strings = self.sections[sec[6]]
            tables.append((sec[4], sec[5] // 24, strings[4], strings[5], sec[1] == 11))
        if not any(t[4] for t in tables) and 6 in self.dynamic:
            dyn = self.dynamic
            if dyn.get(11, 24) != 24 or 5 not in dyn or 10 not in dyn: raise ElfTlsUnsupported('Incomplete dynamic symbols')
            if 4 in dyn:
                count = u32(self.data, self.offset(dyn[4], 8) + 4)
            elif 0x6ffffef5 in dyn:
                off = self.offset(dyn[0x6ffffef5], 16)
                buckets, first, bloom, _ = struct.unpack_from('<IIII', self.data, off)
                if not 0 < buckets < 1000000 or bloom > 1000000: raise ElfTlsUnsupported('Invalid GNU symbol hash')
                bucket_off = off + 16 + bloom * 8
                if bucket_off + buckets * 4 > len(self.data): raise ElfTlsUnsupported('Truncated GNU symbol buckets')
                largest = max(struct.unpack_from('<' + 'I' * buckets, self.data, bucket_off))
                count = max(first, largest)
                if largest:
                    chain = bucket_off + buckets * 4 + (largest - first) * 4
                    for i in range(1000000):
                        if chain + i * 4 + 4 > len(self.data): raise ElfTlsUnsupported('Truncated GNU symbol chain')
                        count = largest + i + 1
                        if u32(self.data, chain + i * 4) & 1: break
                    else: raise ElfTlsUnsupported('Unbounded GNU symbol chain')
            else: raise ElfTlsUnsupported('Dynamic symbol count unavailable')
            tables.append((self.offset(dyn[6], count * 24), count, self.offset(dyn[5], dyn[10]), dyn[10], True))
        result = {}; self.dynsymbols = {}
        for offset, count, str_off, str_size, dynamic in tables:
            if offset + count * 24 > len(self.data) or str_off + str_size > len(self.data): raise ElfTlsUnsupported('Truncated symbols')
            strings = self.data[str_off:str_off + str_size]
            for i in range(count):
                name, info, other, section, value, size = struct.unpack_from('<IBBHQQ', self.data, offset + i * 24)
                if name >= len(strings): raise ElfTlsUnsupported('Symbol name outside string table')
                end = strings.find(b'\0', name)
                if end < 0: raise ElfTlsUnsupported('Unterminated symbol')
                text = strings[name:end].decode('utf-8', errors='replace')
                item = {'name': text, 'value': value, 'size': size, 'type': info & 15, 'defined': bool(section), 'dynamic': dynamic}
                if dynamic: self.dynsymbols[i] = item
                if text and section and info & 15 == 2 and self.executable(value):
                    rows = result.setdefault(text, [])
                    if not any(r['value'] == value for r in rows): rows.append(item)
        return result

    def relative_pointers(self):
        """Materialize relative/absolute pointers without constructing a fake loaded ELF."""
        if not hasattr(self, 'dynsymbols'): self.symbols()
        values = {}
        def emit(address, info, addend):
            self.offset(address, 8)
            kind, symbol = info & 0xffffffff, info >> 32
            if kind == 1027: value = addend
            elif kind == 257 and symbol in self.dynsymbols and self.dynsymbols[symbol]['defined']:
                value = self.dynsymbols[symbol]['value'] + addend
            else: return
            if address in values and values[address] != value: raise ElfTlsUnsupported('Conflicting relocation targets')
            values[address] = value
        dyn = self.dynamic
        if 7 in dyn:
            size = dyn.get(8, 0)
            if dyn.get(9, 24) != 24 or size % 24: raise ElfTlsUnsupported('Malformed RELA table')
            start = self.offset(dyn[7], size)
            for off in range(start, start + size, 24): emit(*struct.unpack_from('<QQq', self.data, off))
        # Android APS2 packs RELA offsets/info/addends as signed LEB128 deltas.
        if 0x60000011 in dyn:
            start = self.offset(dyn[0x60000011], dyn.get(0x60000012, 0)); end = start + dyn.get(0x60000012, 0)
            if self.data[start:start + 4] != b'APS2': raise ElfTlsUnsupported('Unknown Android relocation packing')
            cursor = start + 4
            def sleb():
                nonlocal cursor
                value = shift = 0
                for _ in range(10):
                    if cursor >= end: raise ElfTlsUnsupported('Truncated APS2 stream')
                    byte = self.data[cursor]; cursor += 1; value |= (byte & 127) << shift; shift += 7
                    if not byte & 128: return value - (1 << shift) if byte & 64 else value
                raise ElfTlsUnsupported('Oversized APS2 value')
            count, address = sleb(), sleb(); done = 0; addend = 0
            if not 0 <= count <= len(self.data) // 8: raise ElfTlsUnsupported('Invalid APS2 relocation count')
            while done < count:
                group, flags = sleb(), sleb()
                if group <= 0 or done + group > count or flags & ~15 or flags & 4 and not flags & 8:
                    raise ElfTlsUnsupported('Invalid APS2 group')
                delta = sleb() if flags & 2 else None; info = sleb() if flags & 1 else None
                group_addend = sleb() if flags & 8 and flags & 4 else None
                for _ in range(group):
                    address += delta if delta is not None else sleb()
                    entry_info = info if info is not None else sleb()
                    if flags & 8: addend += group_addend if group_addend is not None else sleb()
                    else: addend = 0
                    emit(address, entry_info, addend)
                done += group
        # DT_RELR, including Android's earlier OS-specific tag.
        for tag, size_tag in ((36, 35), (0x6fffe000, 0x6fffe001)):
            if tag not in dyn: continue
            size = dyn.get(size_tag, 0)
            if size % 8: raise ElfTlsUnsupported('Malformed RELR table')
            off = self.offset(dyn[tag], size); cursor = 0
            for pos in range(off, off + size, 8):
                entry = struct.unpack_from('<Q', self.data, pos)[0]
                if not entry & 1:
                    cursor = entry; emit(cursor, 1027, self.word(cursor)); cursor += 8
                else:
                    for bit in range(1, 64):
                        if entry & (1 << bit): emit(cursor + (bit - 1) * 8, 1027, self.word(cursor + (bit - 1) * 8))
                    cursor += 63 * 8
        # Older linkers leave literal virtual addresses in RELRO without RELA.
        for p in self.loads:
            if not p[1] & 2 or p[1] & 1: continue
            for off in range(align(p[2], 8), p[2] + p[5] - 7, 8):
                address = p[3] + off - p[2]
                if address not in values:
                    value = struct.unpack_from('<Q', self.data, off)[0]
                    if self.executable(value): values[address] = value
        return values

    def strings(self, needle):
        result = []
        for p in self.loads:
            off, end = p[2], p[2] + p[5]
            while True:
                at = self.data.find(needle + b'\0', off, end)
                if at < 0: break
                result.append(p[3] + at - p[2]); off = at + 1
        return result


def purpose_refs(elf, targets):
    """Decode ADRP+ADD address formation; reject clobbered base registers."""
    targets = set(targets); result = {}
    for p in elf.loads:
        if not p[1] & 1: continue
        for off in range(align(p[2], 4), p[2] + p[5] - 3, 4):
            insn = u32(elf.data, off)
            if insn & 0x9f000000 != 0x90000000: continue
            pc = p[3] + off - p[2]; rd = insn & 31
            page = (pc & ~4095) + (sign(((insn >> 5 & 0x7ffff) << 2) | (insn >> 29 & 3), 21) << 12)
            if not any(t & ~4095 == page for t in targets): continue
            for at in range(off + 4, min(off + 68, p[2] + p[5] - 3), 4):
                add = u32(elf.data, at)
                if add & 0xffc00000 == 0x91000000 and add >> 5 & 31 == rd:
                    target = page + (add >> 10 & 4095)
                    if target in targets: result[p[3] + at - p[2]] = target
                    break
                # Calls/branches end the basic block. Most data-producing ARM64
                # opcodes encode their destination in bits0..4; being stricter
                # here loses coverage rather than following an invalid xref.
                if add & 0x7c000000 == 0x14000000 or add & 0xff000010 == 0x54000000 or add & 31 == rd: break
    return result


def boring_verifier(elf):
    clients, servers = elf.strings(b'ssl_client'), elf.strings(b'ssl_server')
    if not clients or not servers: return None
    refs = purpose_refs(elf, clients + servers); pointers = elf.relative_pointers()
    functions = {}
    for slot, target in pointers.items():
        if not elf.executable(target) or target % 4: continue
        neighbors = sum(elf.executable(pointers.get(slot + delta * 8, 0)) for delta in range(-4, 5) if delta)
        if neighbors >= 4: functions.setdefault(target, []).append(slot)
    candidates = []
    for function, slots in functions.items():
        nearby = [(pc, target) for pc, target in refs.items() if function <= pc < function + 4096]
        # A later table function owns its own references.
        limit = min([f for f in functions if f > function] + [function + 4096])
        nearby = [(pc, target) for pc, target in nearby if pc < limit]
        if not any(t in clients for _, t in nearby) or not any(t in servers for _, t in nearby): continue
        off = elf.offset(function, 96, executable=True); prologue = [u32(elf.data, off + i * 4) for i in range(24)]
        alert = any(ins & 0xffffffe0 == 0x52800a00 and any(
            nxt == 0x39000040 | (ins & 31) for nxt in prologue[i + 1:i + 4]) for i, ins in enumerate(prologue))
        if alert: candidates.append({'address': function, 'table_slots': slots, 'purpose_refs': nearby,
                                      'kind': 'boringssl-chain-wrapper', 'contract': 'wrap-return-one'})
    if len(candidates) > 1: raise ElfTlsUnsupported('Ambiguous BoringSSL verifier candidates')
    return candidates[0] if candidates else None


EXPORTS = {'SSL_CTX_set_verify': 'verify-mode-none', 'SSL_set_verify': 'verify-mode-none',
           'SSL_CTX_set_custom_verify': 'custom-verify-ok', 'SSL_set_custom_verify': 'custom-verify-ok',
           'SSL_CTX_set_cert_verify_callback': 'cert-verify-one', 'SSL_get_verify_result': 'return-zero',
           'X509_verify_cert': 'wrap-return-one'}


def discover(data, name=''):
    elf = Elf(data); symbols = elf.symbols(); selected = []; rejected = []
    chromium = any(part in name.lower() for part in ('webviewchromium', 'monochrome', 'trichrome', 'libchrome', 'libcronet'))
    if chromium:
        return elf, [], [{'kind':'chromium-native-table','reason':'Use the owned Java verifier; native custom verification has a different path'}]
    for symbol, contract in EXPORTS.items():
        found = symbols.get(symbol, [])
        if len(found) > 1: raise ElfTlsUnsupported('Ambiguous native symbol: ' + symbol)
        if found:
            row = found[0]
            if row['size'] and row['size'] < 4: raise ElfTlsUnsupported('Native symbol too short: ' + symbol)
            selected.append({'symbol': symbol, 'address': row['value'], 'size': row['size'], 'kind': 'tls-export', 'contract': contract})
    openssl = bool(symbols.get('OpenSSL_version') or symbols.get('SSLeay_version')) and bool(symbols.get('TLS_client_method') or symbols.get('SSLv23_client_method'))
    if not openssl:
        found = boring_verifier(elf)
        if found: selected.append(found)
    by_address = {}
    for row in selected:
        if row['address'] in by_address and by_address[row['address']]['contract'] != row['contract']:
            raise ElfTlsUnsupported('Conflicting contracts at an aliased function')
        by_address.setdefault(row['address'], row)
    return elf, list(by_address.values()), rejected


def branch(source, target, link=False):
    delta = target - source
    if delta % 4 or not -(1 << 27) <= delta < 1 << 27: raise ElfTlsUnsupported('ARM64 branch target out of range')
    return (0x94000000 if link else 0x14000000) | ((delta // 4) & 0x3ffffff)


def relocated(insn, old, new):
    if insn & 0x7c000000 == 0x14000000:
        return branch(new, old + (sign(insn & 0x3ffffff, 26) << 2), bool(insn & 0x80000000))
    if insn & 0x9f000000 == 0x90000000:
        absolute = (old & ~4095) + (sign(((insn >> 5 & 0x7ffff) << 2) | (insn >> 29 & 3), 21) << 12)
        return adr_pair(insn & 31, new, absolute)[0]
    if (insn & 0x1f000000 == 0x10000000 or insn & 0x3b000000 == 0x18000000
            or insn & 0xff000010 == 0x54000000 or insn & 0x7e000000 in (0x34000000, 0x36000000)):
        raise ElfTlsUnsupported('PC-relative first instruction needs a different gateway')
    if insn == 0xd65f03c0 or insn & 0xfffffc1f in (0xd61f0000, 0xd63f0000):
        raise ElfTlsUnsupported('Entry is an indirect branch/return, not a verifier prologue')
    return insn


def adr_pair(register, pc, address):
    delta = ((address & ~4095) - (pc & ~4095)) // 4096
    if not -(1 << 20) <= delta < 1 << 20: raise ElfTlsUnsupported('Callback address out of ADRP range')
    imm = delta & 0x1fffff
    return [0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | register,
            0x91000000 | ((address & 4095) << 10) | (register << 5) | register]


def gateway_words(insn, old, new):
    # Widen conditional entry branches into an inverted short branch followed
    # by an unconditional branch to the original destination. This preserves
    # null-argument checks in newer OpenSSL builds without requiring a near cave.
    if insn & 0xff000010 == 0x54000000:
        target = old + (sign(insn >> 5 & 0x7ffff, 19) << 2)
        inverse = (insn & ~(0x7ffff << 5)) ^ 1
        return [inverse | (2 << 5), branch(new + 4, target)]
    if insn & 0x7e000000 in (0x34000000, 0x36000000):
        bits = 14 if insn & 0x7e000000 == 0x36000000 else 19
        mask = (1 << bits) - 1
        target = old + (sign(insn >> 5 & mask, bits) << 2)
        inverse = (insn & ~(mask << 5)) ^ (1 << 24)
        return [inverse | (2 << 5), branch(new + 4, target)]
    if insn & 0x9f000000 == 0x10000000:
        target = old + sign(((insn >> 5 & 0x7ffff) << 2) | (insn >> 29 & 3), 21)
        return adr_pair(insn & 31, new, target)
    return [relocated(insn, old, new)]


def patch_library(data, name=''):
    elf, selected, rejected = discover(data, name)
    if not selected: raise ElfTlsUnsupported('No bounded TLS verifier/export match')
    # Relocate the header table into a new RX segment and expose it through
    # PT_PHDR. Existing PT_LOAD addresses, file offsets, relocations, section
    # headers, ABI, dependencies and original verifier bodies remain intact.
    old = [p for p in elf.phdrs if p[0] != 6]
    phnum = len(old) + 2
    if phnum >= 65535: raise ElfTlsUnsupported('Program header count exhausted')
    offset = align(len(data), 16384); address = align(max(p[3] + p[6] for p in elf.loads), 16384)
    code_offset = align(phnum * 56, 16); program = bytearray(b'\0' * code_offset)
    def emit(words):
        at = address + len(program)
        program.extend(struct.pack('<' + 'I' * len(words), *words)); return at
    stub_zero = emit([0xd503245f, 0x52800000, 0xd65f03c0])
    stub_one = emit([0xd503245f, 0x52800020, 0xd65f03c0])
    edited = bytearray(data); edits = []
    for row in selected:
        entry = row['address']; at = elf.offset(entry, 4, executable=True)
        if u32(data, at) in (0xd503245f, 0xd503249f, 0xd50324df): entry += 4; at += 4
        original = u32(data, at); contract = row['contract']; start = address + len(program)
        if contract == 'return-zero': destination = stub_zero
        elif contract == 'wrap-return-one':
            # Preserve caller LR across the real verifier, including its own PAC
            # prologue/epilogue. The gateway executes the displaced instruction.
            gateway = start + 20
            emit([0xa9bf7bfd, branch(start + 4, gateway, True), 0x52800020, 0xa8c17bfd, 0xd65f03c0])
            words = gateway_words(original, entry, gateway)
            emit([*words, branch(gateway + len(words) * 4, entry + 4)])
            destination = start
        else:
            words = []
            if contract in ('verify-mode-none', 'custom-verify-ok'): words.append(0x52800001)
            if contract == 'custom-verify-ok': words += adr_pair(2, start + len(words) * 4, stub_zero)
            elif contract == 'cert-verify-one': words += adr_pair(1, start, stub_one)
            words += gateway_words(original, entry, start + len(words) * 4)
            words.append(branch(start + len(words) * 4, entry + 4)); emit(words); destination = start
        replacement = struct.pack('<I', branch(entry, destination)); edited[at:at + 4] = replacement
        edits.append({**row, 'file_offset': at, 'original_hex': data[at:at + 4].hex(), 'replacement_hex': replacement.hex(),
                      'wrapper_address': destination})
    size = len(program)
    headers = [[6, 4, offset, address, address, phnum * 56, phnum * 56, 8], *old,
               [1, 5, offset, address, address, size, size, 16384]]
    for i, p in enumerate(headers): struct.pack_into('<IIQQQQQQ', program, i * 56, *p)
    edited.extend(b'\0' * (offset - len(edited))); edited.extend(program)
    struct.pack_into('<Q', edited, 32, offset); struct.pack_into('<H', edited, 56, phnum)
    output = bytes(edited); check = Elf(output)
    if check.loads[-1][1] != 5 or any(check.offset(row['address'], 4, True) != elf.offset(row['address'], 4, True) for row in selected):
        raise RuntimeError('Native rewrite changed existing virtual/file bindings')
    return output, {'mode': 'offline-arm64', 'input_sha256': hashlib.sha256(data).hexdigest(),
        'output_sha256': hashlib.sha256(output).hexdigest(), 'patches': edits, 'rejected': rejected,
        'injected_segment': {'file_offset': offset, 'virtual_address': address, 'size': size, 'flags': 'RX'},
        'runtime_verification': 'not-run', 'limitations': [
            'App-owned ARM64 only; system/external libraries are unchanged',
            'Custom verify callbacks are replaced; mode-none retains ordinary callbacks',
            'Wrappers preserve original chain-verifier calls but override their result',
            'Independent post-handshake digest comparisons are not disabled',
            'Injected wrappers have no asynchronous unwind metadata']}
