#!/usr/bin/env python3
"""Fail-closed validation for the Watch-enabled combined build."""
import argparse
import hashlib
import json
import pathlib
import sys
import struct


def validate_chained_fixups(data, offset, length, segments, dependency_count):
    """Validate uncompressed imports and generic 64/64_OFFSET page chains.

    ARM64e/authenticated, kernel/cache pointers and multi-start pages are outside
    this deliberately narrow conversion contract and are rejected, not guessed.
    All offsets returned below still address the original immutable byte layout.
    """
    linkedit = segments[-1]
    if (length < 28 or offset < linkedit['fileoff']
            or offset + length > linkedit['fileoff'] + linkedit['filesize']):
        raise ValueError('invalid chained-fixups bounds')
    version, starts, imports, symbols, import_count, import_format, symbol_format = struct.unpack_from('<7I', data, offset)
    widths = {1: 4, 2: 8, 3: 16}
    if (version != 0 or import_format not in widths or symbol_format != 0
            or starts < 28 or starts % 4 or starts + 4 > imports
            or imports > symbols or symbols > length
            or imports + import_count * widths[import_format] > symbols):
        raise ValueError('unsupported or malformed chained-fixups header/imports')
    count = struct.unpack_from('<I', data, offset + starts)[0]
    table_size = 4 + 4 * count
    if count != len(segments) or starts + table_size > imports:
        raise ValueError('chained-fixups segment count mismatch')
    entries = struct.unpack_from(f'<{count}I', data, offset + starts + 4)
    if entries[0]:
        raise ValueError('PAGEZERO cannot have chained starts')
    for index in range(import_count):
        value = struct.unpack_from('<Q' if import_format == 3 else '<I', data,
                                   offset + imports + index * widths[import_format])[0]
        bits = 16 if import_format == 3 else 8
        ordinal = value & ((1 << bits) - 1)
        if ordinal & (1 << (bits - 1)):
            ordinal -= 1 << bits
        name_offset = value >> (32 if import_format == 3 else 9)
        if (ordinal < -3 or ordinal > dependency_count
                or import_format == 3 and (value >> 17) & 0x7fff
                or symbols + name_offset >= length):
            raise ValueError('invalid chained import ordinal/reserved bits/symbol offset')
        name = offset + symbols + name_offset
        end = data.find(b'\0', name, offset + length)
        if end <= name:
            raise ValueError('invalid chained import symbol string')
    record_ranges = []
    for index, entry in enumerate(entries):
        if not entry:
            continue
        record = starts + entry
        if entry < table_size or entry % 4 or record + 22 > imports:
            raise ValueError('invalid chained starts record bounds')
        size, page_size, pointer_format, segment_offset, max_valid, page_count = struct.unpack_from('<IHHQIH', data, offset + record)
        segment = segments[index]
        if (size != 22 + 2 * page_count or record + size > imports
                or page_size not in (4096, 16384) or pointer_format not in (2, 6)
                or segment_offset != segment['vm'] - segments[1]['vm'] or max_valid != 0
                or not page_count or page_count != (segment['filesize'] + page_size - 1) // page_size
                or segment['name'] == b'__LINKEDIT' or segment['prot'] & 4):
            raise ValueError('unsupported or malformed chained starts/page table')
        if any(record < end and begin < record + size for begin, end in record_ranges):
            raise ValueError('overlapping chained starts records')
        record_ranges.append((record, record + size))
        for page in range(page_count):
            start = struct.unpack_from('<H', data, offset + record + 22 + 2 * page)[0]
            if start == 0xffff:
                continue
            if start & 0x8000:
                raise ValueError('multi-start chained pages are not supported')
            page_begin = segment['fileoff'] + page * page_size
            page_end = min(page_begin + page_size, segment['fileoff'] + segment['filesize'])
            cursor = page_begin + start
            while True:
                if cursor % 4 or cursor + 8 > page_end:
                    raise ValueError('chained pointer outside file-backed page')
                pointer = struct.unpack_from('<Q', data, cursor)[0]
                if pointer >> 63:
                    if (pointer & 0xffffff) >= import_count or (pointer >> 32) & 0x7ffff:
                        raise ValueError('invalid chained bind import/reserved bits')
                else:
                    if (pointer >> 44) & 0x7f:
                        raise ValueError('invalid chained rebase reserved bits')
                    target = pointer & 0xfffffffff
                    if pointer_format == 6:
                        target += segments[1]['vm']
                    if not any(s['vm'] <= target < s['vm'] + s['vmsize'] for s in segments[1:]):
                        raise ValueError('chained rebase target outside mapped image')
                next_delta = (pointer >> 51) & 0xfff
                if not next_delta:
                    break
                if next_delta < 2:
                    raise ValueError('overlapping chained pointers')
                cursor += next_delta * 4
    return starts, count, entries


def convert_executable(source, destination):
    data = bytearray(pathlib.Path(source).read_bytes())
    if len(data) < 32:
        raise ValueError('truncated Mach-O header')
    header = struct.unpack_from('<8I', data)
    if header[0] != 0xfeedfacf or header[1] != 0x100000c or header[3] != 2:
        raise ValueError('expected a thin arm64 MH_EXECUTE')
    if header[6] & 0x84 != 0x84 or header[6] & (0x2 | 0x10 | 0x20 | 0x100):
        raise ValueError('unsupported executable linking flags')
    if header[2] != 0 or header[7] != 0:
        raise ValueError('unsupported ARM64 subtype or reserved header')
    if 32 + header[5] > len(data):
        raise ValueError('truncated Mach-O load commands')
    position, pagezero = 32, None
    segments, fixup_commands, mains = [], [], []
    segment_details = []
    instruction_ranges = []
    dependency_count = 0
    dependencies = {0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023}
    strings = dependencies | {0xe, 0x8000001c}
    fixed_sizes = {2: 24, 0xb: 80, 0x1b: 24, 0x24: 16, 0x25: 16,
                   0x26: 16, 0x29: 16, 0x1d: 16, 0x2a: 16, 0x2c: 24,
                   0x80000028: 24, 0x80000033: 16, 0x80000034: 16}
    seen, linkedit_ranges, symbol_count, dynamic_symbols = set(), [], None, None
    for _ in range(header[4]):
        if position + 8 > 32 + header[5] or position + 8 > len(data):
            raise ValueError('truncated Mach-O load commands')
        command, size = struct.unpack_from('<II', data, position)
        if size < 8 or size % 8 or position + size > 32 + header[5] or position + size > len(data):
            raise ValueError('invalid Mach-O load command size')
        if command in (0x22, 0x80000022):
            raise ValueError('legacy dyld opcodes are not supported')
        if command not in strings | fixed_sizes.keys() | {0x19, 0x32}:
            raise ValueError(f'unsupported Mach-O command {command:#x}')
        if command not in dependencies | {0x19, 0x8000001c} and command in seen:
            raise ValueError('duplicate singleton load command')
        seen.add(command)
        if command in fixed_sizes and size != fixed_sizes[command]:
            raise ValueError('inconsistent Mach-O command size')
        if command in strings:
            minimum = 24 if command in dependencies else 12
            if size < minimum:
                raise ValueError('truncated string load command')
            name_offset = struct.unpack_from('<I', data, position + 8)[0]
            if name_offset < minimum or name_offset >= size or data.find(b'\0', position + name_offset, position + size) <= position + name_offset:
                raise ValueError('invalid load-command string')
        if command == 0x32:
            if size < 24 or size != 24 + 8 * struct.unpack_from('<I', data, position + 20)[0]:
                raise ValueError('inconsistent build-version command size')
        if command == 0x2c:
            cryptoff, cryptsize, cryptid, pad = struct.unpack_from('<4I', data, position + 8)
            if cryptid or pad or cryptoff + cryptsize > len(data):
                raise ValueError('encrypted or malformed executable is not supported')
        if command in (0x26, 0x29, 0x1d, 0x80000033, 0x80000034):
            linkedit_ranges.append(struct.unpack_from('<II', data, position + 8))
        if command == 2:
            symoff, symbol_count, stroff, strsize = struct.unpack_from('<4I', data, position + 8)
            linkedit_ranges.extend(((symoff, 16 * symbol_count), (stroff, strsize)))
        if command == 0xb:
            dynamic_symbols = struct.unpack_from('<18I', data, position + 8)
            if any(dynamic_symbols[i] for i in (7, 9, 11, 15, 17)):
                raise ValueError('unsupported legacy dynamic symbol tables/relocations')
            linkedit_ranges.append((dynamic_symbols[12], 4 * dynamic_symbols[13]))
        if command == 0x19:
            if size < 72:
                raise ValueError('truncated Mach-O segment')
            _, _, name, vm, vmsize, fileoff, filesize, maxprot, prot, nsects, flags = struct.unpack_from('<II16sQQQQiiII', data, position)
            name = name.rstrip(b'\0')
            if size != 72 + 80 * nsects:
                raise ValueError('inconsistent segment section command size')
            if name == b'__PAGEZERO':
                if (pagezero is not None or position != 32 or segments or size != 72
                        or (vm, vmsize, fileoff, filesize, maxprot, prot, nsects, flags)
                        != (0, 0x100000000, 0, 0, 0, 0, 0, 0)):
                    raise ValueError('invalid __PAGEZERO segment')
                pagezero = position
            else:
                if (name not in (b'__TEXT', b'__DATA_CONST', b'__DATA', b'__LINKEDIT')
                        or flags not in (0, 0x10) or flags and name != b'__DATA_CONST'
                        or not vmsize or vm + vmsize > 1 << 64 or filesize > vmsize
                        or fileoff + filesize > len(data) or maxprot & ~7 or prot & ~maxprot):
                    raise ValueError('invalid segment bounds or protections')
                for old in segment_details:
                    if vm < old['vm'] + old['vmsize'] and old['vm'] < vm + vmsize:
                        raise ValueError('overlapping segment VM ranges')
                    if filesize and old['filesize'] and fileoff < old['fileoff'] + old['filesize'] and old['fileoff'] < fileoff + filesize:
                        raise ValueError('overlapping segment file ranges')
            details = dict(name=name, vm=vm, vmsize=vmsize, fileoff=fileoff, filesize=filesize, prot=prot)
            section_ranges = []
            for index in range(nsects):
                section = struct.unpack_from('<16s16sQQIIIIIIII', data, position + 72 + 80 * index)
                _, segname, addr, length, off, align, reloff, nreloc, attrs, r1, r2, r3 = section
                if (segname.rstrip(b'\0') != name or addr < vm or addr + length > vm + vmsize
                        or align > 31 or addr % (1 << align) or attrs & 0xff > 0x16
                        or reloff or nreloc or r3):
                    raise ValueError('invalid section bounds or unsupported relocations')
                if any(addr < end and begin < addr + length for begin, end in section_ranges):
                    raise ValueError('overlapping sections')
                section_ranges.append((addr, addr + length))
                if attrs & 0xff not in (1, 0xc, 0x12):  # zero-fill has no file backing
                    if (off < fileoff or off + length > fileoff + filesize
                            or addr - vm != off - fileoff or off < 32 + header[5]):
                        raise ValueError('invalid section file bounds')
                    if attrs & 0x80000400 and name == b'__TEXT' and prot & 4:
                        instruction_ranges.append((off, off + length))
                elif off != 0:
                    raise ValueError('file-backed zero-fill section')
            segments.append(position)
            segment_details.append(details)
        if command in dependencies:
            dependency_count += 1
        if command == 0x80000028:
            mains.append(struct.unpack_from('<Q', data, position + 8)[0])
        if command == 0x80000034:
            fixup_commands.append(position)
        position += size
    if position != 32 + header[5] or pagezero is None:
        raise ValueError('missing __PAGEZERO or inconsistent load commands')
    if (len(segment_details) < 3 or segment_details[1]['name'] != b'__TEXT'
            or segment_details[1]['vm'] != 0x100000000 or segment_details[1]['fileoff'] != 0
            or segment_details[1]['filesize'] < position or segment_details[1]['prot'] != 5
            or segment_details[-1]['name'] != b'__LINKEDIT'
            or len({s['name'] for s in segment_details}) != len(segment_details)):
        raise ValueError('unsupported segment layout')
    linkedit = segment_details[-1]
    occupied = []
    for off, length in linkedit_ranges:
        if not length:
            if off and not linkedit['fileoff'] <= off <= linkedit['fileoff'] + linkedit['filesize']:
                raise ValueError('invalid empty linkedit range')
            continue
        if off < linkedit['fileoff'] or off + length > linkedit['fileoff'] + linkedit['filesize']:
            raise ValueError('linkedit data outside segment bounds')
        if any(off < end and begin < off + length for begin, end in occupied):
            raise ValueError('overlapping linkedit data')
        occupied.append((off, off + length))
    if dynamic_symbols is not None:
        if symbol_count is None or any(dynamic_symbols[i] + dynamic_symbols[i + 1] > symbol_count for i in (0, 2, 4)):
            raise ValueError('invalid dynamic symbol indices')
    if len(mains) != 1 or mains[0] % 4 or not any(begin <= mains[0] and mains[0] + 4 <= end for begin, end in instruction_ranges):
        raise ValueError('expected exactly one valid LC_MAIN into executable TEXT instructions')
    # __PAGEZERO has no relocations. Removing it shifts dyld's segment indices.
    # Keep every starts_in_segment record at its original offset: the freed slot
    # is harmless padding, so no chained pointer, import or instruction is moved.
    if segments[0] != pagezero or len(fixup_commands) != 1:
        raise ValueError('unsupported PAGEZERO/fixup layout')
    for command_position in fixup_commands:
        offset, length = struct.unpack_from('<II', data, command_position + 8)
        starts, count, entries = validate_chained_fixups(
            data, offset, length, segment_details, dependency_count)
        struct.pack_into('<I', data, offset + starts, count - 1)
        struct.pack_into(f'<{count}I', data, offset + starts + 4, *entries[1:], 0)
    name = b'@executable_path/SideStore.dylib\0'
    data[pagezero:pagezero + 72] = (struct.pack('<6I', 0xd, 72, 24, 1, 0, 0) + name).ljust(72, b'\0')
    struct.pack_into('<I', data, 12, 6)
    struct.pack_into('<I', data, 24, (header[6] | 0x100000) & ~0x200000)
    with pathlib.Path(destination).open('xb') as output:
        output.write(data)
    return {'sha256': hashlib.sha256(data).hexdigest(), 'filetype': 'MH_DYLIB'}


def verify_hash(path, expected):
    digest = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    if digest != expected:
        raise ValueError(f'SHA-256 mismatch: expected {expected}, got {digest}')
    return {'sha256': digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('verify-hash')
    command.add_argument('path')
    command.add_argument('sha256')
    command = commands.add_parser('convert')
    command.add_argument('source')
    command.add_argument('destination')
    args = parser.parse_args()
    try:
        result = (verify_hash(args.path, args.sha256) if args.command == 'verify-hash'
                  else convert_executable(args.source, args.destination))
        print(json.dumps(result))
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
