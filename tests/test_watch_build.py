import hashlib
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools' / 'watch_build.py'


def fixture():
    """Modern thin ARM64 executable with a real section, entry, bind and import."""
    segment = lambda name, vm, vs, off, size, prot, ns=0: struct.pack(
        '<II16sQQQQiiII', 0x19, 72 + ns * 80, name, vm, vs, off, size, prot, prot, ns, 0)
    section = struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT',
                          0x100001000, 16, 4096, 2, 0, 0, 0x80000400, 0, 0, 0)
    dependency = (struct.pack('<6I', 0xc, 48, 24, 0, 0, 0) + b'/usr/lib/a.dylib\0').ljust(48, b'\0')
    rpath = (struct.pack('<3I', 0x8000001c, 32, 12) + b'@executable_path\0').ljust(32, b'\0')
    commands = (segment(b'__PAGEZERO', 0, 0x100000000, 0, 0, 0)
                + segment(b'__TEXT', 0x100000000, 8192, 0, 8192, 5, 1) + section
                + segment(b'__DATA', 0x100002000, 4096, 8192, 4096, 3)
                + segment(b'__LINKEDIT', 0x100003000, 4096, 12288, 80, 1)
                + struct.pack('<IIQQ', 0x80000028, 24, 4096, 0)
                + dependency + rpath + struct.pack('<4I', 0x80000034, 16, 12288, 80))
    data = bytearray((struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, 8,
                                  len(commands), 0x200085, 0) + commands).ljust(12368, b'\0'))
    data[4096:4112] = bytes.fromhex('1f2003d5' * 4)  # ARM64 NOPs
    struct.pack_into('<Q', data, 8192, 1 << 63)  # bind import 0, next 0
    struct.pack_into('<7I', data, 12288, 0, 28, 72, 76, 1, 1, 0)
    struct.pack_into('<5I', data, 12316, 4, 0, 0, 20, 0)
    struct.pack_into('<IHHQIH', data, 12336, 24, 4096, 6, 8192, 0, 1)
    struct.pack_into('<H', data, 12358, 0)
    struct.pack_into('<I', data, 12360, 1)  # library ordinal 1, name offset 0
    data[12364:12368] = b'foo\0'
    return data


def commands(data):
    pos = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, pos)
        yield cmd, pos, size
        pos += size


def append_command(data, command):
    end = 32 + struct.unpack_from('<I', data, 20)[0]
    data[end:end+len(command)] = command
    struct.pack_into('<I', data, 16, struct.unpack_from('<I', data, 16)[0] + 1)
    struct.pack_into('<I', data, 20, end - 32 + len(command))
    return data


class WatchBuildTests(unittest.TestCase):
    def convert(self, data, destination_kind=None):
        with tempfile.TemporaryDirectory() as directory:
            src, dst = (pathlib.Path(directory) / n for n in ('input', 'output'))
            src.write_bytes(data)
            if destination_kind == 'file':
                dst.write_bytes(b'keep existing')
            elif destination_kind == 'dangling':
                dst.symlink_to('absent')
            elif destination_kind == 'input':
                dst.symlink_to(src)
            result = subprocess.run([sys.executable, str(SCRIPT), 'convert', str(src), str(dst)],
                                    capture_output=True, text=True)
            self.assertEqual(src.read_bytes(), data, 'input changed')
            if destination_kind:
                self.assertNotEqual(result.returncode, 0)
                if destination_kind == 'file':
                    self.assertEqual(dst.read_bytes(), b'keep existing')
                else:
                    self.assertTrue(dst.is_symlink())
                return result, None
            if result.returncode:
                self.assertFalse(os.path.lexists(dst), 'rejection created output')
                return result, None
            return result, dst.read_bytes()

    def reject(self, data):
        result, _ = self.convert(data)
        self.assertNotEqual(result.returncode, 0, 'malformed executable accepted')
        return result

    def test_converts_arm64_without_changing_stable_bytes(self):
        data = fixture()
        result, converted = self.convert(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        assert converted is not None
        expected = bytearray(data)
        expected[32:104] = (struct.pack('<6I', 0xd, 72, 24, 1, 0, 0)
                           + b'@executable_path/SideStore.dylib\0').ljust(72, b'\0')
        struct.pack_into('<I', expected, 12, 6)
        struct.pack_into('<I', expected, 24, (0x200085 | 0x100000) & ~0x200000)
        struct.pack_into('<5I', expected, 12316, 3, 0, 20, 0, 0)
        self.assertEqual(converted, expected)  # includes main, code, rpath, import, bind
        self.assertEqual(json.loads(result.stdout)['sha256'], hashlib.sha256(converted).hexdigest())

    def test_rejects_invalid_pagezero_before_output(self):
        for field, fmt, value in [(56, '<Q', 1), (64, '<Q', 1), (72, '<Q', 8),
                                  (80, '<i', 1), (84, '<i', 1), (88, '<I', 1),
                                  (92, '<I', 1), (96, '<I', 1)]:
            with self.subTest(field=field):
                data = fixture()
                struct.pack_into(fmt, data, field, value)
                self.reject(data)

    def test_rejects_missing_duplicate_or_invalid_main(self):
        for mutation in ('missing', 'duplicate', 'header', 'data', 'outside', 'size'):
            with self.subTest(mutation=mutation):
                data = fixture()
                main = next(p for c, p, s in commands(data) if c == 0x80000028)
                if mutation == 'missing':
                    struct.pack_into('<I', data, main, 0x2c)
                elif mutation == 'duplicate':
                    # Replace the same-sized harmless dependency with LC_MAIN.
                    dep = next(p for c, p, s in commands(data) if c == 0xc)
                    struct.pack_into('<IIQQ', data, dep, 0x80000028, 40, 4096, 0)
                elif mutation == 'size':
                    struct.pack_into('<I', data, main + 4, 16)
                else:
                    struct.pack_into('<Q', data, main + 8,
                                     {'header': 32, 'data': 8192, 'outside': 99999}[mutation])
                self.reject(data)

    def test_rejects_malformed_chained_starts_imports_and_pointers(self):
        changes = [
            ('version', 12288, '<I', 1), ('starts header', 12292, '<I', 4),
            ('segment count', 12316, '<I', 3), ('PAGEZERO starts', 12320, '<I', 20),
            ('record inside table', 12328, '<I', 4), ('record beyond blob', 12328, '<I', 999),
            ('zero record size', 12336, '<I', 0), ('short record', 12336, '<I', 22),
            ('oversized record', 12336, '<I', 99), ('page size', 12340, '<H', 3),
            ('pointer format', 12342, '<H', 1), ('segment offset', 12344, '<Q', 0),
            ('max valid pointer', 12352, '<I', 1), ('page count', 12356, '<H', 2),
            ('page start out of bounds', 12358, '<H', 4095),
            ('multi start overflow index', 12358, '<H', 0x8001),
            ('imports overlap starts', 12296, '<I', 32),
            ('imports out of bounds', 12296, '<I', 80),
            ('symbols overlap imports', 12300, '<I', 72),
            ('import count too large', 12304, '<I', 2),
            ('import format', 12308, '<I', 4), ('compressed symbols', 12312, '<I', 1),
            ('import symbol offset', 12360, '<I', (99 << 9) | 1),
            ('import library ordinal', 12360, '<I', 2),
            ('pointer import ordinal', 8192, '<Q', (1 << 63) | 1),
            ('pointer reserved bits', 8192, '<Q', (1 << 63) | (1 << 32)),
            ('pointer next crosses page', 8192, '<Q', (1 << 63) | (1024 << 51)),
        ]
        for label, off, fmt, value in changes:
            with self.subTest(label=label):
                data = fixture()
                struct.pack_into(fmt, data, off, value)
                self.reject(data)
        data = fixture()
        data[12367] = ord('x')
        self.reject(data)  # no terminating symbol NUL

    def test_supported_import_formats_and_pointer_formats_preserve_bytes(self):
        for import_format, pointer_format in ((1, 2), (2, 6), (3, 6)):
            with self.subTest(import_format=import_format, pointer_format=pointer_format):
                data = fixture()
                width = {1: 4, 2: 8, 3: 16}[import_format]
                data[12360:] = (struct.pack('<QQ', 1, 7) if width == 16 else
                                struct.pack('<Ii', 1, 7) if width == 8 else struct.pack('<I', 1)) + b'foo\0'
                length = 76 + width
                linkedit = next(p for c, p, s in commands(data) if c == 0x19 and data[p+8:p+24].rstrip(b'\0') == b'__LINKEDIT')
                fixups = next(p for c, p, s in commands(data) if c == 0x80000034)
                struct.pack_into('<Q', data, linkedit + 48, length)
                struct.pack_into('<I', data, fixups + 12, length)
                struct.pack_into('<I', data, 12300, 72 + width)
                struct.pack_into('<I', data, 12308, import_format)
                struct.pack_into('<H', data, 12342, pointer_format)
                result, converted = self.convert(data)
                self.assertEqual(result.returncode, 0, result.stderr)
                assert converted is not None
                self.assertEqual(converted[12336:], data[12336:])
                self.assertEqual(converted[8192:8200], data[8192:8200])

    def test_rejects_unsupported_ambiguous_commands_and_bad_ranges(self):
        data = fixture()
        locations = {c: p for c, p, s in commands(data)}
        text, section = 104, 176
        changes = [
            ('unknown command', locations[0x8000001c], '<I', 0x80000077),
            ('thread entry command', locations[0x8000001c], '<I', 5),
            ('encrypted image', locations[0x80000028], '<I', 0x2c),
            ('prebound header', 24, '<I', 0x200095),
            ('subtype', 8, '<I', 2), ('reserved header', 28, '<I', 1),
            ('segment flags', text + 68, '<I', 0xffffffff),
            ('section count', text + 64, '<I', 2),
            ('segment exceeds file', text + 48, '<Q', 999999),
            ('segment exceeds VM', text + 32, '<Q', 4096),
            ('section exceeds file', section + 48, '<I', 8190),
            ('section relocation', section + 60, '<I', 1),
            ('section VM mismatch', section + 32, '<Q', 0x100001004),
            ('dependency name offset', locations[0xc] + 8, '<I', 8),
            ('rpath name offset', locations[0x8000001c] + 8, '<I', 99),
            ('missing chained command', locations[0x80000034], '<I', 0x26),
            ('linkedit data outside segment', locations[0x80000034] + 8, '<I', 4096),
        ]
        for label, off, fmt, value in changes:
            with self.subTest(label=label):
                data = fixture()
                struct.pack_into(fmt, data, off, value)
                if label == 'encrypted image':
                    struct.pack_into('<I', data, off + 16, 1)
                self.reject(data)
        data = fixture()
        dep = locations[0xc]
        data[dep+24:dep+48] = b'x' * 24
        self.reject(data)
    def test_rejects_encryption_duplicate_commands_and_linkedit_bounds(self):
        data = fixture()
        locations = {c: p for c, p, s in commands(data)}
        # A duplicate LC_MAIN with exact cmdsize, not merely a malformed size.
        main = locations[0x80000028]
        self.reject(append_command(fixture(), bytes(fixture()[main:main+24])))
        for extra in (struct.pack('<6I', 0x2c, 24, 4096, 16, 1, 0),
                      struct.pack('<6I', 2, 24, 8192, 100, 8192, 4),
                      struct.pack('<4I', 0x26, 16, 8192, 8),
                      struct.pack('<6I', 0x32, 24, 2, 0, 0, 1),
                      struct.pack('<4I', 0x80000034, 16, 12288, 80)):
            with self.subTest(extra=extra.hex()):
                self.reject(append_command(fixture(), extra))

    def test_rejects_unknown_sections_misalignment_and_invalid_rebases(self):
        changes = [
            ('section type', 176 + 64, '<I', 0xff),
            ('section alignment', 176 + 52, '<I', 13),
            ('segment alignment', 104 + 32, '<Q', 8191),
            ('unsupported segment name', 256 + 8, '<16s', b'__UNKNOWN'),
            ('rebase outside image', 8192, '<Q', 0xfffffffff),
        ]
        for label, off, fmt, value in changes:
            with self.subTest(label=label):
                data = fixture()
                struct.pack_into(fmt, data, off, value)
                self.reject(data)

    def test_real_pagezero_position_flags_and_valid_rebase(self):
        data = fixture()
        data[32:256] = data[104:256] + data[32:104]
        self.reject(data)
        data = fixture()
        struct.pack_into('<I', data, 100, 1)
        self.reject(data)
        for pointer_format in (2, 6):
            with self.subTest(pointer_format=pointer_format):
                data = fixture()
                struct.pack_into('<H', data, 12342, pointer_format)
                struct.pack_into('<Q', data, 8192, 0x100001000 if pointer_format == 2 else 4096)
                result, converted = self.convert(data)
                self.assertEqual(result.returncode, 0, result.stderr)
                assert converted is not None
                self.assertEqual(converted[8192:8200], data[8192:8200])

    def test_existing_and_dangling_outputs_are_not_overwritten(self):
        for kind in ('file', 'dangling', 'input'):
            with self.subTest(kind=kind):
                self.convert(fixture(), kind)

    def test_rejects_both_legacy_dyld_info_commands(self):
        for command in (0x22, 0x80000022):
            data = fixture()
            pos = next(p for c, p, s in commands(data) if c == 0x8000001c)
            struct.pack_into('<I', data, pos, command)
            self.assertIn('legacy dyld opcodes are not supported', self.reject(data).stderr)

    def test_rejects_non_arm64_and_truncated_commands(self):
        data = fixture()
        struct.pack_into('<I', data, 4, 0x1000007)
        self.assertIn('thin arm64', self.reject(data).stderr)
        self.assertIn('truncated', self.reject(fixture()[:32]).stderr)

    def test_verifies_exact_input_hash_before_embedding(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = pathlib.Path(directory) / 'input.ipa'
            artifact.write_bytes(b'checksum test')
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            result = subprocess.run([sys.executable, str(SCRIPT), 'verify-hash', str(artifact), digest], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            rejected = subprocess.run([sys.executable, str(SCRIPT), 'verify-hash', str(artifact), '0' * 64], capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('SHA-256 mismatch', rejected.stderr)

    def test_combined_self_updates_use_our_patched_feed(self):
        hooks = (ROOT / 'SideStoreSupport' / 'SideStoreHooks.m').read_text()
        self.assertIn('https://raw.githubusercontent.com/Andris73/altstore/master/livecontainer-watch.json', hooks)
        self.assertNotIn('https://github.com/LiveContainer/LiveContainer/releases/latest/download/LiveContainer+SideStore.ipa', hooks)


if __name__ == '__main__':
    unittest.main()
