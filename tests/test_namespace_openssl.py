"""Synthetic load-command tests; these are NOT native install_name_tool proof."""
import importlib.util
import pathlib
import plistlib
import struct
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / 'tools/namespace_openssl.py'
SPEC = importlib.util.spec_from_file_location('namespace_openssl', MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
OLD = '@rpath/OpenSSL.framework/OpenSSL'
NEW = '@rpath/LCOpenSSL.framework/LCOpenSSL'


def module():
    if not MODULE_PATH.exists():
        raise AssertionError('standalone namespace implementation missing')
    result = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(result)
    return result


def named(cmd, name, versions=(7, 0x30303, 0x30000)):
    raw = name.encode() + b'\0'
    size = (24 + len(raw) + 7) // 8 * 8
    return (struct.pack('<6I', cmd, size, 24, *versions) + raw).ljust(size, b'\0')


def image(filetype=2, dependency: str | None = OLD, identity: str | None = None, kind=0xc, seed=1):
    commands = [struct.pack('<II16s', 0x1b, 24, bytes([seed]) * 16)]
    if identity is not None:
        commands.append(named(0xd, identity))
    if dependency is not None:
        commands.append(named(kind, dependency))
    commands.append(struct.pack('<6I', 0x32, 24, 2, 0x0f0000, 0x100000, 0))
    return (struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, filetype, len(commands),
                        sum(map(len, commands)), 0x85, 0) + b''.join(commands)).ljust(1024, b'\0') + b'INSTRUCTIONS-AND-IMPORT-ORDINALS'


def commands(data):
    offset = 32
    result = []
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, offset)
        result.append((cmd, data[offset:offset + size]))
        offset += size
    return result


class NativePatch:
    """Only native boundary is mocked: rewrite precise structured name commands."""
    def __init__(self):
        self.calls = []

    def __call__(self, args, *, check):
        assert check and args[0] == '/usr/bin/install_name_tool'
        self.calls.append(args)
        path = pathlib.Path(args[-1])
        data = path.read_bytes()
        rewritten = []
        for cmd, raw in commands(data):
            target = cmd == 0xd if args[1] == '-id' else cmd in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20)
            if target:
                offset = struct.unpack_from('<I', raw, 8)[0]
                name = raw[offset:].split(b'\0', 1)[0].decode()
                if args[1] == '-id' or name == args[2]:
                    raw = named(cmd, args[2] if args[1] == '-id' else args[3], struct.unpack_from('<3I', raw, 12))
            rewritten.append(raw)
        header = bytearray(data[:32])
        struct.pack_into('<I', header, 20, sum(map(len, rewritten)))
        path.write_bytes((header + b''.join(rewritten)).ljust(1024, b'\0') + data[1024:])
        return subprocess.CompletedProcess(args, 0)


def host(root):
    app = root / 'Host.app'
    framework = app / 'Frameworks/OpenSSL.framework'
    framework.mkdir(parents=True)
    info = dict(CFBundleExecutable='OpenSSL', CFBundleName='OpenSSL', CFBundleDisplayName='OpenSSL',
                CFBundleIdentifier='com.github.krzyzanowskim.OpenSSL', CFBundlePackageType='FMWK',
                CFBundleVersion='3.3.3001', MinimumOSVersion='12.0')
    (framework / 'Info.plist').write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
    (framework / 'OpenSSL').write_bytes(image(6, None, OLD))
    (framework / 'OpenSSL').chmod(0o755)
    (framework / 'LICENSE').write_text('original license')
    for index, name in enumerate(('Host', 'Frameworks/ZSign.dylib', 'PlugIns/Widget.appex/Widget', 'Frameworks/Other.framework/Other')):
        path = app / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(image(2 if index < 3 else 6, seed=index + 2))
    return app


class NamespaceTests(unittest.TestCase):
    def test_rejects_unsafe_inventory_before_mutation(self):
        cases = {
            'fat': lambda app: (app / 'Frameworks/ZSign.dylib').write_bytes(b'\xca\xfe\xba\xbe' + bytes(100)),
            'x86': lambda app: (app / 'Host').write_bytes(image().replace(struct.pack('<I', 0x100000c), struct.pack('<I', 0x1000007), 1)),
            'truncated': lambda app: (app / 'Host').write_bytes(image()[:45]),
            'unknown_path': lambda app: (app / 'Host').write_bytes(image(dependency='@loader_path/OpenSSL.framework/OpenSSL')),
            'flat': lambda app: self.header_change(app / 'Host', 24, 5),
            'force_flat': lambda app: self.header_change(app / 'Host', 24, 0x185),
            'destination': lambda app: (app / 'Frameworks/LCOpenSSL.framework').symlink_to('missing'),
            'linked_file': lambda app: (app / 'Host').symlink_to(app / 'Frameworks/ZSign.dylib') if not (app / 'Host').exists() else self.link(app),
            'hardlink': lambda app: self.hardlink(app),
            'foreign_id': lambda app: (app / 'Frameworks/Other.framework/Other').write_bytes(image(6, None, OLD)),
            'already_namespaced': lambda app: (app / 'Host').write_bytes(image(dependency=NEW)),
            'bad_offset': lambda app: self.command_change(app / 'Host', 1, 8, 16),
            'bad_size': lambda app: self.command_change(app / 'Host', 1, 4, 7),
            'trailing_name': lambda app: self.command_change(app / 'Host', 1, 56, 1),
            'duplicate_id': lambda app: self.append_command(app / 'Frameworks/OpenSSL.framework/OpenSSL', named(0xd, OLD)),
            'duplicate_dependency': lambda app: self.append_command(app / 'Host', named(0x80000018, OLD)),
            'duplicate_uuid': lambda app: self.append_command(app / 'Host', struct.pack('<II16s', 0x1b, 24, bytes(16))),
            'rpath_as_dependency': lambda app: self.append_command(app / 'Host', (struct.pack('<3I', 0x8000001c, 48, 12) + OLD.encode() + b'\0').ljust(48, b'\0')),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                app = host(pathlib.Path(tmp))
                mutate(app)
                patch = NativePatch()
                implementation = module()
                with self.assertRaises(implementation.NamespaceError):
                    implementation.namespace_host_openssl(app, runner=patch)
                self.assertEqual(patch.calls, [])
                self.assertTrue((app / 'Frameworks/OpenSSL.framework/OpenSSL').exists())

    @staticmethod
    def header_change(path, offset, value):
        data = bytearray(path.read_bytes())
        struct.pack_into('<I', data, offset, value)
        path.write_bytes(data)

    @staticmethod
    def command_change(path, index, offset, value):
        data = bytearray(path.read_bytes())
        start = 32 + sum(len(raw) for _, raw in commands(data)[:index])
        struct.pack_into('<I', data, start + offset, value)
        path.write_bytes(data)

    @staticmethod
    def append_command(path, raw):
        data = bytearray(path.read_bytes())
        size = struct.unpack_from('<I', data, 20)[0]
        count = struct.unpack_from('<I', data, 16)[0]
        data[32 + size:32 + size + len(raw)] = raw
        struct.pack_into('<II', data, 16, count + 1, size + len(raw))
        path.write_bytes(data)

    @staticmethod
    def link(app):
        (app / 'Host').unlink()
        (app / 'Host').symlink_to(app / 'Frameworks/ZSign.dylib')

    @staticmethod
    def hardlink(app):
        import os
        os.link(app / 'Host', app / 'HostAlias')

    def test_fails_closed_on_native_noop_and_corrupt_payload(self):
        for mode in ('noop', 'nonzero', 'instructions', 'earlier_image', 'metadata', 'license', 'mode'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                app = host(pathlib.Path(tmp))
                patch = NativePatch()
                def runner(args, *, check):
                    if mode == 'noop':
                        return subprocess.CompletedProcess(args, 0)
                    if mode == 'nonzero':
                        raise subprocess.CalledProcessError(1, args)
                    result = patch(args, check=check)
                    target = pathlib.Path(args[-1])
                    if mode == 'instructions':
                        target.write_bytes(target.read_bytes()[:-1] + b'X')
                    if mode == 'earlier_image' and target == app / 'Host':
                        earlier = app / 'Frameworks/LCOpenSSL.framework/LCOpenSSL'
                        earlier.write_bytes(earlier.read_bytes()[:-1] + b'X')
                    if mode == 'metadata':
                        (app / 'Frameworks/LCOpenSSL.framework/Info.plist').write_bytes(plistlib.dumps({}))
                    if mode == 'license':
                        (app / 'Frameworks/LCOpenSSL.framework/LICENSE').write_text('bad')
                    if mode == 'mode':
                        target.chmod(0o600)
                    return result
                implementation = module()
                with self.assertRaises(implementation.NamespaceError):
                    implementation.namespace_host_openssl(app, runner=runner)

    def test_rejects_uninventoried_paths_and_runtime_references(self):
        for mode in ('runtime_path', 'unknown_command_path', 'corrupt_bundle_executable', 'metadata_identity_collision', 'executable_destination'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                app = host(pathlib.Path(tmp))
                if mode == 'runtime_path':
                    path = app / 'Host'
                    path.write_bytes(path.read_bytes() + b'@loader_path/OpenSSL.framework/OpenSSL\0')
                if mode == 'unknown_command_path':
                    raw = (struct.pack('<II', 0x80000027, 64) + OLD.encode() + b'\0').ljust(64, b'\0')
                    self.append_command(app / 'Host', raw)
                if mode == 'corrupt_bundle_executable':
                    (app / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable': 'Host'}))
                    (app / 'Host').write_bytes(b'not macho')
                if mode == 'metadata_identity_collision':
                    (app / 'PlugIns/Widget.appex/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'com.kdt.livecontainer.LCOpenSSL', 'CFBundleExecutable': 'Widget'}))
                if mode == 'executable_destination':
                    (app / 'Frameworks/OpenSSL.framework/LCOpenSSL').write_text('do not clobber')
                patch = NativePatch()
                implementation = module()
                with self.assertRaises(implementation.NamespaceError):
                    implementation.namespace_host_openssl(app, runner=patch)
                self.assertEqual(patch.calls, [])

    def test_optional_absence_requires_zero_references_and_is_byte_unchanged(self):
        import shutil
        for referenced in (False, True):
            with self.subTest(referenced=referenced), tempfile.TemporaryDirectory() as tmp:
                app = host(pathlib.Path(tmp))
                shutil.rmtree(app / 'Frameworks/OpenSSL.framework')
                for path in app.rglob('*'):
                    if path.is_file():
                        path.write_bytes(image(dependency=OLD if referenced else '/usr/lib/libSystem.B.dylib'))
                before = {p: p.read_bytes() for p in app.rglob('*') if p.is_file()}
                patch = NativePatch()
                implementation = module()
                if referenced:
                    with self.assertRaises(implementation.NamespaceError):
                        implementation.namespace_host_openssl(app, runner=patch)
                else:
                    self.assertEqual(implementation.namespace_host_openssl(app, runner=patch), {'mapping': {}, 'images': []})
                self.assertEqual(before, {p: p.read_bytes() for p in app.rglob('*') if p.is_file()})
                self.assertEqual(patch.calls, [])

    def test_dependency_variants_are_native_patched_without_ordinal_changes(self):
        import shutil
        for kind in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                original = host(pathlib.Path(tmp) / 'immutable')
                (original / 'Host').write_bytes(image(kind=kind))
                before = {p.relative_to(original): p.read_bytes() for p in original.rglob('*') if p.is_file()}
                staged = pathlib.Path(tmp) / 'staged.app'
                shutil.copytree(original, staged)
                patch = NativePatch()
                report = module().namespace_host_openssl(staged, runner=patch)
                self.assertEqual(before, {p.relative_to(original): p.read_bytes() for p in original.rglob('*') if p.is_file()})
                self.assertIn(NEW.encode(), (staged / 'Host').read_bytes())
                self.assertEqual(report.get('native_commands'), patch.calls)

    def test_namespaces_every_host_consumer_preserving_identity_and_resources(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = host(pathlib.Path(tmp))
            before = {p.relative_to(app): p.read_bytes() for p in app.rglob('*') if p.is_file()}
            patch = NativePatch()
            report = module().namespace_host_openssl(app, runner=patch)
            renamed = app / 'Frameworks/LCOpenSSL.framework'
            self.assertFalse((app / 'Frameworks/OpenSSL.framework').exists())
            self.assertEqual((renamed / 'LICENSE').read_text(), 'original license')
            self.assertEqual((renamed / 'LCOpenSSL').stat().st_mode & 0o777, 0o755)
            info = plistlib.loads((renamed / 'Info.plist').read_bytes())
            self.assertEqual(info['CFBundleIdentifier'], 'com.kdt.livecontainer.LCOpenSSL')
            for key in ('CFBundleExecutable', 'CFBundleName', 'CFBundleDisplayName'):
                self.assertEqual(info[key], 'LCOpenSSL')
            self.assertEqual(info['CFBundleVersion'], '3.3.3001')
            self.assertEqual(len(patch.calls), 5)
            self.assertEqual(report['mapping'], {OLD: NEW})
            self.assertEqual(len(report['images']), 5)
            for oldpath, raw in before.items():
                if raw[:4] != b'\xcf\xfa\xed\xfe':
                    continue
                path = app / str(oldpath).replace('OpenSSL.framework/OpenSSL', 'LCOpenSSL.framework/LCOpenSSL')
                updated = path.read_bytes()
                self.assertEqual(raw[1024:], updated[1024:])
                self.assertEqual(commands(raw)[0], commands(updated)[0])
                self.assertNotIn(OLD.encode(), updated)
                self.assertIn(NEW.encode(), updated)
                self.assertEqual([c for c, _ in commands(raw)], [c for c, _ in commands(updated)])


if __name__ == '__main__':
    unittest.main()
