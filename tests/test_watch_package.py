import hashlib
import importlib.util
import pathlib
import plistlib
import struct
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import package_watch as package


def macho(filetype=2, seed=1):
    """Complete arm64 source fixture: instructions, LC_MAIN, imports and fixup page."""
    def segment(name, vm, size, offset, backed, protection, sections=0):
        return struct.pack('<II16sQQQQiiII', 0x19, 72 + 80 * sections, name, vm, size, offset, backed, protection, protection, sections, 0)
    section = struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT', 0x100001000, 16, 4096, 2, 0, 0, 0x80000400, 0, 0, 0)
    dependency = (struct.pack('<6I', 0xc, 48, 24, 0, 0, 0) + b'/usr/lib/a.dylib\0').ljust(48, b'\0')
    rpath = (struct.pack('<3I', 0x8000001c, 32, 12) + b'@executable_path\0').ljust(32, b'\0')
    segment_count = 4 if filetype == 2 else 3
    record_offset = 4 + 4 * segment_count
    imports_offset = 28 + record_offset + 24
    symbols_offset = imports_offset + 4
    fixups_size = symbols_offset + 4
    commands = segment(b'__PAGEZERO', 0, 0x100000000, 0, 0, 0) if filetype == 2 else b''
    commands += (segment(b'__TEXT', 0x100000000, 8192, 0, 8192, 5, 1) + section
                 + segment(b'__DATA', 0x100002000, 4096, 8192, 4096, 3)
                 + segment(b'__LINKEDIT', 0x100003000, 4096, 12288, fixups_size, 1))
    if filetype == 2:
        commands += struct.pack('<IIQQ', 0x80000028, 24, 4096, 0)
    commands += dependency + rpath + struct.pack('<4I', 0x80000034, 16, 12288, fixups_size)
    commands += struct.pack('<II16s', 0x1b, 24, bytes([seed]) * 16)
    data = bytearray((struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, filetype, 9 if filetype == 2 else 7,
                                  len(commands), 0x200085 if filetype == 2 else 0x85, 0) + commands).ljust(12288 + fixups_size, b'\0'))
    data[4096:4112] = bytes.fromhex('1f2003d5' * 4)
    struct.pack_into('<Q', data, 8192, 1 << 63)
    struct.pack_into('<7I', data, 12288, 0, 28, imports_offset, symbols_offset, 1, 1, 0)
    entries = (0, 0, record_offset, 0) if filetype == 2 else (0, record_offset, 0)
    struct.pack_into('<I', data, 12316, segment_count)
    struct.pack_into(f'<{segment_count}I', data, 12320, *entries)
    struct.pack_into('<IHHQIH', data, 12316 + record_offset, 24, 4096, 6, 8192, 0, 1)
    struct.pack_into('<H', data, 12316 + record_offset + 22, 0)
    struct.pack_into('<I', data, 12288 + imports_offset, 1)
    data[12288 + symbols_offset:] = b'foo\0'
    return bytes(data)


def bundle(path, identifier, executable, filetype=2, seed=1, **info):
    path.mkdir(parents=True)
    metadata = dict(CFBundleIdentifier=identifier, CFBundleExecutable=executable,
                    CFBundleName=executable, CFBundleShortVersionString='0.7',
                    CFBundleVersion='311', CFBundlePackageType='APPL', MinimumOSVersion='15.0')
    metadata.update(info)
    (path / 'Info.plist').write_bytes(plistlib.dumps(metadata))
    (path / executable).write_bytes(macho(filetype, seed))
    (path / executable).chmod(0o755)
    return path


def fixture(root):
    host = bundle(root / 'LiveContainer.app', 'com.kdt.livecontainer', 'LiveContainer')
    bundle(host / 'Frameworks/SideStoreSupport.framework', 'com.kdt.livecontainer.SideStoreSupport', 'SideStoreSupport', 6)
    side = bundle(root / 'SideStore.app', 'com.SideStore.SideStore', 'SideStore', MinimumOSVersion='17.0')
    bundle(side / 'PlugIns/AltWidgetExtension.appex', 'com.SideStore.SideStore.AltWidget', 'AltWidgetExtension',
           NSExtension={'NSExtensionPrincipalClass': 'AltWidgetExtension.Widget', 'NSExtensionPointIdentifier': 'com.apple.widgetkit-extension'})
    backup_archive = root / 'SideBackup.xcarchive'
    helper = bundle(backup_archive / 'Products/Applications/SideBackup.app', 'com.SideStore.SideStore.SideBackup', 'SideBackup', seed=2)
    dwarf = backup_archive / 'dSYMs/SideBackup.app.dSYM/Contents/Resources/DWARF/SideBackup'
    dwarf.parent.mkdir(parents=True)
    dwarf.write_bytes(macho(10, 2))
    with zipfile.ZipFile(side / 'SideBackup.ipa', 'w') as archive:
        for item in helper.rglob('*'):
            if item.is_file():
                archive.write(item, 'Payload/SideBackup.app/' + item.relative_to(helper).as_posix())
    for name in ('Intents.intentdefinition', 'ViewApp.intentdefinition'):
        (side / name).write_bytes(plistlib.dumps({'fixture': name}))
    (side / 'Metadata.appintents').mkdir()
    (side / 'Metadata.appintents/extract.actionsdata').write_text('{"type":"9SideStore20RefreshAllAppsIntentV"}')
    return host, side, backup_archive


def snapshot(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file()}


class PackageTests(unittest.TestCase):
    def assemble(self, root, host, side, backup):
        self.assertIn('backup_archive', __import__('inspect').signature(package.assemble).parameters, 'native helper archive must be authenticated')
        return package.assemble(host, side, root / 'output', {'host': {'version': '3.8.11', 'build': '381101'}}, 'f' * 40, backup_archive=backup)

    def test_helper_zip_graph_preflight(self):
        import io
        cases = [('x', 'x/child'), ('NAME', 'name'), ('caf\u00e9', 'cafe\u0301')]
        for first, second in cases:
            with self.subTest(first=first), io.BytesIO() as buffer:
                with zipfile.ZipFile(buffer, 'w') as z:
                    z.writestr('Payload/SideBackup.app/' + first, b'one')
                    z.writestr('Payload/SideBackup.app/' + second, b'two')
                buffer.seek(0)
                with zipfile.ZipFile(buffer) as z:
                    with self.assertRaisesRegex(ValueError, 'unsafe SideBackup IPA member'):
                        package.helper_zip_inventory(z)

    def test_helper_zip_aliases_are_rejected(self):
        for alias in ('Payload/SideBackup.app/./SideBackup', 'Payload//SideBackup.app/SideBackup'):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                host, side, backup = fixture(root)
                ipa = side / 'SideBackup.ipa'
                with zipfile.ZipFile(ipa) as z:
                    entries = [(e, z.read(e)) for e in z.infolist()]
                native = (backup / 'Products/Applications/SideBackup.app/SideBackup').read_bytes()
                with zipfile.ZipFile(ipa, 'w') as z:
                    for e, data in entries:
                        if e.filename == 'Payload/SideBackup.app/SideBackup':
                            data = bytearray(data)
                            data[4096] ^= 1
                        z.writestr(e, data)
                    z.writestr(alias, native)
                before = snapshot(root)
                with self.assertRaisesRegex(ValueError, 'unsafe SideBackup IPA member'):
                    self.assemble(root, host, side, backup)
                self.assertEqual(snapshot(root), before)
                self.assertFalse((root / 'output').exists())

    def test_namespace_runs_before_guest_copy(self):
        from unittest.mock import patch
        def hook(host_copy):
            self.assertFalse((host_copy / 'Frameworks/SideStoreApp.framework').exists())
            self.assertTrue((host_copy / 'LiveContainer').is_file())
            return {'mapping': {}, 'images': []}
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            host, side, backup = fixture(root)
            with patch.object(package, 'namespace_host_openssl', side_effect=hook) as call:
                result = self.assemble(root, host, side, backup)
            call.assert_called_once()
            self.assertIn('host_openssl_namespace', (result / 'LCWatchBuild.json').read_text())

    def test_namespace_failure_is_atomic(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            host, side, backup = fixture(root)
            before = snapshot(root)
            with patch.object(package, 'namespace_host_openssl', side_effect=ValueError('namespace failure')):
                with self.assertRaisesRegex(ValueError, 'namespace failure'):
                    self.assemble(root, host, side, backup)
            self.assertEqual(snapshot(root), before)
            self.assertFalse((root / 'output').exists())

    def test_combines_actual_widget_guest_contract_resources_and_immutable_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            host, side, backup = fixture(root)
            bundle(host / 'PlugIns/ShareExtension.appex', 'com.kdt.livecontainer.ShareExtension', 'ShareExtension')
            (host / 'NOTICE').write_text('existing license notice')
            (side / 'LICENSE').write_text('existing corresponding source notice')
            # A relative internal plist link is safely materialized before mutation.
            (host / 'Info.plist').rename(host / 'Original.plist')
            (host / 'Info.plist').symlink_to('Original.plist')
            before = snapshot(root)
            result = self.assemble(root, host, side, backup)
            info = package.read_info(result)
            self.assertEqual(info['MinimumOSVersion'], '17.0')
            self.assertEqual(info['CFBundleVersion'], '381101')
            guest = result / 'Frameworks/SideStoreApp.framework'
            config = plistlib.loads((guest / 'LCAppInfo.plist').read_bytes())
            self.assertEqual(config['LCDataUUID'], config['LCContainers'][0]['folderName'])
            for policy in ('dontInjectTweakLoader', 'dontLoadTweakLoader', 'dontSign'):
                self.assertIs(config[policy], True)
            widget = result / 'PlugIns/LiveWidgetExtension.appex'
            metadata = package.read_info(widget)
            self.assertEqual(metadata['CFBundleExecutable'], 'LiveWidgetExtension')
            self.assertEqual(metadata['CFBundleName'], 'LiveWidgetExtension')
            self.assertEqual(metadata['CFBundleIdentifier'], 'com.kdt.livecontainer.LiveWidgetExtension')
            self.assertEqual(metadata['NSExtension']['NSExtensionPrincipalClass'], 'AltWidgetExtension.Widget')
            self.assertEqual((widget / 'LiveWidgetExtension').read_bytes(), (side / 'PlugIns/AltWidgetExtension.appex/AltWidgetExtension').read_bytes())
            self.assertIn('RefreshAllIntent', info['INIntentsSupported'])
            self.assertIn('16SideStoreSupport20RefreshAllAppsIntentV', (result / 'Metadata.appintents/extract.actionsdata').read_text())
            self.assertIn('9SideStore20RefreshAllAppsIntentV', (guest / 'Metadata.appintents/extract.actionsdata').read_text())
            self.assertEqual((result / 'NOTICE').read_text(), 'existing license notice')
            self.assertEqual((guest / 'LICENSE').read_text(), 'existing corresponding source notice')
            self.assertFalse(any(p.is_symlink() for p in result.rglob('*')))
            after = snapshot(root)
            self.assertEqual(before, {k: after[k] for k in before})
            self.assertEqual(package.macho_info(side / 'SideStore')['uuid'], package.macho_info(guest / 'SideStore')['uuid'])

    def test_native_helper_identity_architecture_uuid_and_bytes_are_required(self):
        for corruption in ('text-zip', 'identity', 'architecture', 'dsym', 'helper-extension', 'ipa-bytes'):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                host, side, backup = fixture(root)
                helper = backup / 'Products/Applications/SideBackup.app'
                if corruption == 'text-zip':
                    with zipfile.ZipFile(side / 'SideBackup.ipa', 'w') as archive:
                        archive.writestr('text', 'not native')
                elif corruption == 'identity':
                    info = package.read_info(helper)
                    info['CFBundleIdentifier'] = 'other.app'
                    package.write_info(helper, info)
                elif corruption == 'architecture':
                    binary = bytearray((helper / 'SideBackup').read_bytes())
                    struct.pack_into('<I', binary, 4, 7)
                    (helper / 'SideBackup').write_bytes(binary)
                elif corruption == 'dsym':
                    (backup / 'dSYMs/SideBackup.app.dSYM/Contents/Resources/DWARF/SideBackup').write_bytes(macho(10, 3))
                elif corruption == 'helper-extension':
                    bundle(helper / 'PlugIns/AltWidgetExtension.appex', 'com.SideStore.SideStore.AltWidget', 'AltWidgetExtension')
                else:
                    (helper / 'SideBackup').write_bytes(macho(2, 3))
                    (backup / 'dSYMs/SideBackup.app.dSYM/Contents/Resources/DWARF/SideBackup').write_bytes(macho(10, 3))
                with self.assertRaises((ValueError, zipfile.BadZipFile)):
                    self.assemble(root, host, side, backup)
                self.assertFalse((root / 'output').exists())
                self.assertFalse(list(root.glob('.watch-package-*')))

    def test_embedded_helper_framework_must_match_native_code_and_metadata(self):
        for difference in ('uuid', 'bytes-same-uuid', 'minimum-os', 'bundle-metadata'):
            with self.subTest(difference=difference), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                host, side, backup = fixture(root)
                helper = backup / 'Products/Applications/SideBackup.app'
                framework = bundle(helper / 'Frameworks/HelperSupport.framework',
                                   'test.helper.support', 'HelperSupport', 6, seed=3,
                                   MinimumOSVersion='16.0')
                overrides = {}
                if difference in ('uuid', 'bytes-same-uuid'):
                    code = bytearray(macho(6, 4 if difference == 'uuid' else 3))
                    code[4096] ^= 1
                    overrides[framework / 'HelperSupport'] = bytes(code)
                else:
                    info = package.read_info(framework)
                    info['MinimumOSVersion' if difference == 'minimum-os' else 'CFBundleVersion'] = '23.0'
                    overrides[framework / 'Info.plist'] = plistlib.dumps(info)
                with zipfile.ZipFile(side / 'SideBackup.ipa', 'w') as archive:
                    for item in helper.rglob('*'):
                        if item.is_file():
                            archive.writestr('Payload/SideBackup.app/' + item.relative_to(helper).as_posix(),
                                             overrides.get(item, item.read_bytes()))
                before = snapshot(root)
                with self.assertRaisesRegex(ValueError, 'embedded SideBackup.*native archive'):
                    self.assemble(root, host, side, backup)
                self.assertEqual(snapshot(root), before)
                self.assertFalse((root / 'output').exists())
                self.assertFalse(list(root.glob('.watch-package-*')))
                self.assertFalse((root / '.output.reserved').exists())

    def test_embedded_helper_requires_complete_matching_framework_and_dylib_inventory(self):
        for product in ('framework', 'dylib'):
            for difference in ('missing', 'extra', 'uuid', 'bytes-same-uuid', 'deployment-command'):
                with self.subTest(product=product, difference=difference), tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    host, side, backup = fixture(root)
                    helper = backup / 'Products/Applications/SideBackup.app'
                    framework = bundle(helper / 'Frameworks/HelperSupport.framework',
                                       'test.helper.support', 'HelperSupport', 6, seed=3,
                                       MinimumOSVersion='16.0')
                    code = framework / 'HelperSupport'
                    if product == 'dylib':
                        code = framework / 'libInner.dylib'
                        code.write_bytes(macho(6, 3))
                    changes = {}
                    omitted = set()
                    if difference == 'missing':
                        omitted = {p for p in framework.rglob('*') if p.is_file()} if product == 'framework' else {code}
                    elif difference == 'extra':
                        if product == 'framework':
                            relative = 'Frameworks/Extra.framework/'
                            info = package.read_info(framework)
                            info.update(CFBundleExecutable='Extra', CFBundleIdentifier='test.helper.extra', MinimumOSVersion='23.0')
                            changes[relative + 'Info.plist'] = plistlib.dumps(info)
                            changes[relative + 'Extra'] = macho(6, 4)
                        else:
                            changes['Frameworks/libExtra.dylib'] = macho(6, 4)
                    else:
                        data = bytearray(macho(6, 4 if difference == 'uuid' else 3))
                        if difference == 'bytes-same-uuid':
                            data[4096] ^= 1
                        elif difference == 'deployment-command':
                            # Insert LC_BUILD_VERSION without changing the native UUID.
                            count, size = struct.unpack_from('<II', data, 16)
                            data[32 + size:32 + size + 24] = struct.pack('<6I', 0x32, 24, 2, 23 << 16, 23 << 16, 0)
                            struct.pack_into('<II', data, 16, count + 1, size + 24)
                        changes[code.relative_to(helper).as_posix()] = bytes(data)
                    with zipfile.ZipFile(side / 'SideBackup.ipa', 'w') as archive:
                        for item in helper.rglob('*'):
                            if item.is_file() and item not in omitted:
                                relative = item.relative_to(helper).as_posix()
                                archive.writestr('Payload/SideBackup.app/' + relative,
                                                 changes.pop(relative, item.read_bytes()))
                        for relative, data in changes.items():
                            archive.writestr('Payload/SideBackup.app/' + relative, data)
                    before = snapshot(root)
                    with self.assertRaisesRegex(ValueError, 'embedded SideBackup.*native archive'):
                        self.assemble(root, host, side, backup)
                    self.assertEqual(snapshot(root), before)
                    self.assertFalse((root / 'output').exists())
                    self.assertFalse(list(root.glob('.watch-package-*')))
                    self.assertFalse((root / '.output.reserved').exists())

    def test_equivalent_nested_helper_products_preserve_deployment_maximum_and_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            host, side, backup = fixture(root)
            helper = backup / 'Products/Applications/SideBackup.app'
            framework = bundle(helper / 'Frameworks/HelperSupport.framework',
                               'test.helper.support', 'HelperSupport', 6, seed=3,
                               MinimumOSVersion='19.0')
            bundle(framework / 'Frameworks/Nested.framework', 'test.helper.nested',
                   'Nested', 6, seed=4, MinimumOSVersion='20.0')
            dylib = framework / 'libInner.dylib'
            data = bytearray(macho(6, 5))
            count, size = struct.unpack_from('<II', data, 16)
            data[32 + size:32 + size + 24] = struct.pack('<6I', 0x32, 24, 2, 21 << 16, 21 << 16, 0)
            struct.pack_into('<II', data, 16, count + 1, size + 24)
            dylib.write_bytes(data)
            # A safe native plist link is materialized; plist serialization need
            # not match byte-for-byte when all bundle metadata values do.
            (framework / 'Info.plist').rename(framework / 'Original.plist')
            (framework / 'Info.plist').symlink_to('Original.plist')
            with zipfile.ZipFile(side / 'SideBackup.ipa', 'w') as archive:
                for item in helper.rglob('*'):
                    if item.is_file():
                        data = item.read_bytes()
                        if item.name == 'Info.plist':
                            data = plistlib.dumps(plistlib.loads(data), fmt=plistlib.FMT_BINARY)
                        archive.writestr('Payload/SideBackup.app/' + item.relative_to(helper).as_posix(), data)
            before = {str(p): package.source_snapshot(p) for p in (host, side, backup)}
            result = self.assemble(root, host, side, backup)
            self.assertEqual(package.read_info(result)['MinimumOSVersion'], '21.0.0')
            carried = result / 'Frameworks/SideStoreApp.framework/SideBackup.ipa'
            self.assertEqual(carried.read_bytes(), (side / 'SideBackup.ipa').read_bytes())
            self.assertEqual({str(p): package.source_snapshot(p) for p in (host, side, backup)}, before)

    def test_unknown_or_invalid_host_extension_fails_closed(self):
        for name, identifier, binary in [('Unknown', 'com.kdt.livecontainer.Unknown', True),
                                         ('ShareExtension', 'other.app', True),
                                         ('LiveProcess', 'com.kdt.livecontainer.LiveProcess', False)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                host, side, backup = fixture(root)
                extension = bundle(host / f'PlugIns/{name}.appex', identifier, name)
                if not binary:
                    (extension / name).unlink()
                with self.assertRaises(ValueError):
                    self.assemble(root, host, side, backup)
                self.assertFalse((root / 'output').exists())

    def test_output_dangling_link_collision_failure_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            host, side, backup = fixture(root)
            output = root / 'output'
            output.symlink_to('missing')
            with self.assertRaises((ValueError, FileExistsError)):
                self.assemble(root, host, side, backup)
            self.assertTrue(output.is_symlink())
            output.unlink()
            bundle(side / 'Frameworks/SideStoreSupport.framework', 'com.other.support', 'SideStoreSupport', 6)
            with self.assertRaisesRegex(ValueError, 'collision'):
                self.assemble(root, host, side, backup)
            self.assertFalse(output.exists())
            self.assertFalse(list(root.glob('.watch-package-*')))

    def test_signing_inventory_is_bottom_up_across_extensions(self):
        with tempfile.TemporaryDirectory() as directory:
            app = bundle(pathlib.Path(directory) / 'Host.app', 'test.host', 'Host')
            extension = bundle(app / 'PlugIns/Test.appex', 'test.host.ext', 'Test')
            framework = bundle(extension / 'Frameworks/Nested.framework', 'test.nested', 'Nested', 6)
            dylib = framework / 'libInner.dylib'
            dylib.write_bytes(macho(6))
            self.assertTrue(hasattr(package, 'signing_inventory'), 'recursive bottom-up signing is missing')
            order = package.signing_inventory(app)
            self.assertLess(order.index(dylib), order.index(framework))
            self.assertLess(order.index(framework), order.index(extension))
            self.assertLess(order.index(extension), order.index(app))

    def test_native_host_viewapp_resource_is_retained_when_guest_contract_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            host, side, backup = fixture(root)
            intent = {'INIntentDefinitionNamespace': 'TPucbY', 'INIntents': [{'INIntentName': 'ViewApp', 'INIntentParameters': [{'INIntentParameterName': 'app', 'INIntentParameterType': 'Object', 'INIntentParameterTag': 2, 'INIntentParameterObjectType': 'App', 'INIntentParameterObjectTypeNamespace': 'TPucbY'}]}], 'INTypes': [], 'INEnums': []}
            guest_resource = plistlib.dumps({**intent, 'INIntentDefinitionToolsVersion': '12.0'})
            host_resource = plistlib.dumps({**intent, 'INIntentDefinitionToolsVersion': '26.0'})
            (host / 'ViewApp.intentdefinition').write_bytes(host_resource)
            (side / 'ViewApp.intentdefinition').write_bytes(guest_resource)
            result = self.assemble(root, host, side, backup)
            self.assertEqual((result / 'ViewApp.intentdefinition').read_bytes(), host_resource)
            self.assertEqual((result / 'Frameworks/SideStoreApp.framework/ViewApp.intentdefinition').read_bytes(), guest_resource)

    def test_recursive_internal_directory_links_fail_before_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            host, side, backup = fixture(root)
            (host / 'a').mkdir()
            (host / 'b').mkdir()
            (host / 'a/to-b').symlink_to('../b')
            (host / 'b/to-a').symlink_to('../a')
            with self.assertRaisesRegex(ValueError, 'recursive|cyclic'):
                package.check_source(host)

    def test_helper_minimum_os_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            host, side, backup = fixture(root)
            helper = backup / 'Products/Applications/SideBackup.app'
            info = package.read_info(helper)
            info['MinimumOSVersion'] = '18.0'
            package.write_info(helper, info)
            bundle(helper / 'Frameworks/HelperSupport.framework', 'test.helper.support', 'HelperSupport', 6, MinimumOSVersion='19.0')
            with zipfile.ZipFile(side / 'SideBackup.ipa', 'w') as archive:
                for item in helper.rglob('*'):
                    if item.is_file():
                        archive.write(item, 'Payload/SideBackup.app/' + item.relative_to(helper).as_posix())
            result = self.assemble(root, host, side, backup)
            self.assertEqual(package.read_info(result)['MinimumOSVersion'], '19.0')

    def test_signing_command_boundary_uses_placeholders_then_genuine_verify(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            app = bundle(root / 'Host.app', 'test.host', 'Host')
            extension = bundle(app / 'PlugIns/Test.appex', 'test.host.ext', 'Test')
            framework = bundle(extension / 'Frameworks/Nested.framework', 'test.nested', 'Nested', 6)
            dylib = framework / 'libInner.dylib'
            dylib.write_bytes(macho(6))
            with patch.object(package.subprocess, 'run') as run:
                package.sign_tree(app, root)
            calls = [call.args[0] for call in run.call_args_list]
            self.assertEqual([pathlib.Path(call[-1]) for call in calls[:-1]], package.signing_inventory(app))
            self.assertEqual(calls[-1], ['/usr/bin/codesign', '--verify', '--deep', '--strict', '--verbose=2', str(app)])
            for call in calls[:-1]:
                self.assertEqual(call[call.index('--sign') + 1], '-')
                self.assertNotIn('--deep', call)
            for path in root.glob('*.entitlements.plist'):
                entitlements = plistlib.loads(path.read_bytes())
                self.assertEqual(entitlements['com.apple.developer.team-identifier'], 'XYZ0123456')

    def test_rejects_absolute_internal_link_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            host, _, _ = fixture(pathlib.Path(directory))
            original = host / 'Original.plist'
            (host / 'Info.plist').rename(original)
            (host / 'Info.plist').symlink_to(original)
            before = snapshot(host)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                package.check_source(host)
            self.assertEqual(snapshot(host), before)

    def test_rejects_escaping_and_dangling_links(self):
        with tempfile.TemporaryDirectory() as directory:
            host, _, _ = fixture(pathlib.Path(directory))
            for target in ('../../outside', 'missing'):
                link = host / 'bad'
                link.symlink_to(target)
                with self.assertRaises(ValueError):
                    package.check_source(host)
                link.unlink()


if __name__ == '__main__':
    unittest.main()
