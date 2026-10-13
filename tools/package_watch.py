#!/usr/bin/env python3
"""Assemble authenticated native inputs without mutating them; ad-hoc signing only."""
import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import uuid
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from watch_build import convert_executable
from native_inputs import publish
from namespace_openssl import namespace_host_openssl

ROOT = pathlib.Path(__file__).resolve().parents[1]
HOST_EXTENSIONS = {'LiveProcess', 'ShareExtension', 'LaunchAppExtension'}
MAGICS = {b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'}


def read_info(bundle):
    with (bundle / 'Info.plist').open('rb') as stream:
        return plistlib.load(stream)


def write_info(bundle, data):
    path = bundle / 'Info.plist'
    if path.is_symlink():
        raise ValueError('refusing plist mutation through a symlink')
    path.write_bytes(plistlib.dumps(data))


def check_tree(bundle, allow_links=True):
    bundle = pathlib.Path(bundle)
    if not bundle.is_dir() or bundle.is_symlink():
        raise ValueError(f'missing native directory or symlink root: {bundle}')
    for item in bundle.rglob('*'):
        if item.is_symlink():
            try:
                target = item.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise ValueError(f'dangling or cyclic symlink: {item}') from error
            if not allow_links or item.readlink().is_absolute() or not target.is_relative_to(bundle.resolve()):
                raise ValueError(f'unsafe symlink: {item}')
            # copytree can otherwise loop forever when materializing ancestor links.
            if target.is_dir() and item.parent.resolve().is_relative_to(target):
                raise ValueError('recursive directory symlink')
        elif not (item.is_dir() or item.is_file()):
            raise ValueError(f'unsupported native file: {item}')
    if allow_links:
        def visit(directory, ancestors):
            real = directory.resolve()
            if real in ancestors:
                raise ValueError('recursive directory symlink graph')
            for child in directory.iterdir():
                if child.is_dir():
                    visit(child, (*ancestors, real))
        visit(bundle, ())


def macho_info(path, expected_types=(2, 6, 8, 10)):
    data = pathlib.Path(path).read_bytes()
    if len(data) < 32:
        raise ValueError('truncated native Mach-O')
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', data)
    if magic != 0xfeedfacf or cpu != 0x100000c or kind not in expected_types or size > len(data) - 32:
        raise ValueError('expected supported thin arm64 native Mach-O architecture/type')
    position, native_uuid, minimum = 32, None, None
    for _ in range(count):
        if position + 8 > 32 + size:
            raise ValueError('truncated native load commands')
        command, length = struct.unpack_from('<II', data, position)
        if length < 8 or length % 8 or position + length > 32 + size:
            raise ValueError('invalid native load command')
        if command == 0x1b:
            if length != 24 or native_uuid is not None:
                raise ValueError('invalid native UUID command')
            native_uuid = str(uuid.UUID(bytes=data[position + 8:position + 24]))
        if command in (0x24, 0x25, 0x2f, 0x30, 0x32):
            if length < (24 if command == 0x32 else 16):
                raise ValueError('truncated deployment command')
            if command == 0x32 and struct.unpack_from('<I', data, position + 8)[0] != 2:
                raise ValueError('not an iOS device binary')
            # LC_VERSION_MIN_IPHONEOS is 0x25; 0x24 is the macOS variant.
            if command in (0x24, 0x2f, 0x30):
                raise ValueError('unsupported native platform')
            packed = struct.unpack_from('<I', data, position + (12 if command == 0x32 else 8))[0]
            minimum = f'{packed >> 16}.{(packed >> 8) & 255}.{packed & 255}'
        position += length
    if position != 32 + size or not native_uuid or native_uuid == str(uuid.UUID(int=0)):
        raise ValueError('missing native UUID or inconsistent load commands')
    return {'uuid': native_uuid, 'architecture': 'arm64', 'filetype': kind, 'minimum_os': minimum}


def check_source(bundle, expected_identifier=None, expected_executable=None):
    bundle = pathlib.Path(bundle)
    check_tree(bundle)
    info = read_info(bundle)
    executable = info.get('CFBundleExecutable', '')
    identifier = info.get('CFBundleIdentifier', '')
    if not isinstance(executable, str) or not executable or pathlib.Path(executable).name != executable or executable in ('.', '..') or not (bundle / executable).is_file():
        raise ValueError('invalid bundle executable')
    if not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', identifier):
        raise ValueError('invalid bundle identity')
    if expected_identifier and identifier != expected_identifier:
        raise ValueError(f'unexpected native identity: {identifier}')
    if expected_executable and executable != expected_executable:
        raise ValueError('unexpected native executable name')
    macho_info(bundle / executable, (6,) if bundle.suffix == '.framework' else (2,))
    return info


def signing_inventory(app):
    app = pathlib.Path(app)
    check_tree(app, allow_links=False)
    bundles = [app, *(p for p in app.rglob('*') if p.is_dir() and p.suffix in ('.framework', '.appex', '.app'))]
    executables = set()
    for bundle in bundles:
        info = check_source(bundle)
        executables.add(bundle / info['CFBundleExecutable'])
    dylibs = list(app.rglob('*.dylib'))
    for dylib in dylibs:
        macho_info(dylib, (6,))
    for item in app.rglob('*'):
        if item.is_file():
            with item.open('rb') as stream:
                magic = stream.read(4)
            if magic in MAGICS and item not in executables and item not in dylibs:
                raise ValueError(f'unreviewed code product: {item}')
    return sorted([*bundles, *dylibs], key=lambda p: (-len(p.parts), p.as_posix()))


def validate_products(app, side=False):
    check_source(app)
    # Product allowlist comes from the pinned project.pbxproj + target xcconfigs.
    project = (ROOT / 'LiveContainer.xcodeproj/project.pbxproj').read_text()
    for extension in app.rglob('*.appex'):
        name = extension.stem
        if side:
            if name != 'AltWidgetExtension' or extension.parent != app / 'PlugIns':
                raise ValueError(f'unreviewed SideStore extension: {extension.name}')
            check_source(extension, 'com.SideStore.SideStore.AltWidget', name)
        else:
            if name not in HOST_EXTENSIONS or f'path = {name}.appex;' not in project or extension.parent not in (app / 'PlugIns', app / 'Extensions'):
                raise ValueError(f'unreviewed host extension: {extension.name}')
            check_source(extension, 'com.kdt.livecontainer.' + name, name)
    for child in app.rglob('*.app'):
        raise ValueError(f'unreviewed nested application: {child}')
    # Materialize links in a private copy before inventory inspection.
    with tempfile.TemporaryDirectory(prefix='watch-inventory-') as directory:
        copy = pathlib.Path(directory) / app.name
        shutil.copytree(app, copy, symlinks=False)
        signing_inventory(copy)


def validate_archive(archive, name, identifier):
    archive = pathlib.Path(archive)
    check_tree(archive)
    applications = archive / 'Products/Applications'
    if sorted(p.name for p in applications.iterdir()) != [f'{name}.app']:
        raise ValueError('unexpected native archive applications')
    app = applications / f'{name}.app'
    info = check_source(app, identifier, name)
    binary = macho_info(app / info['CFBundleExecutable'], (2,))
    dwarf = archive / f'dSYMs/{name}.app.dSYM/Contents/Resources/DWARF/{name}'
    if macho_info(dwarf, (10,))['uuid'] != binary['uuid']:
        raise ValueError('native archive dSYM UUID mismatch')
    return app, binary


def helper_zip_inventory(backup):
    import unicodedata
    inventory = {}
    for entry in backup.infolist():
        name = pathlib.PurePosixPath(entry.filename)
        canonical = name.as_posix() + ('/' if entry.is_dir() else '')
        kind = stat.S_IFMT(entry.external_attr >> 16)
        key = unicodedata.normalize('NFC', name.as_posix()).casefold()
        if (entry.filename != canonical or entry.orig_filename != entry.filename
                or name.is_absolute() or '..' in name.parts or '\\' in entry.filename
                or key in inventory or kind not in (0, stat.S_IFREG, stat.S_IFDIR)
                or (entry.external_attr >> 16) & 0o7000
                or (kind == stat.S_IFDIR and not entry.is_dir())
                or (kind == stat.S_IFREG and entry.is_dir())
                or (entry.is_dir() and entry.file_size)):
            raise ValueError('unsafe SideBackup IPA member')
        if name.parts[:2] != ('Payload', 'SideBackup.app') and entry.filename != 'Payload/':
            raise ValueError('unexpected helper IPA topology')
        inventory[key] = (name, entry)
    for key, (name, entry) in inventory.items():
        for parent in name.parents:
            parent_key = unicodedata.normalize('NFC', parent.as_posix()).casefold()
            if parent_key in inventory and not inventory[parent_key][1].is_dir():
                raise ValueError('unsafe SideBackup IPA member: file parent conflict')
    return list(inventory.values())


def validate_backup(ipa, archive):
    if archive is None:
        raise ValueError('native SideBackup archive and dSYM are required')
    helper, binary = validate_archive(archive, 'SideBackup', 'com.SideStore.SideStore.SideBackup')
    if any(helper.rglob('*.appex')):
        raise ValueError('unreviewed SideBackup extension')
    validate_products(helper, side=True)
    with zipfile.ZipFile(ipa) as backup, tempfile.TemporaryDirectory(prefix='watch-sidebackup-') as directory:
        for name, entry in helper_zip_inventory(backup):
            destination = pathlib.Path(directory) / name
            if entry.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(backup.read(entry))  # read verifies CRC, but CRC alone is never sufficient.
        embedded = pathlib.Path(directory) / 'Payload/SideBackup.app'
        info = check_source(embedded, 'com.SideStore.SideStore.SideBackup', 'SideBackup')
        if any(embedded.rglob('*.appex')):
            raise ValueError('unreviewed embedded SideBackup extension')
        validate_products(embedded, side=True)
        if macho_info(embedded / info['CFBundleExecutable'], (2,))['uuid'] != binary['uuid'] or (embedded / 'SideBackup').read_bytes() != (helper / 'SideBackup').read_bytes():
            raise ValueError('embedded SideBackup differs from native archive executable/UUID')
        if read_info(helper) != info:
            raise ValueError('embedded SideBackup metadata differs from native archive')
        # Compare materialized trees, matching the copy semantics used during
        # assembly while never mutating authenticated native inputs.
        native = pathlib.Path(directory) / 'native/SideBackup.app'
        shutil.copytree(helper, native, symlinks=False)
        native_products = {p.relative_to(native): p for p in signing_inventory(native)}
        embedded_products = {p.relative_to(embedded): p for p in signing_inventory(embedded)}
        if native_products.keys() != embedded_products.keys():
            raise ValueError('embedded SideBackup code inventory differs from native archive')
        for relative, native_product in native_products.items():
            embedded_product = embedded_products[relative]
            if native_product.is_dir() != embedded_product.is_dir():
                raise ValueError('embedded SideBackup code product type differs from native archive')
            if native_product.is_dir():
                native_info = read_info(native_product)
                embedded_info = read_info(embedded_product)
                if native_info != embedded_info:
                    raise ValueError('embedded SideBackup bundle metadata differs from native archive')
                native_code = native_product / native_info['CFBundleExecutable']
                embedded_code = embedded_product / embedded_info['CFBundleExecutable']
            else:
                native_code, embedded_code = native_product, embedded_product
            if macho_info(native_code) != macho_info(embedded_code) or native_code.read_bytes() != embedded_code.read_bytes():
                raise ValueError('embedded SideBackup nested executable/UUID differs from native archive')
    return binary


def source_snapshot(root):
    return {p.relative_to(root).as_posix(): (str(p.readlink()) if p.is_symlink() else hashlib.sha256(p.read_bytes()).hexdigest())
            for p in root.rglob('*') if p.is_file() or p.is_symlink()}


def install_guest_config(embedded):
    config = plistlib.loads((ROOT / '.github/sidelc/LCAppInfo.plist').read_bytes())
    identity = str(uuid.UUID(config['LCDataUUID'])).upper()
    if identity != config['LCDataUUID'] or not any(c.get('folderName') == identity and c.get('isolateAppGroup') is False for c in config.get('LCContainers', [])):
        raise ValueError('invalid SideStore guest container identity')
    if any(config.get(k) is not True for k in ('dontInjectTweakLoader', 'dontLoadTweakLoader', 'dontSign')) or config.get('is32bit') is not False or config.get('doUseLCBundleId', False):
        raise ValueError('invalid SideStore guest injection/signing policy')
    loader = (ROOT / 'LiveContainer/LCBootstrap.m').read_text()
    if any(f'guestAppInfo[@"{key}"]' not in loader for key in ('LCDataUUID', 'dontInjectTweakLoader', 'dontLoadTweakLoader', 'is32bit')):
        raise ValueError('guest loader contract changed; review required')
    shutil.copy2(ROOT / '.github/sidelc/LCAppInfo.plist', embedded / 'LCAppInfo.plist')


def compatible_intent_resource(host, guest):
    ignored = {'INIntentDefinitionToolsVersion', 'INIntentDefinitionSystemVersion',
               'INIntentDefinitionToolsBuildVersion', 'INIntentHash'}
    def contract(value):
        if isinstance(value, dict):
            return {key: contract(child) for key, child in value.items() if key not in ignored}
        if isinstance(value, list):
            return [contract(child) for child in value]
        return value
    native_host, native_guest = (plistlib.loads(path.read_bytes()) for path in (host, guest))
    return bool(native_host.get('INIntents')) and contract(native_host) == contract(native_guest)


def assemble(host, side, output, inputs, revision, backup_archive=None):
    host, side, output = map(pathlib.Path, (host, side, output))
    if os.path.lexists(output):
        raise ValueError('refusing to overwrite package output')
    if output.resolve().is_relative_to(host.resolve()) or output.resolve().is_relative_to(side.resolve()):
        raise ValueError('output overlaps immutable input')
    output.parent.mkdir(parents=True, exist_ok=True)
    reservation = output.with_name('.' + output.name + '.reserved')
    reservation.mkdir()  # Exclusive reservation, including competing assemblers.
    stage = None
    try:
        # macOS temporary roots can spell /private/var as /var. Canonicalize
        # our newly owned staging directory, not the supplied native trees;
        # namespace_host_openssl still rejects symlink roots/ancestors/content.
        stage = pathlib.Path(tempfile.mkdtemp(prefix='.watch-package-', dir=output.parent)).resolve(strict=True)
        host_info = check_source(host, 'com.kdt.livecontainer', 'LiveContainer')
        side_info = check_source(side, 'com.SideStore.SideStore', 'SideStore')
        validate_products(host)
        validate_products(side, side=True)
        helper = validate_backup(side / 'SideBackup.ipa', backup_archive)
        if not (host / 'Frameworks/SideStoreSupport.framework').is_dir():
            raise ValueError('native host has no SideStoreSupport framework')
        before = {str(p): source_snapshot(p) for p in (host, side, pathlib.Path(backup_archive))}
        result = stage / 'Payload/LiveContainer.app'
        shutil.copytree(host, result, symlinks=False)
        namespace_proof = namespace_host_openssl(result)
        frameworks = result / 'Frameworks'
        embedded = frameworks / 'SideStoreApp.framework'
        if os.path.lexists(embedded):
            raise ValueError('host is already combined')
        shutil.copytree(side, embedded, symlinks=False)
        check_tree(result, allow_links=False)
        executable = embedded / side_info['CFBundleExecutable']
        native_uuid = macho_info(executable)['uuid']
        converted = executable.with_name(executable.name + '.watch-dylib')
        conversion = convert_executable(executable, converted)
        shutil.copymode(executable, converted)
        converted.replace(executable)
        if macho_info(executable, (6,))['uuid'] != native_uuid:
            raise ValueError('converter changed native UUID')
        side_frameworks = embedded / 'Frameworks'
        if side_frameworks.exists():
            for item in side_frameworks.iterdir():
                destination = frameworks / item.name
                if os.path.lexists(destination):
                    raise ValueError(f'framework collision requires ABI review: {item.name}')
                shutil.move(str(item), str(destination))
            side_frameworks.rmdir()
        plugins = result / 'PlugIns'
        plugins.mkdir(exist_ok=True)
        side_plugins = embedded / 'PlugIns'
        if not (side_plugins / 'AltWidgetExtension.appex').is_dir():
            raise ValueError('missing pinned native AltWidgetExtension')
        source = side_plugins / 'AltWidgetExtension.appex'
        destination = plugins / 'LiveWidgetExtension.appex'
        if os.path.lexists(destination):
            raise ValueError('extension collision')
        shutil.move(str(source), str(destination))
        widget = read_info(destination)
        (destination / 'AltWidgetExtension').rename(destination / 'LiveWidgetExtension')
        widget.update(CFBundleExecutable='LiveWidgetExtension', CFBundleName='LiveWidgetExtension', CFBundleIdentifier='com.kdt.livecontainer.LiveWidgetExtension')
        # Do NOT rename Swift/Objective-C module names or principal classes in
        # binary/resource metadata: the native executable is not recompiled.
        write_info(destination, widget)
        side_plugins.rmdir()
        install_guest_config(embedded)
        for name in ('Intents.intentdefinition', 'ViewApp.intentdefinition', 'Metadata.appintents'):
            source, destination = embedded / name, result / name
            if not source.exists():
                raise ValueError(f'missing native intent resource: {name}')
            if destination.exists():
                # The pinned host already compiles ViewApp. Its schema matches
                # SideStore except Xcode/editor fields and the generated hash;
                # retain the HOST bytes and the separate guest copy, not a blind
                # overwrite that loses the host's native resource registration.
                if name == 'ViewApp.intentdefinition' and compatible_intent_resource(destination, source):
                    continue
                raise ValueError(f'intent resource collision requires review: {name}')
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
        metadata = result / 'Metadata.appintents/extract.actionsdata'
        # Xcode emits JSON here; refusing unfamiliar encodings avoids corrupting
        # binary/plist length tables with blind byte replacement.
        actions = json.loads(metadata.read_text())
        def adapt(value):
            if isinstance(value, str):
                for intent in ('20RefreshAllAppsIntentV', '26RefreshAllAppsWidgetIntentV'):
                    value = value.replace('9SideStore' + intent, '16SideStoreSupport' + intent)
            elif isinstance(value, list):
                value = [adapt(v) for v in value]
            elif isinstance(value, dict):
                value = {k: adapt(v) for k, v in value.items()}
            return value
        metadata.write_text(json.dumps(adapt(actions), ensure_ascii=False, indent=2) + '\n')
        version, build = inputs['host']['version'], inputs['host']['build']
        backup_app = pathlib.Path(backup_archive) / 'Products/Applications/SideBackup.app'
        minimums = [value for value in (read_info(backup_app).get('MinimumOSVersion'), helper.get('minimum_os')) if value]
        for helper_framework in backup_app.rglob('*.framework'):
            helper_info = read_info(helper_framework)
            for value in (helper_info.get('MinimumOSVersion'), macho_info(helper_framework / helper_info['CFBundleExecutable'])['minimum_os']):
                if value:
                    minimums.append(value)
        for helper_dylib in backup_app.rglob('*.dylib'):
            value = macho_info(helper_dylib)['minimum_os']
            if value:
                minimums.append(value)
        for info in (host_info, side_info, *(read_info(p) for p in result.rglob('*') if p.is_dir() and p.suffix in ('.framework', '.appex'))):
            if 'MinimumOSVersion' in info:
                minimums.append(info['MinimumOSVersion'])
        for code in signing_inventory_after_conversion(result, embedded, side_info):
            minimum = macho_info(code)['minimum_os']
            if minimum:
                minimums.append(minimum)
        if minimums:
            host_info['MinimumOSVersion'] = max(minimums, key=lambda v: tuple(int(p) for p in v.split('.')))
        host_info.update(CFBundleShortVersionString=version, CFBundleVersion=build, CFBundleDisplayName='LiveContainer Watch', LCVersionInfo='watch-beta1')
        for key, value in side_info.items():
            if key.endswith('UsageDescription') and key not in host_info:
                host_info[key] = value
        for key in ('NSBonjourServices', 'INIntentsSupported', 'NSUserActivityTypes', 'ALTAppGroups'):
            extra = ['RefreshAllIntent', 'ViewAppIntent'] if key in ('INIntentsSupported', 'NSUserActivityTypes') else []
            host_info[key] = list(dict.fromkeys(host_info.get(key, []) + side_info.get(key, []) + extra))
        host_info['ALTAppGroups'] = list(dict.fromkeys(host_info['ALTAppGroups'] + ['group.com.SideStore.SideStore']))
        host_info['CFBundleURLTypes'] = host_info.get('CFBundleURLTypes', []) + side_info.get('CFBundleURLTypes', [])
        if 'NSAppTransportSecurity' in side_info:
            host_info['NSAppTransportSecurity'] = {**host_info.get('NSAppTransportSecurity', {}), **side_info['NSAppTransportSecurity']}
        write_info(result, host_info)
        side_info.update(CFBundlePackageType='FMWK', CFBundleIdentifier='com.kdt.livecontainer.SideStoreApp')
        write_info(embedded, side_info)
        for plugin in result.rglob('*.appex'):
            info = read_info(plugin)
            info.update(CFBundleShortVersionString=version, CFBundleVersion=build)
            write_info(plugin, info)
        for profile in result.rglob('embedded.mobileprovision'):
            profile.unlink()
        for signature in sorted(result.rglob('_CodeSignature'), key=lambda p: len(p.parts), reverse=True):
            shutil.rmtree(signature)
        signing_inventory(result)
        provenance = {'channel': 'watch-beta1', 'host_revision': revision, 'inputs': inputs,
                      'host_openssl_namespace': namespace_proof,
                      'native_uuids': {'host': macho_info(result / 'LiveContainer')['uuid'], 'sidestore': native_uuid, 'sidebackup': helper['uuid']},
                      'input_tree_sha256': {p: hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest() for p, s in before.items()},
                      'converted_sidestore_sha256_before_adhoc_signing': conversion['sha256'],
                      'physical_watch_acceptance': 'not tested; full resign/reinstall required for Watch renewal'}
        (result / 'LCWatchBuild.json').write_text(json.dumps(provenance, indent=2) + '\n')
        if any(source_snapshot(pathlib.Path(p)) != snapshot for p, snapshot in before.items()):
            raise ValueError('immutable native input changed during assembly')
        publish(stage, output)
        return output / 'Payload/LiveContainer.app'
    finally:
        if stage is not None and stage.exists():
            shutil.rmtree(stage)
        reservation.rmdir()


def signing_inventory_after_conversion(result, embedded, side_info):
    # The guest becomes a framework before its plist is updated below.
    for bundle in [result, *(p for p in result.rglob('*') if p.is_dir() and p.suffix in ('.framework', '.appex'))]:
        yield bundle / read_info(bundle)['CFBundleExecutable']
    yield from result.rglob('*.dylib')


def sign_tree(app, work):
    groups = ['group.com.SideStore.SideStore', 'group.com.kdt.livecontainer.shared']
    for index, code in enumerate(signing_inventory(app)):
        check_tree(app, allow_links=False)
        command = ['/usr/bin/codesign', '--force', '--sign', '-', '--generate-entitlement-der']
        if code.suffix in ('.app', '.appex'):
            identifier = read_info(code)['CFBundleIdentifier']
            entitlements = {'application-identifier': 'XYZ0123456.' + identifier,
                            'com.apple.developer.team-identifier': 'XYZ0123456',
                            'com.apple.security.application-groups': groups,
                            'keychain-access-groups': ['XYZ0123456.' + identifier, 'XYZ0123456.com.SideStore.SideStore'],
                            'get-task-allow': True}
            path = pathlib.Path(work) / f'code-{index}.entitlements.plist'
            path.write_bytes(plistlib.dumps(entitlements))
            command += ['--entitlements', str(path)]
        subprocess.run([*command, str(code)], check=True)
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', '--verbose=2', str(app)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host_app', type=pathlib.Path)
    parser.add_argument('sidestore_app', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    parser.add_argument('--backup-archive', type=pathlib.Path, required=True)
    parser.add_argument('--inputs', type=pathlib.Path, required=True)
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    try:
        result = assemble(args.host_app, args.sidestore_app, args.output, json.loads(args.inputs.read_text()), args.revision, args.backup_archive)
        print(json.dumps({'application': str(result)}))
    except (ValueError, OSError, zipfile.BadZipFile, KeyError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
