"""Namespace ONLY a caller-owned, private host staging tree, before guest copy.

This is not ABI substitution or global C-symbol isolation. The caller must discard
staging on failure, re-sign afterwards, and verify native imports/rpaths and device
bindings (ZSign uses RTLD_GLOBAL). No archive, guest, or signing operations here.
"""
import hashlib
import os
from pathlib import Path
import plistlib
import struct
import subprocess
from typing import NoReturn

OLD = '@rpath/OpenSSL.framework/OpenSSL'
NEW = '@rpath/LCOpenSSL.framework/LCOpenSSL'
IDENTIFIER = 'com.kdt.livecontainer.LCOpenSSL'
DEPENDENCIES = {0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20}
NAMES = DEPENDENCIES | {0xd, 0x8000001c}


class NamespaceError(ValueError):
    """Unsafe/unsupported layout, native patch failure, or failed readback."""


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _parse(data, path):
    def reject(message) -> NoReturn:
        raise NamespaceError(f'{path}: {message}')
    if len(data) < 32:
        reject('truncated Mach-O header')
    header = struct.unpack_from('<8I', data)
    magic, cpu, subtype, filetype, count, size, flags, reserved = header
    if magic != 0xfeedfacf or cpu != 0x100000c or subtype != 0 or filetype not in (2, 6, 8):
        reject('unsupported architecture/fat/file type')
    if reserved or count > size // 8 or size > len(data) - 32:
        reject('malformed load command bounds')
    records = []
    opaque = bytearray(data)
    uuids = []
    offset = 32
    for _ in range(count):
        if offset + 8 > 32 + size:
            reject('truncated command')
        cmd, length = struct.unpack_from('<II', data, offset)
        if length < 8 or length % 8 or offset + length > 32 + size:
            reject('malformed command size')
        raw = data[offset:offset + length]
        name = None
        versions = None
        if cmd in NAMES:
            minimum = 12 if cmd == 0x8000001c else 24
            if length < minimum:
                reject('truncated name command')
            start = struct.unpack_from('<I', raw, 8)[0]
            if start != minimum:
                reject('ambiguous name offset')
            tail = raw[start:]
            if b'\0' not in tail:
                reject('unterminated name')
            value, padding = tail.split(b'\0', 1)
            if not value or any(padding):
                reject('empty name or ambiguous trailing name bytes')
            try:
                name = value.decode('utf-8')
            except UnicodeDecodeError:
                reject('invalid name encoding')
            if 'OpenSSL.framework' in name and name not in (OLD, NEW):
                reject('unexpected OpenSSL.framework reference')
            opaque[offset + start:offset + length] = bytes(length - start)
            if cmd != 0x8000001c:
                versions = struct.unpack_from('<3I', raw, 12)
        if cmd == 0x1b:
            if length != 24:
                reject('malformed UUID')
            uuids.append(raw[8:].hex())
        records.append({'cmd': cmd, 'name': name, 'versions': versions, 'raw': raw})
        offset += length
    if offset != 32 + size:
        reject('load command count/size mismatch')
    if b'OpenSSL.framework' in opaque:
        reject('unreviewed OpenSSL.framework reference outside load names')
    if len(uuids) != 1:
        reject('missing or duplicate UUID')
    ids = [r for r in records if r['cmd'] == 0xd]
    if len(ids) > 1 or (ids and filetype != 6):
        reject('duplicate or invalid dylib ID')
    deps = [r['name'] for r in records if r['cmd'] in DEPENDENCIES]
    if len(deps) != len(set(deps)):
        reject('duplicate dependency ambiguity')
    if any(r['name'] in (OLD, NEW) for r in records) and (not flags & 0x80 or flags & 0x100):
        reject('OpenSSL image requires MH_TWOLEVEL without MH_FORCE_FLAT')
    return {'header': header, 'records': records, 'uuid': uuids[0], 'sha256': _digest(data)}


def _evidence(parsed):
    return {'sha256': parsed['sha256'], 'uuid': parsed['uuid'],
            'header': list(parsed['header']),
            'commands': [{'cmd': r['cmd'], 'name': r['name'],
                          'versions': list(r['versions']) if r['versions'] else None,
                          'sha256': _digest(r['raw'])} for r in parsed['records']]}


def namespace_host_openssl(host_copy, *, runner=None):
    """Mutate host_copy only; return JSON-serializable before/after evidence.

    runner has subprocess.run's (argv, check=True) contract. Success alone is
    insufficient: every command is parsed again and compared in ordinal order.
    Failure can leave staging partly changed; the caller MUST discard that tree.
    """
    runner = subprocess.run if runner is None else runner
    root = Path(host_copy)
    source = root / 'Frameworks/OpenSSL.framework'
    destination = root / 'Frameworks/LCOpenSSL.framework'
    if not root.is_dir() or root.is_symlink() or any(p.is_symlink() for p in root.parents):
        raise NamespaceError('host staging root must be a real private directory')
    if os.path.lexists(destination):
        raise NamespaceError('conflicting LCOpenSSL destination')
    images = {}
    snapshots = {}
    magics = {bytes.fromhex(s) for s in ('cffaedfe', 'feedfacf', 'cefaedfe', 'feedface', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca')}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise NamespaceError(f'symlink in private staging tree: {path}')
        if not path.is_file():
            continue
        if path.stat().st_nlink != 1:
            raise NamespaceError(f'hardlinked staging file: {path}')
        data = path.read_bytes()
        snapshots[path] = (data, path.stat().st_mode)
        if data[:4] in magics or path.suffix == '.dylib':
            images[path] = _parse(data, path)
            for record in images[path]['records']:
                if record['name'] == NEW:
                    raise NamespaceError('preexisting LCOpenSSL load reference')
                if record['name'] == OLD and (record['cmd'] == 0x8000001c or (record['cmd'] == 0xd and path != source / 'OpenSSL')):
                    raise NamespaceError('unexpected OpenSSL ID/rpath ownership')
    for path, (data, _) in snapshots.items():
        if path.name != 'Info.plist':
            continue
        try:
            info = plistlib.loads(data)
        except (ValueError, plistlib.InvalidFileException) as error:
            raise NamespaceError(f'malformed bundle metadata: {path}') from error
        if not isinstance(info, dict):
            raise NamespaceError(f'bundle metadata is not a dictionary: {path}')
        if info.get('CFBundleIdentifier') == IDENTIFIER:
            raise NamespaceError(f'namespace identifier collision: {path}')
        name = info.get('CFBundleExecutable')
        if name is not None:
            if not isinstance(name, str) or not name or Path(name).name != name or name in ('.', '..'):
                raise NamespaceError(f'unsafe bundle executable: {path}')
            if path.parent / name not in images:
                raise NamespaceError(f'missing/unsupported bundle executable: {path}')
    if not source.exists():
        if any(r['name'] == OLD for p in images.values() for r in p['records']):
            raise NamespaceError('OpenSSL references without host framework')
        return {'mapping': {}, 'images': []}
    if os.path.lexists(destination):
        raise NamespaceError('conflicting LCOpenSSL destination')
    executable = source / 'OpenSSL'
    if os.path.lexists(source / 'LCOpenSSL'):
        raise NamespaceError('conflicting LCOpenSSL executable destination')
    metadata_path = source / 'Info.plist'
    metadata_bytes = metadata_path.read_bytes()
    metadata = plistlib.loads(metadata_bytes)
    if (metadata.get('CFBundleExecutable') != 'OpenSSL' or metadata.get('CFBundleName') != 'OpenSSL'
            or metadata.get('CFBundleIdentifier') != 'com.github.krzyzanowskim.OpenSSL'
            or metadata.get('CFBundlePackageType') != 'FMWK'):
        raise NamespaceError('unexpected host OpenSSL metadata')
    original = images.get(executable)
    if original is None or original['header'][3] != 6 or [r['name'] for r in original['records'] if r['cmd'] == 0xd] != [OLD]:
        raise NamespaceError('host OpenSSL must be arm64 MH_DYLIB with expected ID')
    source.rename(destination)
    (destination / 'OpenSSL').rename(destination / 'LCOpenSSL')
    metadata.update(CFBundleExecutable='LCOpenSSL', CFBundleName='LCOpenSSL', CFBundleIdentifier=IDENTIFIER)
    if 'CFBundleDisplayName' in metadata:
        metadata['CFBundleDisplayName'] = 'LCOpenSSL'
    renamed_metadata = destination / 'Info.plist'
    renamed_metadata.write_bytes(plistlib.dumps(metadata, fmt=plistlib.FMT_BINARY if metadata_bytes.startswith(b'bplist') else plistlib.FMT_XML))
    report = {'mapping': {OLD: NEW}, 'images': [], 'native_commands': [], 'metadata': {'before_sha256': _digest(metadata_bytes)}}
    translated = {}
    for oldpath, before in images.items():
        path = destination / oldpath.relative_to(source) if oldpath.is_relative_to(source) else oldpath
        if oldpath == executable:
            path = destination / 'LCOpenSSL'
        translated[oldpath] = path
        try:
            if oldpath == executable:
                args = ['/usr/bin/install_name_tool', '-id', NEW, str(path)]
                report['native_commands'].append(args)
                runner(args, check=True)
            if any(r['cmd'] in DEPENDENCIES and r['name'] == OLD for r in before['records']):
                args = ['/usr/bin/install_name_tool', '-change', OLD, NEW, str(path)]
                report['native_commands'].append(args)
                runner(args, check=True)
        except (OSError, subprocess.SubprocessError) as error:
            raise NamespaceError(f'native install_name_tool failed: {path}') from error

    # Read back the entire inventory only AFTER all native subprocesses finish.
    for oldpath, before in images.items():
        path = translated[oldpath]
        after = _parse(path.read_bytes(), path)
        original_data, mode = snapshots[oldpath]
        updated_data = path.read_bytes()
        boundary = 32 + max(before['header'][5], after['header'][5])
        if (original_data[boundary:] != updated_data[boundary:]
                or any(original_data[32 + before['header'][5]:boundary])):
            raise NamespaceError(f'native readback payload/header padding changed: {path}')
        # sizeofcmds alone may grow; architecture, flags, UUID and ordinal order may not.
        if before['header'][:5] + before['header'][6:] != after['header'][:5] + after['header'][6:]:
            raise NamespaceError(f'native readback header changed: {path}')
        for previous, current in zip(before['records'], after['records']):
            expected = NEW if previous['name'] == OLD else previous['name']
            if previous['cmd'] != current['cmd'] or current['name'] != expected or previous['versions'] != current['versions']:
                raise NamespaceError(f'native readback commands mismatch: {path}')
            if previous['name'] is None and previous['raw'] != current['raw']:
                raise NamespaceError(f'native readback unrelated command changed: {path}')
        report['images'].append({'before_path': str(oldpath.relative_to(root)), 'path': str(path.relative_to(root)),
                                 'before': _evidence(before), 'after': _evidence(after)})
    if plistlib.loads(renamed_metadata.read_bytes()) != metadata:
        raise NamespaceError('namespace metadata readback mismatch')
    for oldpath, (data, mode) in snapshots.items():
        path = translated.get(oldpath, destination / oldpath.relative_to(source) if oldpath.is_relative_to(source) else oldpath)
        if path.is_symlink() or path.stat().st_mode != mode:
            raise NamespaceError(f'staging file mode changed: {path}')
        if oldpath not in images and oldpath != metadata_path and path.read_bytes() != data:
            raise NamespaceError(f'staging resource changed: {path}')
    report['metadata']['after_sha256'] = _digest(renamed_metadata.read_bytes())
    return report
