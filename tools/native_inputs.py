#!/usr/bin/env python3
"""Fail-closed native artifact ingestion and no-clobber publication."""
import argparse
import ctypes
import errno
import hashlib
import os
import pathlib
import re
import shutil
import sys
import tarfile
import tempfile

REQUIRED = {f'{name}.xcarchive.tar.gz' for name in ('LiveContainer', 'SideStore', 'SideBackup')} | {'provenance.txt', 'watch-inputs.json'}


def verify_manifest(root):
    root = pathlib.Path(root)
    entries = {}
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](?:\./)?([A-Za-z0-9_.-]+)', line)
        if not match or match[2] in entries or match[2] == 'SHA256SUMS':
            raise ValueError('invalid or duplicate checksum entry')
        entries[match[2]] = match[1].lower()
    if not REQUIRED <= entries.keys():
        raise ValueError('missing mandatory checksum coverage')
    for name, digest in entries.items():
        path = root / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f'checksum mismatch or unsafe native input: {name}')
    return entries


def safe_path(name, expected):
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != expected or '\\' in name:
        raise ValueError(f'unsafe archive path: {name}')
    return path.as_posix()


def extract_archive(source, destination, expected):
    destination = pathlib.Path(destination)
    # Validate the complete graph before writing anything. Never delegate extraction
    # to tar: a preceding link must not redirect a later file write.
    with tarfile.open(source, 'r:gz') as tar:
        members, links = {}, {}
        for member in tar.getmembers():
            name = safe_path(member.name, expected)
            if (name == expected and not member.isdir()) or name in members or not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
                raise ValueError('invalid archive root, duplicate or unsupported archive member')
            if member.mode & 0o6000:
                raise ValueError('privileged archive member')
            members[name] = member
            if member.issym() or member.islnk():
                target = pathlib.PurePosixPath(member.linkname)
                if target.is_absolute() or '\\' in member.linkname:
                    raise ValueError('absolute archive link')
                # Normalize .. without allowing escape from the expected archive root.
                parts = list(pathlib.PurePosixPath(name).parent.parts) if member.issym() else []
                for part in target.parts:
                    if part == '..':
                        if len(parts) <= 1:
                            raise ValueError('escaping archive link')
                        parts.pop()
                    elif part != '.':
                        parts.append(part)
                links[name] = safe_path('/'.join(parts), expected)
        for name in members:
            for parent in pathlib.PurePosixPath(name).parents:
                if parent.as_posix() in links or (parent.as_posix() in members and not members[parent.as_posix()].isdir()):
                    raise ValueError('archive member has non-directory parent')
        def resolve(name, seen=()):
            if name in seen or name not in members:
                raise ValueError('dangling or cyclic archive link')
            if name in links:
                return resolve(links[name], (*seen, name))
            return name
        for name in links:
            final = members[resolve(name)]
            if members[name].islnk() and not final.isfile():
                raise ValueError('hardlink must target a regular file')
        directories = {name for name, member in members.items() if member.isdir()}
        children = {}
        for name in members:
            for parent in pathlib.PurePosixPath(name).parents:
                if parent.parts:
                    directories.add(parent.as_posix())
            parent = pathlib.PurePosixPath(name).parent.as_posix()
            children.setdefault(parent, set()).add(name)
        # Include implied directory edges too. Directory links can cycle through
        # different sibling subtrees despite having individually valid targets.
        for name in directories:
            children.setdefault(pathlib.PurePosixPath(name).parent.as_posix(), set()).add(name)
        complete = set()
        def visit(name, ancestors=()):
            real = resolve(name) if name in links else name
            if real not in directories:
                return
            if real in ancestors:
                raise ValueError('recursive archive directory alias')
            if real not in complete:
                for child in children.get(real, ()):
                    visit(child, (*ancestors, real))
                complete.add(real)
        visit(expected)
        destination.parent.mkdir(parents=True, exist_ok=True)
        stage = pathlib.Path(tempfile.mkdtemp(prefix='.native-extract-', dir=destination.parent))
        try:
            for name, member in members.items():
                path = stage / name
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as stream, path.open('xb') as output:
                        shutil.copyfileobj(stream, output)
                    path.chmod(member.mode & 0o777)
            pending = set(links)
            while pending:
                progress = False
                for name in list(pending):
                    target = stage / resolve(name)
                    # A directory alias must wait until all links inside its target
                    # have been materialized to avoid silently losing resources.
                    if any(p.startswith(resolve(name) + '/') for p in pending):
                        continue
                    path = stage / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if target.is_dir():
                        shutil.copytree(target, path)
                    else:
                        shutil.copy2(target, path)
                    pending.remove(name)
                    progress = True
                if not progress:
                    raise ValueError('recursive directory alias')
            publish(stage, destination)
        finally:
            if stage.exists():
                shutil.rmtree(stage)


def publish(source, destination):
    """Atomic directory rename that cannot replace even an empty destination."""
    source, destination = map(pathlib.Path, (source, destination))
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        result = libc.renamex_np(os.fsencode(source), os.fsencode(destination), 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith('linux'):
        result = libc.renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1)  # RENAME_NOREPLACE
    else:
        raise OSError('atomic no-replace publication is unavailable')
    if result:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    ingest = commands.add_parser('ingest')
    ingest.add_argument('native', type=pathlib.Path)
    ingest.add_argument('destination', type=pathlib.Path)
    ingest.add_argument('revision')
    commit = commands.add_parser('publish')
    commit.add_argument('source', type=pathlib.Path)
    commit.add_argument('destination', type=pathlib.Path)
    args = parser.parse_args()
    if args.command == 'publish':
        publish(args.source, args.destination)
    else:
        if os.path.lexists(args.destination):
            raise ValueError('refusing existing ingest destination')
        args.destination.parent.mkdir(parents=True, exist_ok=True)
        stage = pathlib.Path(tempfile.mkdtemp(prefix='.native-ingest-', dir=args.destination.parent))
        try:
            snapshot = stage / 'native'
            snapshot.mkdir()
            for path in args.native.iterdir():
                if path.is_symlink() or not path.is_file() or not re.fullmatch(r'[A-Za-z0-9_.-]+', path.name):
                    raise ValueError('unsafe native artifact file')
                shutil.copy2(path, snapshot / path.name, follow_symlinks=False)
            entries = verify_manifest(snapshot)
            if set(p.name for p in snapshot.iterdir()) != set(entries) | {'SHA256SUMS'}:
                raise ValueError('missing native source/resource checksum coverage')
            if f'host_revision={args.revision}' not in (snapshot / 'provenance.txt').read_text().splitlines():
                raise ValueError('native host revision mismatch')
            # The authenticated snapshot is the only source ever consumed.
            for name in ('LiveContainer', 'SideStore', 'SideBackup'):
                extract_archive(snapshot / f'{name}.xcarchive.tar.gz', stage / name, f'{name}.xcarchive')
            publish(stage, args.destination)
        finally:
            if stage.exists():
                shutil.rmtree(stage)


if __name__ == '__main__':
    main()
