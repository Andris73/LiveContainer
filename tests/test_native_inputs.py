import hashlib
import importlib.util
import io
import pathlib
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))


def api():
    spec = importlib.util.spec_from_file_location('native_inputs', ROOT / 'tools/native_inputs.py')
    if not pathlib.Path(spec.origin).is_file():
        raise AssertionError('safe native input validator is missing')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive(path, entries):
    with tarfile.open(path, 'w:gz') as tar:
        for name, kind, value in entries:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            if kind == tarfile.REGTYPE:
                entry.size = len(value)
                tar.addfile(entry, io.BytesIO(value))
            else:
                entry.linkname = value
                tar.addfile(entry)


class NativeInputsTests(unittest.TestCase):
    def test_ingest_snapshots_authenticated_sources_and_cleans_all_failures(self):
        import subprocess
        module = api()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            native = root / 'native'
            native.mkdir()
            for name in ('LiveContainer', 'SideStore', 'SideBackup'):
                archive(native / f'{name}.xcarchive.tar.gz', [(f'{name}.xcarchive/data', tarfile.REGTYPE, name.encode())])
            (native / 'provenance.txt').write_text('host_revision=' + 'f' * 40 + '\n')
            (native / 'watch-inputs.json').write_text('{}')
            (native / 'SideStore.source.tar').write_bytes(b'original source/licensing artifact')
            def sums():
                files = sorted(p for p in native.iterdir() if p.name != 'SHA256SUMS')
                (native / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ./' + p.name + '\n' for p in files))
            sums()
            destination = root / 'ingested'
            result = subprocess.run([sys.executable, str(ROOT / 'tools/native_inputs.py'), 'ingest', str(native), str(destination), 'f' * 40], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((destination / 'native/SideStore.source.tar').is_file(), 'authenticated native snapshot/source preservation missing')
            self.assertEqual((destination / 'native/SideStore.source.tar').read_bytes(), (native / 'SideStore.source.tar').read_bytes(), 'native snapshot/source preservation missing')
            __import__('shutil').rmtree(destination)
            archive(native / 'SideStore.xcarchive.tar.gz', [('evil', tarfile.REGTYPE, b'bad')])
            sums()
            result = subprocess.run([sys.executable, str(ROOT / 'tools/native_inputs.py'), 'ingest', str(native), str(destination), 'f' * 40], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(destination.exists(), 'failed ingest left partial staging')
            self.assertFalse(list(root.glob('.native-ingest-*')))

    def test_script_gates_ingestion_archives_signing_and_publication(self):
        text = (ROOT / '.github/package-watch.sh').read_text()
        for required in ('native_inputs.py', 'ingest', '--backup-archive', 'validate_archive', 'sign_tree', 'publish', 'unzip -t', 'reserved', 'source.tar'):
            self.assertIn(required, text)
        self.assertNotIn('tar -xzf', text)
        self.assertNotIn('mkdir -p "$output"', text)
        self.assertNotIn('find "$app/Frameworks"', text)

    def test_publish_never_clobbers_racing_existing_or_dangling_destination(self):
        module = api()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for kind in ('directory', 'dangling'):
                source, destination = root / 'stage', root / 'output'
                source.mkdir()
                (source / 'complete').write_text('complete verified artifact')
                if kind == 'directory':
                    destination.mkdir()
                else:
                    destination.symlink_to('absent')
                with self.assertRaises(FileExistsError):
                    module.publish(source, destination)
                self.assertTrue((source / 'complete').exists())
                if destination.is_symlink():
                    destination.unlink()
                else:
                    destination.rmdir()
                module.publish(source, destination)
                self.assertEqual((destination / 'complete').read_text(), 'complete verified artifact')
                __import__('shutil').rmtree(destination)

    def test_checksum_coverage_is_required_not_only_listed_entries(self):
        module = api()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'provenance.txt').write_bytes(b'revision')
            (root / 'SHA256SUMS').write_text(hashlib.sha256(b'revision').hexdigest() + '  ./provenance.txt\n')
            with self.assertRaisesRegex(ValueError, 'coverage'):
                module.verify_manifest(root)

    def test_preflights_all_tar_paths_types_and_link_targets(self):
        module = api()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            cases = [('Other.xcarchive/x', tarfile.REGTYPE, b'x'),
                     ('LiveContainer.xcarchive/../../evil', tarfile.REGTYPE, b'x'),
                     ('LiveContainer.xcarchive/x', tarfile.SYMTYPE, '/etc/passwd'),
                     ('LiveContainer.xcarchive/x', tarfile.SYMTYPE, '../../outside'),
                     ('LiveContainer.xcarchive/x', tarfile.LNKTYPE, '../outside'),
                     ('LiveContainer.xcarchive/x', tarfile.FIFOTYPE, ''),
                     ('LiveContainer.xcarchive/x', tarfile.SYMTYPE, 'missing'),
                     ('LiveContainer.xcarchive', tarfile.REGTYPE, b'not a root directory'),
                     ('LiveContainer.xcarchive', tarfile.SYMTYPE, 'data')]
            for index, entry in enumerate(cases):
                with self.subTest(entry=entry):
                    archive(root / 'input.tar.gz', [entry])
                    destination = root / f'stage-{index}'
                    with self.assertRaises(ValueError):
                        module.extract_archive(root / 'input.tar.gz', destination, 'LiveContainer.xcarchive')
                    self.assertFalse(destination.exists())

    def test_recursive_directory_alias_graph_is_rejected_before_staging(self):
        module = api()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive(root / 'input.tar.gz', [('root', tarfile.DIRTYPE, ''),
                    ('root/a', tarfile.DIRTYPE, ''), ('root/b', tarfile.DIRTYPE, ''),
                    ('root/a/link', tarfile.SYMTYPE, '../b'), ('root/b/link', tarfile.SYMTYPE, '../a')])
            destination = root / 'never-created-parent' / 'stage'
            with self.assertRaises(ValueError):
                module.extract_archive(root / 'input.tar.gz', destination, 'root')
            self.assertFalse(destination.parent.exists(), 'recursive links must fail during preflight, before any writes')

    def test_safe_tar_links_materialize_and_duplicates_fail(self):
        module = api()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive(root / 'input.tar.gz', [('LiveContainer.xcarchive/data', tarfile.REGTYPE, b'payload'),
                                          ('LiveContainer.xcarchive/link', tarfile.SYMTYPE, 'data')])
            module.extract_archive(root / 'input.tar.gz', root / 'stage', 'LiveContainer.xcarchive')
            link = root / 'stage/LiveContainer.xcarchive/link'
            self.assertEqual(link.read_bytes(), b'payload')
            self.assertFalse(link.is_symlink())
            archive(root / 'bad.tar.gz', [('LiveContainer.xcarchive/data', tarfile.REGTYPE, b'a'),
                                        ('LiveContainer.xcarchive/data', tarfile.REGTYPE, b'b')])
            with self.assertRaises(ValueError):
                module.extract_archive(root / 'bad.tar.gz', root / 'bad-stage', 'LiveContainer.xcarchive')


if __name__ == '__main__':
    unittest.main()
