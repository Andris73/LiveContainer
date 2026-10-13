"""Static contracts for the native-only Watch beta CI (no Apple SDK required)."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WatchCI(unittest.TestCase):
    def test_native_workflow_has_no_publication_path(self):
        text = (ROOT / '.github/workflows/build.yml').read_text()
        self.assertIn('runs-on: macos-15', text)
        self.assertIn('contents: read', text)
        self.assertIn('bash .github/build-watch.sh', text)
        for forbidden in ('contents: write', 'release__nightly', 'action-gh-release',
                          'nightly-release', 'build_github.sh', 'ALTSTORE_TOKEN', 'dylibify'):
            self.assertNotIn(forbidden, text)
        actions = re.findall(r'uses:\s*([^\s]+)', text)
        self.assertTrue(actions)
        for action in actions:
            self.assertRegex(action, r'^[\w.-]+/[\w.-]+@[0-9a-f]{40}$')
        self.assertIn('if-no-files-found: error', text)
        self.assertIn('native-watch-beta', text)
        self.assertIn('timeout-minutes:', text)

    def test_manifest_pins_sources_and_numeric_beta_version(self):
        path = ROOT / '.github/watch-inputs.json'
        self.assertTrue(path.is_file(), 'missing native source manifest')
        data = json.loads(path.read_text())
        self.assertEqual(data['host']['base_revision'], '4dbe0f9a626de801184a42c0be8d2cb105058e3d')
        self.assertEqual(data['host']['branch'], 'watch-combined')
        self.assertEqual(data['host']['version'], '3.8.11')
        self.assertEqual(data['host']['build'], '381101')
        self.assertEqual(data['channel'], 'beta')
        self.assertEqual(data['sidestore']['revision'], 'a86f42b1d6d4eb57da0e48a1ce214191ba424f3c')
        self.assertEqual(data['minimuxer']['revision'], '2a20ddafdeb96ece8176d4600d8719360e27d8b2')
        self.assertEqual(data['minimuxer']['repository'], 'https://github.com/Andris73/minimuxer.git')
        self.assertEqual(data['sidesign']['revision'], 'e580ddc3a0e69699b570aba63bf614b1a2d532bc')
        self.assertEqual(data['openssl']['revision'], '623c84da314e85363236507ca38a4bde65df21c3')
        self.assertEqual(data['litehook']['revision'], 'a7e9f599d7f0b3d77008ad62bf10cb10dab6eca9')
        self.assertEqual(data['xcode']['developer_dir'], '/Applications/Xcode_26.2.app/Contents/Developer')
        self.assertEqual(data['xcode']['build'], '17C52')
        self.assertEqual(data['rust']['target'], 'aarch64-apple-ios')
        self.assertRegex(data['rust']['version'], r'^\d+\.\d+\.\d+$')
        for key in ('sidestore', 'minimuxer', 'sidesign', 'openssl', 'litehook', 'idevice'):
            self.assertRegex(data[key]['revision'], r'^[0-9a-f]{40}$')
        self.assertRegex(data['openssl']['source_sha256'], r'^[0-9a-f]{64}$')
        modules = (ROOT / '.gitmodules').read_text()
        self.assertIn('https://github.com/LiveContainerMirror/litehook', modules)

    def test_script_archives_native_sources_fail_closed(self):
        path = ROOT / '.github/build-watch.sh'
        self.assertTrue(path.is_file(), 'missing native build entrypoint')
        text = path.read_text()
        for required in ('set -euo pipefail', 'Darwin', 'git merge-base --is-ancestor',
                         'git submodule update --init --recursive', 'checkout --detach',
                         'CODE_SIGNING_ALLOWED=NO', 'CODE_SIGNING_REQUIRED=NO',
                         'CODE_SIGN_IDENTITY=', 'DEBUG_INFORMATION_FORMAT=dwarf-with-dsym',
                         'generic/platform=iOS', 'make build', 'BUILD_CONFIG=Release',
                         '-onlyUsePackageVersionsFromResolvedFile', '-disableAutomaticPackageResolution',
                         'aarch64-apple-ios', '--locked', 'companion_proxy_get_device_registry',
                         'SideBackup.ipa', 'dSYMs', 'tar', 'build_openssl.sh',
                         '--fail', '--connect-timeout', '--max-time', 'source_sha256'):
            self.assertIn(required, text)
        for forbidden in ('dylibify', 'build_github.sh', 'make submodules',
                          'git commit', 'git push', 'gh release', 'security find-identity',
                          'aarch64-apple-ios-sim', 'curl |'):
            self.assertNotIn(forbidden, text)
        self.assertNotIn('git apply', text)
        self.assertRegex(text, r'git(?: -C "[^"\n]+")? diff --exit-code')
        self.assertIn('host_archive=', text)
        self.assertIn('sidestore_archive=', text)

    def test_readme_records_unverified_runtime_and_source_restrictions(self):
        path = ROOT / 'README-WATCH.md'
        self.assertTrue(path.is_file(), 'missing Watch build handoff')
        text = path.read_text()
        for required in ('beta', 'not proven', 'SideStore', 'AGENTS', 'unmodified',
                         'dSYMs', '381101', '3.8.11', 'checksum', 'Rust',
                         'build_openssl.sh', 'temporary', 'packaging', 'release'):
            self.assertIn(required, text)

    def test_rust_sdk_environment_does_not_leak_into_either_app_archive(self):
        text = (ROOT / '.github/build-watch.sh').read_text()
        # Execute the real Rust-to-app transition, stubbing only native build tools.
        transition = text[text.index('export SDKROOT=', text.index('rustup target add')):
                          text.index('# SideStore README/AGENTS restrictions:')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            setup = r'''
set -euo pipefail
work="$1"; logs="$work"; ss="$work"; idevice="$work"
rust_version=1.0; rust_target=aarch64-apple-ios
value() { printf 'test'; }
fail() { printf '%s\n' "$*" >&2; exit 1; }
xcrun() {
    if [[ "$1" == nm ]]; then
        printf ' _companion_proxy_connect\n _companion_proxy_get_device_registry\n _companion_proxy_start_forwarding_service_port\n'
    else
        printf '/rust-only-sdk\n'
    fi
}
cargo() {
    [[ "$SDKROOT" == /rust-only-sdk && "$BINDGEN_EXTRA_CLANG_ARGS" == --sysroot=/rust-only-sdk && "$IPHONEOS_DEPLOYMENT_TARGET" == 17.0 ]]
    mkdir -p "$idevice/target/$rust_target/release"
    printf 'compiled' > "$idevice/target/$rust_target/release/libidevice_ffi.a"
}
record_environment() {
    printf '%s|%s|%s|%s\n' "$1" "${SDKROOT+set}" "${BINDGEN_EXTRA_CLANG_ARGS+set}" "${IPHONEOS_DEPLOYMENT_TARGET+set}" >> "$work/archive-environments"
}
xcodebuild() { record_environment host; }
make() { record_environment sidestore; }
'''
            result = subprocess.run(['bash', '-c', setup + transition, 'test', str(path)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((path / 'archive-environments').read_text().splitlines(),
                             ['host|||', 'sidestore|||'],
                             'Rust-only SDK/deployment variables leaked into an app archive')

    def test_native_archives_require_matching_device_dsyms(self):
        text = (ROOT / '.github/build-watch.sh').read_text()
        self.assertIn('dwarfdump', text)
        self.assertIn("dSYMs/{app.name}.dSYM", text)
        self.assertIn("CFBundleExecutable", text)
        self.assertIn(r'\(arm64\)', text)
        self.assertIn('UUID mismatch', text)


    def test_native_archive_duplicate_helper_is_verified_before_normalization(self):
        text = (ROOT / '.github/build-watch.sh').read_text()
        code = text.split("<<'ARCHIVES'\n", 1)[1].split('\nARCHIVES', 1)[0]
        # Run the actual archive gate; stub dwarfdump, not filesystem validation.
        for case in ('matching', 'different', 'unknown', 'root-mode', 'file-mode', 'empty-directory', 'missing', 'symlink'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                import plistlib
                root = Path(directory)
                archives = [root / (name + '.xcarchive') for name in ('LiveContainer', 'SideStore', 'SideBackup')]
                for archive, name in zip(archives, ('LiveContainer', 'SideStore', 'SideBackup')):
                    app = archive / 'Products/Applications' / (name + '.app')
                    app.mkdir(parents=True)
                    (app / name).write_bytes(b'native-code')
                    (app / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable': name}))
                    (archive / 'dSYMs' / (name + '.app.dSYM')).mkdir(parents=True)
                import shutil
                duplicate = archives[1] / 'Products/Applications/SideBackup.app'
                shutil.copytree(archives[2] / 'Products/Applications/SideBackup.app', duplicate)
                if case == 'different':
                    (duplicate / 'SideBackup').write_bytes(b'not-the-native-helper')
                if case == 'unknown':
                    (archives[1] / 'Products/Applications/Unexpected.app').mkdir()
                if case == 'root-mode':
                    duplicate.chmod(0o700)
                    (archives[2] / 'Products/Applications/SideBackup.app').chmod(0o755)
                if case == 'file-mode':
                    (duplicate / 'SideBackup').chmod(0o700)
                if case == 'empty-directory':
                    (duplicate / 'extra').mkdir()
                if case == 'missing':
                    (duplicate / 'SideBackup').unlink()
                if case == 'symlink':
                    (duplicate / 'SideBackup').unlink()
                    (duplicate / 'SideBackup').symlink_to('Info.plist')
                prefix = "import subprocess\nsubprocess.check_output = lambda *a, **k: 'UUID: 11111111-1111-1111-1111-111111111111 (arm64)'\n"
                result = subprocess.run(['python3', '-c', prefix + code, *map(str, archives)], capture_output=True, text=True)
                if case == 'matching':
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(duplicate.exists())
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(duplicate.exists(), 'failure must leave archive untouched')

    def test_generic_ios_destination_has_no_duplicate_arch_argument(self):
        text = (ROOT / '.github/build-watch.sh').read_text()
        host = text.split('xcodebuild archive -project LiveContainer.xcodeproj', 1)[1].split('tee "$logs/livecontainer.log"', 1)[0]
        side = text.split('COMMON_BUILD_SETTINGS=', 1)[1].split('\n', 1)[0]
        for command in (host, side):
            self.assertNotIn('-arch arm64', command)
            self.assertIn('ARCHS=arm64', command)
            self.assertIn('-destination', command)


    def test_openssl_native_archives_replace_template_at_xcframework_boundary(self):
        # Execute the generated helper; only unavailable Apple/build tools are stubbed.
        # Markers represent lineage, NOT Mach-O binaries or a successful native build.
        import hashlib
        import os
        import plistlib
        import sys
        import tarfile
        text = (ROOT / '.github/build-watch.sh').read_text()
        helper = text.split("<<'OPENSSL_SCRIPT'\n", 1)[1].split('\nOPENSSL_SCRIPT', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / 'vendor'
            template = vendor / 'Frameworks/iphoneos/OpenSSL.framework'
            template.mkdir(parents=True)
            (template / 'OpenSSL').write_bytes(b'PREBUILT-TEMPLATE')
            (template / 'Info.plist').write_bytes(plistlib.dumps({
                'CFBundleExecutable': 'OpenSSL', 'MinimumOSVersion': '12.0'}))
            for name in ('_CodeSignature/CodeResources', 'CodeResources',
                         'Modules/module.modulemap', 'Headers/shim.h', 'LICENSE'):
                path = template / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('template metadata: ' + name)
            source = root / 'source'
            (source / 'include/openssl').mkdir(parents=True)
            (source / 'include/openssl/ssl.h').write_text('#include <openssl/crypto.h>\n')
            (source / 'include/openssl/crypto.h').write_text('/* fresh crypto header */\n')
            configure = source / 'Configure'
            configure.write_text('#!/bin/sh\nexec python3 -c '\
                                 + "'import json,os,sys; json.dump(dict(args=sys.argv[1:], sdk=os.environ.get(\"SDKROOT\"), deployment=os.environ.get(\"IPHONEOS_DEPLOYMENT_TARGET\")),open(\"configuration.json\",\"w\"))' \"$@\"\n")
            configure.chmod(0o755)
            archive = root / 'source.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                tar.add(source, arcname='openssl-source')
            tools = root / 'tools'
            tools.mkdir()
            stub = tools / 'stub'
            stub.write_text('#!' + sys.executable + '\n' + r'''
import json, os, pathlib, plistlib, shutil, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
log = pathlib.Path(os.environ['HARNESS_LOG'])
with log.open('a') as f:
    f.write(json.dumps({'tool': name, 'args': args}) + '\n')
if name == 'curl':
    shutil.copyfile(os.environ['HARNESS_ARCHIVE'], args[args.index('-o') + 1])
elif name == 'sysctl':
    print('2')
elif name == 'ditto':
    shutil.copytree(args[0], args[1], dirs_exist_ok=True)
elif name == 'make':
    src = pathlib.Path.cwd()
    configuration = json.loads((src / 'configuration.json').read_text())
    if 'build_libs' in args:
        for library in ('libssl.a', 'libcrypto.a'):
            (src / library).write_text('FRESH:' + library)
    elif 'install_dev' in args:
        prefix = pathlib.Path(next(a.split('=', 1)[1] for a in configuration['args'] if a.startswith('--prefix=')))
        (prefix / 'lib').mkdir(parents=True)
        for library in ('libssl.a', 'libcrypto.a'):
            shutil.copyfile(src / library, prefix / 'lib' / library)
        shutil.copytree(src / 'include', prefix / 'include')
    else:
        raise SystemExit('unexpected make target')
elif name == 'clang':
    libraries = [pathlib.Path(a) for a in args if a.endswith('.a')]
    assert [p.name for p in libraries] == ['libssl.a', 'libcrypto.a']
    assert all(p.read_text() == 'FRESH:' + p.name for p in libraries)
    output = pathlib.Path(args[args.index('-o') + 1])
    output.write_bytes(b'SOURCE-LINKED:' + b'|'.join(p.read_bytes() for p in libraries))
elif name == 'xcrun':
    if '--show-sdk-path' in args:
        print('/fixture/iPhoneOS.sdk')
    elif '--find' in args:
        print(pathlib.Path(sys.argv[0]).parent / 'clang')
    elif args[0] == 'dsymutil':
        assert pathlib.Path(args[1]).read_bytes().startswith(b'SOURCE-LINKED:')
        pathlib.Path(args[args.index('-o') + 1]).mkdir()
    else:
        raise SystemExit('unexpected xcrun operation')
elif name == 'xcodebuild':
    assert args[0] == '-create-xcframework'
    framework = pathlib.Path(args[args.index('-framework') + 1])
    assert (framework / 'OpenSSL').read_bytes().startswith(b'SOURCE-LINKED:')
    output = pathlib.Path(args[args.index('-output') + 1])
    shutil.copytree(framework, output / 'ios-arm64/OpenSSL.framework')
else:
    raise SystemExit('unexpected tool: ' + name)
''')
            stub.chmod(0o755)
            for name in ('curl', 'sysctl', 'ditto', 'make', 'clang', 'xcrun', 'xcodebuild'):
                (tools / name).symlink_to(stub.name)
            log = root / 'commands.jsonl'
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                       HARNESS_LOG=str(log), HARNESS_ARCHIVE=str(archive))
            build = root / 'build'
            result = subprocess.run(['bash', '-c', helper, 'helper', str(vendor),
                                     str(build), 'https://fixture.invalid/pinned-source',
                                     hashlib.sha256(archive.read_bytes()).hexdigest()],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            configuration = json.loads((build / 'src/configuration.json').read_text())
            self.assertEqual(configuration['deployment'], '17.0', 'OpenSSL must target actual iOS 17')
            self.assertIn('-miphoneos-version-min=17.0', configuration['args'])
            self.assertEqual(configuration['sdk'], '/fixture/iPhoneOS.sdk')
            commands = [json.loads(line) for line in log.read_text().splitlines()]
            link = next(c['args'] for c in commands if c['tool'] == 'clang')
            for flag in ('-dynamiclib', '-arch', 'arm64', '-isysroot', '/fixture/iPhoneOS.sdk',
                         '-miphoneos-version-min=17.0', '-Wl,-all_load',
                         '-Wl,-headerpad_max_install_names', '-Wl,-no_adhoc_codesign', '-lSystem'):
                self.assertIn(flag, link)
            self.assertEqual(link[link.index('-install_name') + 1], '@rpath/OpenSSL.framework/OpenSSL')
            self.assertEqual([a for a in link if a.endswith('.a')],
                             [str(build / 'install/lib' / name) for name in ('libssl.a', 'libcrypto.a')])
            self.assertLess(next(i for i, c in enumerate(commands) if c['tool'] == 'make' and 'install_dev' in c['args']),
                            next(i for i, c in enumerate(commands) if c['tool'] == 'clang'))
            expected = b'SOURCE-LINKED:FRESH:libssl.a|FRESH:libcrypto.a'
            for framework in (build / 'frameworks/OpenSSL.framework', template,
                              vendor / 'Frameworks/OpenSSL.xcframework/ios-arm64/OpenSSL.framework'):
                self.assertEqual((framework / 'OpenSSL').read_bytes(), expected)
                self.assertEqual(plistlib.loads((framework / 'Info.plist').read_bytes())['MinimumOSVersion'], '17.0')
                self.assertFalse((framework / '_CodeSignature').exists())
                self.assertFalse((framework / 'CodeResources').exists())
                for name in ('Modules/module.modulemap', 'Headers/shim.h', 'LICENSE'):
                    self.assertEqual((framework / name).read_text(), 'template metadata: ' + name)
                self.assertEqual((framework / 'Headers/ssl.h').read_text(), '#include <OpenSSL/crypto.h>\n')

    def test_source_built_openssl_does_not_expect_the_original_vendor_certificate(self):
        text = (ROOT / 'LiveContainer.xcodeproj/project.pbxproj').read_text()
        reference = next(line for line in text.splitlines() if 'OpenSSL.xcframework */ = {isa = PBXFileReference' in line)
        self.assertNotIn('expectedSignature', reference)
        build = (ROOT / '.github/build-watch.sh').read_text()
        self.assertIn('source_sha256', build)
        self.assertIn('shasum -a 256 -c', build)
        self.assertIn('./Configure ios64-xcrun', build)


if __name__ == '__main__':
    unittest.main()
