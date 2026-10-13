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


    def test_generic_ios_destination_has_no_duplicate_arch_argument(self):
        text = (ROOT / '.github/build-watch.sh').read_text()
        host = text.split('xcodebuild archive -project LiveContainer.xcodeproj', 1)[1].split('tee "$logs/livecontainer.log"', 1)[0]
        side = text.split('COMMON_BUILD_SETTINGS=', 1)[1].split('\n', 1)[0]
        for command in (host, side):
            self.assertNotIn('-arch arm64', command)
            self.assertIn('ARCHS=arm64', command)
            self.assertIn('-destination', command)


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
