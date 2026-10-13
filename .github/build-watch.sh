#!/usr/bin/env bash
# Native inputs only. Combining, entitlement signing, installation and release are separate gates.
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { printf '%s\n' 'Native archives require macOS and Xcode 26.2.' >&2; exit 1; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
manifest="$root/.github/watch-inputs.json"
value() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d[sys.argv[2]][sys.argv[3]])' "$manifest" "$1" "$2"; }
fail() { printf '::error::%s\n' "$*" >&2; exit 1; }
export DEVELOPER_DIR="$(value xcode developer_dir)"
[[ -d "$DEVELOPER_DIR" ]] || fail "Pinned Xcode missing: $DEVELOPER_DIR"
[[ "$(xcodebuild -version)" == "$(printf 'Xcode %s\nBuild version %s' "$(value xcode version)" "$(value xcode build)")" ]] || fail 'Xcode version/build mismatch'
xcrun --sdk iphoneos --show-sdk-version
if [[ -n "${GITHUB_REF_NAME:-}" ]]; then
    [[ "$GITHUB_REF_NAME" == "$(value host branch)" ]] || fail 'Build must use watch-combined'
fi
git merge-base --is-ancestor "$(value host base_revision)" HEAD || fail 'Host does not descend from pinned base'
host_revision="$(git rev-parse HEAD)"
out="$root/native-output"
logs="$root/native-logs"
[[ ! -e "$out" ]] || fail 'Refusing to overwrite native-output'
mkdir -p "$out" "$logs"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/watch-native.XXXXXX")"
trap 'rm -rf "$work"' EXIT
export GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=http.lowSpeedLimit GIT_CONFIG_VALUE_0=1000
export GIT_CONFIG_KEY_1=http.lowSpeedTime GIT_CONFIG_VALUE_1=60

checkout_pin() {
    local repo="$1" revision="$2" destination="$3"
    git init "$destination"
    git -C "$destination" remote add origin "$repo"
    git -C "$destination" fetch --depth 1 origin "$revision"
    git -C "$destination" checkout --detach FETCH_HEAD
    [[ "$(git -C "$destination" rev-parse HEAD)" == "$revision" ]] || fail "Source pin mismatch: $destination"
}
check_pin() {
    [[ "$(git -C "$1" rev-parse HEAD)" == "$2" ]] || fail "Dependency pin mismatch: $1"
}
git submodule sync --recursive
git submodule update --init --recursive OpenSSL litehook
check_pin OpenSSL "$(value openssl revision)"
check_pin litehook "$(value litehook revision)"
[[ "$(git config --file .gitmodules submodule.litehook.url)" == https://github.com/LiveContainerMirror/litehook ]] || fail 'litehook mirror mismatch'

# This helper is generated outside the source tree to keep the scoped repository edits small.
# The upstream all-platform Makefile requires a distribution identity; never run it here.
mkdir -p "$work/.github"
cat > "$work/.github/build_openssl.sh" <<'OPENSSL_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
source_tree="$1"; build="$2"; url="$3"; source_sha256="$4"
mkdir -p "$build/src" "$build/frameworks"
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 \
    --retry 2 --retry-max-time 600 "$url" -o "$build/openssl.tar.gz"
printf '%s  %s\n' "$source_sha256" "$build/openssl.tar.gz" | shasum -a 256 -c -
tar -xzf "$build/openssl.tar.gz" --strip-components=1 -C "$build/src"
sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
export SDKROOT="$sdk" IPHONEOS_DEPLOYMENT_TARGET=12.0
export CC="$(xcrun --sdk iphoneos --find clang)"
(
    cd "$build/src"
    ./Configure ios64-xcrun no-shared no-tests no-asm -g -miphoneos-version-min=12.0
    make -j"$(sysctl -n hw.ncpu)" build_libs
)
# Keep the pinned framework's module map, shim, resources, notices and bundle layout.
framework="$build/frameworks/OpenSSL.framework"
ditto "$source_tree/Frameworks/iphoneos/OpenSSL.framework" "$framework"
rm -rf "$framework/_CodeSignature"
python3 - "$build/src/include/openssl" "$framework/Headers" <<'HEADERS'
import pathlib, re, sys
source, destination = map(pathlib.Path, sys.argv[1:])
destination.mkdir(parents=True, exist_ok=True)
for header in source.glob('*.h'):
    text = header.read_text()
    text = re.sub(r'#\s*include\s*<openssl/', '#include <OpenSSL/', text)
    (destination / header.name).write_text(text)
HEADERS
"$CC" -dynamiclib -arch arm64 -isysroot "$sdk" -miphoneos-version-min=12.0 -g \
    -install_name @rpath/OpenSSL.framework/OpenSSL -Wl,-all_load \
    "$build/src/libssl.a" "$build/src/libcrypto.a" -o "$framework/OpenSSL"
xcrun dsymutil "$framework/OpenSSL" -o "$build/frameworks/OpenSSL.framework.dSYM"
# Only the device slice is needed. Replace runner-local generated dependency products, not source.
rm -rf "$source_tree/Frameworks/OpenSSL.xcframework" "$source_tree/Frameworks/iphoneos/OpenSSL.framework"
ditto "$framework" "$source_tree/Frameworks/iphoneos/OpenSSL.framework"
xcodebuild -create-xcframework -framework "$framework" \
    -debug-symbols "$build/frameworks/OpenSSL.framework.dSYM" \
    -output "$source_tree/Frameworks/OpenSSL.xcframework"
OPENSSL_SCRIPT
bash "$work/.github/build_openssl.sh" "$root/OpenSSL" "$work/openssl-build" \
    "$(value openssl source_url)" "$(value openssl source_sha256)" 2>&1 | tee "$logs/openssl.log"

ss="$work/SideStore"
checkout_pin "$(value sidestore repository)" "$(value sidestore revision)" "$ss"
git -C "$ss" submodule init
git -C "$ss" config submodule.Dependencies/minimuxer.url "$(value minimuxer repository)"
git -C "$ss" config submodule.Dependencies/SideSign.url "$(value sidesign repository)"
git -C "$ss" submodule update --init --recursive
# a86f42b embeds a stale minimuxer gitlink. Only this explicitly authorized dependency differs.
git -C "$ss/Dependencies/minimuxer" fetch --depth 1 origin "$(value minimuxer revision)"
git -C "$ss/Dependencies/minimuxer" checkout --detach "$(value minimuxer revision)"
git -C "$ss/Dependencies/minimuxer" submodule update --init --recursive
check_pin "$ss/Dependencies/minimuxer" "$(value minimuxer revision)"
check_pin "$ss/Dependencies/SideSign" "$(value sidesign revision)"

# Compile the matching Rust Watch FFI from source as an independent native API gate.
# Minimuxer remains unmodified: SPM still checks its published XCFramework checksum.
idevice="$work/idevice"
checkout_pin "$(value idevice repository)" "$(value idevice revision)" "$idevice"
rust_version="$(value rust version)"
rust_target="$(value rust target)"
[[ "$rust_target" == aarch64-apple-ios ]] || fail 'Rust target must be iOS device'
command -v rustup >/dev/null || fail 'Hosted runner must provide rustup'
rustup toolchain install "$rust_version" --profile minimal
rustup target add --toolchain "$rust_version" "$rust_target"
export SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)"
export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$SDKROOT"
export IPHONEOS_DEPLOYMENT_TARGET=17.0
cargo "+$rust_version" build --locked --release --manifest-path "$idevice/ffi/Cargo.toml" \
    --target "$rust_target" --features obfuscate 2>&1 | tee "$logs/rust-device.log"
rust_library="$idevice/target/$rust_target/release/libidevice_ffi.a"
[[ -s "$rust_library" ]] || fail 'No compiled native Rust library'
xcrun nm -gU "$rust_library" > "$logs/rust-symbols.txt"
for symbol in companion_proxy_connect companion_proxy_get_device_registry companion_proxy_start_forwarding_service_port; do
    grep -Eq "[[:space:]]_${symbol}$" "$logs/rust-symbols.txt" || fail "Missing Watch FFI: $symbol"
done
# Keep the Rust build's deployment/SDK environment from changing either app's project settings.
unset SDKROOT BINDGEN_EXTRA_CLANG_ARGS IPHONEOS_DEPLOYMENT_TARGET

signing=(CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY= DEBUG_INFORMATION_FORMAT=dwarf-with-dsym)
xcodebuild archive -project LiveContainer.xcodeproj -scheme LiveContainer \
    -configuration Release -sdk iphoneos -arch arm64 -destination 'generic/platform=iOS' \
    -archivePath "$work/LiveContainer.xcarchive" -derivedDataPath "$work/host-derived" \
    -disableAutomaticPackageResolution -onlyUsePackageVersionsFromResolvedFile \
    "${signing[@]}" "MARKETING_VERSION=$(value host version)" \
    "CURRENT_PROJECT_VERSION=$(value host build)" 2>&1 | tee "$logs/livecontainer.log"

# Use the existing SideStore Makefile and target graph. SideBackup's target invokes
# make -B clean-sidebackup copy-sidebackup ipa-sidebackup before its IPA resource is copied.
# No generated Swift/Rust/ObjC contributions, source patch, identity lookup or fakesigning.
(
    cd "$ss"
    make build SCHEME=SideStore CONFIGURATION=Release BUILD_CONFIG=Release \
        COMMON_BUILD_SETTINGS="-project AltStore.xcodeproj -scheme SideStore -sdk iphoneos -configuration Release -arch arm64 -destination generic/platform=iOS -derivedDataPath $work/sidestore-derived -disableAutomaticPackageResolution -onlyUsePackageVersionsFromResolvedFile CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY= DEBUG_INFORMATION_FORMAT=dwarf-with-dsym DEVELOPMENT_TEAM=XYZ0123456 ORG_IDENTIFIER=com.SideStore ENABLE_USER_SCRIPT_SANDBOXING=NO"
) 2>&1 | tee "$logs/sidestore.log"
# SideStore README/AGENTS restrictions: prove original tracked source/config/lockfile survived.
git -C "$ss" diff --exit-code -- . ':!Dependencies/minimuxer'
git -C "$ss/Dependencies/minimuxer" diff --exit-code
git -C "$ss/Dependencies/SideSign" diff --exit-code

# The host source plist hardcodes 3.8.10; update only the unsigned archive metadata.
python3 - "$work/LiveContainer.xcarchive" "$(value host version)" "$(value host build)" <<'VERSION'
import pathlib, plistlib, sys
archive, version, build = pathlib.Path(sys.argv[1]), *sys.argv[2:]
app = archive / 'Products/Applications/LiveContainer.app/Info.plist'
with app.open('rb') as f:
    data = plistlib.load(f)
data.update(CFBundleShortVersionString=version, CFBundleVersion=build)
with app.open('wb') as f:
    plistlib.dump(data, f)
metadata = archive / 'Info.plist'
with metadata.open('rb') as f:
    data = plistlib.load(f)
data['ApplicationProperties'].update(CFBundleShortVersionString=version, CFBundleVersion=build)
with metadata.open('wb') as f:
    plistlib.dump(data, f)
VERSION
[[ -s "$ss/SideStore.xcarchive/Products/Applications/SideStore.app/SideBackup.ipa" ]] || fail 'Source-built SideBackup missing (stale symlink?)'
unzip -t "$ss/SideStore.xcarchive/Products/Applications/SideStore.app/SideBackup.ipa"
[[ -d "$ss/build/sidebackup.xcarchive/dSYMs/SideBackup.app.dSYM" ]] || fail 'SideBackup dSYM missing'
ditto "$ss/build/sidebackup.xcarchive" "$work/SideBackup.xcarchive"
python3 - "$work/LiveContainer.xcarchive" "$ss/SideStore.xcarchive" "$work/SideBackup.xcarchive" <<'ARCHIVES'
import pathlib, plistlib, re, subprocess, sys

def uuids(path):
    output = subprocess.check_output(['xcrun', 'dwarfdump', '--uuid', str(path)], text=True)
    matches = set(re.findall(r'UUID: ([0-9A-Fa-f-]+) \(arm64\)', output))
    if not matches:
        raise SystemExit(f'No device arm64 UUID: {path}')
    return matches

for path in sys.argv[1:]:
    archive = pathlib.Path(path)
    apps = list((archive / 'Products/Applications').glob('*.app'))
    if len(apps) != 1:
        raise SystemExit(f'Expected exactly one native app: {archive}')
    app = apps[0]
    with (app / 'Info.plist').open('rb') as f:
        info = plistlib.load(f)
    executable = app / info['CFBundleExecutable']
    dsym = archive / f'dSYMs/{app.name}.dSYM'
    if not executable.is_file() or not dsym.is_dir():
        raise SystemExit(f'Executable/dSYM missing: {app}')
    if uuids(executable) != uuids(dsym):
        raise SystemExit(f'Executable/dSYM UUID mismatch: {app}')
    print(f'Validated arm64 executable and matching dSYM: {app.name}')
ARCHIVES
tar -czf "$out/LiveContainer.xcarchive.tar.gz" -C "$work" LiveContainer.xcarchive
tar -czf "$out/SideStore.xcarchive.tar.gz" -C "$ss" SideStore.xcarchive
tar -czf "$out/SideBackup.xcarchive.tar.gz" -C "$work" SideBackup.xcarchive
cp "$rust_library" "$out/libidevice_ffi.a"
cp "$idevice/ffi/idevice.h" "$out/idevice.h"
cp "$manifest" "$out/watch-inputs.json"
cp "$ss/AltStore.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved" "$out/SideStore.Package.resolved"
# Ship pinned source and original licenses alongside the native packaging inputs.
git archive --format=tar HEAD > "$out/LiveContainer.source.tar"
git -C "$ss" archive --format=tar HEAD > "$out/SideStore.source.tar"
for spec in "minimuxer:$ss/Dependencies/minimuxer" "SideSign:$ss/Dependencies/SideSign" "idevice:$idevice" "OpenSSL:$root/OpenSSL" "litehook:$root/litehook"; do
    git -C "${spec#*:}" archive --format=tar HEAD > "$out/${spec%%:*}.source.tar"
done
printf 'host_revision=%s\nchannel=beta\nxcode=26.2 (17C52)\n' "$host_revision" > "$out/provenance.txt"
(cd "$out" && shasum -a 256 ./* > SHA256SUMS)
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'artifact=native-watch-beta-%s-%s\nhost_archive=LiveContainer.xcarchive.tar.gz\nsidestore_archive=SideStore.xcarchive.tar.gz\n' \
        "$host_revision" "${GITHUB_RUN_ATTEMPT:-1}" >> "$GITHUB_OUTPUT"
fi
