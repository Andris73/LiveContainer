# LiveContainer Watch combined — native build inputs

**3.8.11 / 381101, watch beta 1.** Watch installation, refresh, pairing, and wrist/runtime behavior are **not proven** by compilation or by the static tests. Do not describe this as a stable release.

## Boundary

This workflow produces **unpublished GitHub Actions artifacts**, not a public GitHub release or AltStore feed update. It never combines the apps, converts executables, fakesigns bundles, imports Apple credentials, or runs the stock `.github/build_github.sh`. Packaging and release gates belong to the separate parent integration work. The workflow token has `contents: read`, and there is no publishing job.

Run on `watch-combined`, descended from `4dbe0f9a626de801184a42c0be8d2cb105058e3d`, either by pushing that branch or by manually dispatching **Watch beta native archives** on it. The immutable workflow checkout revision becomes the actual host input; the base is an ancestry constraint, not a substitute for the checked-out host changes.

## Native source/toolchain contract

The complete input list is `.github/watch-inputs.json`:

- Host: `Andris73/LiveContainer`, based on the primary `LiveContainerMirror/LiveContainer` source.
- SideStore: `Andris73/SideStore@a86f42b1d6d4eb57da0e48a1ce214191ba424f3c`; its LC Bundle integration already exists.
- minimuxer: `Andris73/minimuxer@2a20ddafdeb96ece8176d4600d8719360e27d8b2`, replacing the stale SideStore gitlink `6fa67344f3df670173a7367bdb1418b7e62ba497` **only in the disposable CI checkout**.
- SideSign: `Andris73/SideSign@e580ddc3a0e69699b570aba63bf614b1a2d532bc`.
- OpenSSL wrapper gitlink: `623c84da314e85363236507ca38a4bde65df21c3`.
- litehook gitlink: `a7e9f599d7f0b3d77008ad62bf10cb10dab6eca9`, with the `LiveContainerMirror/litehook` mirror URL.
- Rust IDevice source: `Andris73/idevice@ffed7c7670c9f9401c5cbbe640bee17f951e40e7`, the source commit for `v0.1.68-ss-cp229e`.
- macOS runner: `macos-15`; Xcode **26.2, build 17C52**, `/Applications/Xcode_26.2.app/Contents/Developer`. A missing or different Xcode fails rather than falling back. The hosted OS image itself is not immutable.
- Rust **1.90.0**, target **aarch64-apple-ios**, `cargo build --locked --release --features obfuscate`. No simulator target or Rust tools/examples build is required. Default FFI features include the Watch companion proxy; exported companion registry/forwarding symbols must exist.

Both app archives are compiled from source for `iphoneos`/arm64 with explicit unsigned command-line overrides: `CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=`. SideStore uses its existing `make build SCHEME=SideStore CONFIGURATION=Release BUILD_CONFIG=Release` path and Makefile build settings. All SPM resolutions must use the original checked-in `Package.resolved`; the build disables automatic package resolution. The build fails rather than silently adopting a moving branch update.

The host source plist hardcodes `3.8.10`; command-line version/build settings are supplied, then only the **unsigned compiled archive's** app and archive plists receive `3.8.11` and numeric `381101`. No host plist source edit is required.

### OpenSSL helper and dependency provenance

No `.github/build_openssl.sh` exists in the selected host base. Because the repository edit scope excludes adding that file, `.github/build-watch.sh` materializes and executes **`.github/build_openssl.sh` in the temporary CI workspace**, not in either source repository. It fetches OpenSSL **3.3.3** with bounded, fail-fast curl timeouts/retries and verifies the manifest's fixed SHA-256 before extraction. It compiles the iOS device static libraries and wraps them in the framework layout from the pinned OpenSSL gitlink, retaining the module map, shim, resources and license notices. The generated device-only XCFramework replaces runner-local dependency build products. The upstream all-platform Makefile is intentionally not used: it requires a distribution signing identity and builds unnecessary platforms.

**minimuxer is Swift at this pin**, not the older Rust minimuxer tree. Its `DeviceGateway/Package.swift` uses a checksum-pinned published Rust IDevice XCFramework (`69fc85b29eea6d593b6f917e1b54023d825ae6b4e1b5a1f920057bc54f27fbae`), plus checksum-pinned EMProxy/libimobiledevice binaries. This scaffold keeps those package definitions unmodified. It also independently compiles the matching Rust IDevice FFI from source and uploads its library/header as a native API/provenance gate. **That separately compiled Rust library is not substituted into SideStore's SPM binary dependency.** Replacing that XCFramework requires a separately reviewed dependency integration and new checksum; it must not be disguised as an unchanged-source build.

### SideStore contribution restrictions / SideBackup

SideStore's root README and AGENTS prohibit AI-generated source contributions. This build generates no SideStore Swift/Rust/ObjC code, applies no source patches, and makes no upstream posts/commits. Its source and package lockfile remain unmodified apart from the explicitly selected minimuxer submodule checkout; post-build `git diff --exit-code` checks enforce this. All temporary build settings are command-line settings; no credentials or `CodeSigning.xcconfig` are read by this scaffolding.

`AltStore/Resources/SideBackup.ipa` is a symlink to a generated product, not a usable prebuilt backup IPA. The existing SideBackup target runs `make -B clean-sidebackup copy-sidebackup ipa-sidebackup`, and SideStore depends on that target. Preserve this graph and Makefile path. CI requires a nonempty, valid embedded `SideBackup.ipa` and its source-built `SideBackup.app.dSYM`; it does not download a replacement.

## Artifact handoff

Successful native output contains:

- `LiveContainer.xcarchive.tar.gz` — unsigned host archive, including dSYMs.
- `SideStore.xcarchive.tar.gz` — independently compiled unsigned SideStore archive, including dSYMs and source-built SideBackup IPA.
- `SideBackup.xcarchive.tar.gz` — backup helper archive including dSYMs.
- `libidevice_ffi.a` / `idevice.h` — device Rust API build gate, not an app or standalone install package.
- `watch-inputs.json`, original `SideStore.Package.resolved`, actual host revision in `provenance.txt`, and `SHA256SUMS`.
- Separate `*.source.tar` files for the pinned host, SideStore and submodules, retaining originals/licenses (Git archives do not recursively include submodules; separate archives are intentional).

The uploaded artifact is `native-watch-beta-<host SHA>-<run attempt>`; retention is 14 days. Tarring whole archives before upload preserves symlinks, executable permissions, nested products and dSYMs. Workflow outputs expose `artifact`, `host_archive`, and `sidestore_archive` to later explicit packaging work. Failure logs have a separate seven-day diagnostic artifact; failed/partial products are not uploaded as successful native inputs.

Before any public release: require a real successful native CI run; inspect Mach-O arm64 outputs and dSYM UUIDs; apply and validate the separately reviewed combination/conversion; retain original license notices and corresponding sources; verify signing/entitlement templates, bundle routing, SideBackup, widget/intents/resources; then test install, launch, refresh, pairing and Watch operations on actual hardware. Artifact production alone does not prove these gates.

## Local verification (Linux-safe)

```sh
python3 -m unittest discover -s tests -p test_watch_ci.py -v
bash -n .github/build-watch.sh
```

These are static contract tests, not fabricated native builds. Executing the build script off macOS refuses before making artifacts. No local Mac is available; native compilation must be exercised on the hosted runner after the parent reviews and publishes the branch. This scaffold does not commit, push or dispatch on the user's behalf.
