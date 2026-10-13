#!/usr/bin/env bash
# Ad-hoc placeholders only; the installing store must apply real user signing.
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { printf '%s\n' 'Ad-hoc packaging requires macOS codesign.' >&2; exit 1; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native="$(cd "$1" && pwd)"
output_parent="$(dirname "$2")"
mkdir -p "$output_parent"
output="$(cd "$output_parent" && pwd)/$(basename "$2")"
revision="$3"
[[ ! -e "$output" && ! -L "$output" ]] || { printf '%s\n' 'Refusing existing package output.' >&2; exit 1; }
reservation="$output.reserved"
mkdir "$reservation" # Exclusive reservation, never mkdir -p.
work=''; public=''
cleanup() {
    [[ -z "$work" ]] || rm -rf "$work"
    [[ -z "$public" ]] || rm -rf "$public"
    rmdir "$reservation"
}
trap cleanup EXIT
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/watch-package.XXXXXX")"
public="$(mktemp -d "$output_parent/.watch-public.XXXXXX")"
# Copies the files into an isolated snapshot, requires checksum coverage, validates
# all archive roots/paths/types/link graphs BEFORE any extraction, then publishes
# the complete ingested tree. Workflow-run authentication is a separate CI gate.
python3 "$root/tools/native_inputs.py" ingest "$native" "$work/inputs" "$revision"
native="$work/inputs/native"
python3 - "$root/tools" "$work/inputs" <<'PY'
import pathlib, re, subprocess, sys
sys.path.insert(0, sys.argv[1])
from package_watch import validate_archive
root = pathlib.Path(sys.argv[2])
identities = {'LiveContainer': 'com.kdt.livecontainer', 'SideStore': 'com.SideStore.SideStore', 'SideBackup': 'com.SideStore.SideStore.SideBackup'}
def uuids(path):
    text = subprocess.check_output(['xcrun', 'dwarfdump', '--uuid', str(path)], text=True)
    values = set(re.findall(r'UUID: ([0-9A-Fa-f-]+) \(([^)]+)\)', text))
    if not values or any(arch != 'arm64' for _, arch in values):
        raise ValueError('expected exactly native device arm64 UUID coverage')
    return {(value.lower(), arch) for value, arch in values}
for name, identity in identities.items():
    archive = root / name / f'{name}.xcarchive'
    app, parsed = validate_archive(archive, name, identity)
    executable = app / name
    dsym = archive / f'dSYMs/{name}.app.dSYM'
    if uuids(executable) != uuids(dsym) or uuids(executable) != {(parsed['uuid'], 'arm64')}:
        raise ValueError(f'architecture-aware dSYM UUID mismatch: {name}')
PY
python3 "$root/tools/package_watch.py" \
    "$work/inputs/LiveContainer/LiveContainer.xcarchive/Products/Applications/LiveContainer.app" \
    "$work/inputs/SideStore/SideStore.xcarchive/Products/Applications/SideStore.app" \
    "$work/combined" --backup-archive "$work/inputs/SideBackup/SideBackup.xcarchive" \
    --inputs "$native/watch-inputs.json" --revision "$revision"
app="$work/combined/Payload/LiveContainer.app"
# This inventory covers the ENTIRE app: deeper dylibs, frameworks inside
# extensions, extensions and finally enclosing apps. Never codesign --deep sign.
python3 - "$root/tools" "$app" "$work" <<'PY'
import pathlib, sys
sys.path.insert(0, sys.argv[1])
from package_watch import sign_tree
sign_tree(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
PY
# Only publish after genuine codesign --verify --deep --strict (inside sign_tree),
# complete ZIP creation/integrity and metadata/source preservation succeed.
(cd "$work/combined" && zip -qry "$public/LiveContainer-SideStore-Watch-Beta.ipa" Payload)
unzip -t "$public/LiveContainer-SideStore-Watch-Beta.ipa"
cp "$app/LCWatchBuild.json" "$public/build-provenance.json"
cp "$native/watch-inputs.json" "$native/provenance.txt" "$native/SHA256SUMS" "$public/"
mv "$public/SHA256SUMS" "$public/native-SHA256SUMS"
# Retain existing corresponding-source archives and their original license notices.
for source in "$native"/*.source.tar; do
    [[ -f "$source" ]] || continue
    cp "$source" "$public/"
done
xcrun dwarfdump --uuid "$app/LiveContainer" "$app/Frameworks/SideStoreApp.framework/SideStore" \
    "$work/inputs/SideBackup/SideBackup.xcarchive/Products/Applications/SideBackup.app/SideBackup" > "$public/binary-uuids.txt"
(cd "$public" && shasum -a 256 ./* > SHA256SUMS && shasum -a 256 -c SHA256SUMS)
python3 "$root/tools/native_inputs.py" publish "$public" "$output"
public=''
