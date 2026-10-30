#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
NETLAUNCH_BUILD_GO="${NETLAUNCH_GO:-go}"
if [ -x .tools/go/bin/go ] && [ "${NETLAUNCH_GO:-}" = "" ]; then NETLAUNCH_BUILD_GO="$PWD/.tools/go/bin/go"; fi
NETLAUNCH_WIN_RUNTIME="${NETLAUNCH_WINDOWS_RUNTIME:-$PWD/.local/windows-runtime}"
cmp "$NETLAUNCH_WIN_RUNTIME/manifest.json" scripts/runtime-manifest.windows-amd64.json
NETLAUNCH_PACKAGE="$PWD/dist/NetLaunch-Windows-amd64-0.1.0-preview.1"
mkdir -p "$NETLAUNCH_PACKAGE/runtime/bin" "$NETLAUNCH_PACKAGE/runtime/certs" "$NETLAUNCH_PACKAGE/runtime/notices/openconnect" "$NETLAUNCH_PACKAGE/examples" "$NETLAUNCH_PACKAGE/licenses"
GOOS=windows GOARCH=amd64 "$NETLAUNCH_BUILD_GO" build -trimpath -o "$NETLAUNCH_PACKAGE/netlaunch.exe" ./cmd/netlaunch
cp -f README.md THIRD_PARTY.md "$NETLAUNCH_PACKAGE/"
cp -f licenses/*.txt "$NETLAUNCH_PACKAGE/licenses/"
cp -f examples/policy.json examples/bootstrap.json "$NETLAUNCH_PACKAGE/examples/"
cp -f "$NETLAUNCH_WIN_RUNTIME/manifest.json" "$NETLAUNCH_PACKAGE/runtime/"
cp -f "$NETLAUNCH_WIN_RUNTIME/bin/"*.exe "$NETLAUNCH_WIN_RUNTIME/bin/"*.dll "$NETLAUNCH_PACKAGE/runtime/bin/"
cp -f "$NETLAUNCH_WIN_RUNTIME/certs/ca-bundle.crt" "$NETLAUNCH_PACKAGE/runtime/certs/"
cp -f "$NETLAUNCH_WIN_RUNTIME/notices/Go-LICENSE" "$NETLAUNCH_WIN_RUNTIME/notices/mihomo-LICENSE" "$NETLAUNCH_WIN_RUNTIME/notices/yaml-LICENSE" "$NETLAUNCH_WIN_RUNTIME/notices/windows-components.txt" "$NETLAUNCH_PACKAGE/runtime/notices/"
cp -f "$NETLAUNCH_WIN_RUNTIME/notices/openconnect/COPYING.LGPL" "$NETLAUNCH_PACKAGE/runtime/notices/openconnect/"
"$NETLAUNCH_BUILD_GO" run ./cmd/packagezip "$NETLAUNCH_PACKAGE" "$NETLAUNCH_PACKAGE.zip" windows
(cd "$NETLAUNCH_PACKAGE/.." && shasum -a 256 "$(basename "$NETLAUNCH_PACKAGE").zip") > "$NETLAUNCH_PACKAGE.zip.sha256"
echo "$NETLAUNCH_PACKAGE.zip"
