#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
NETLAUNCH_BUILD_GO="${NETLAUNCH_GO:-go}"
if [ -x .tools/go/bin/go ] && [ "${NETLAUNCH_GO:-}" = "" ]; then NETLAUNCH_BUILD_GO="$PWD/.tools/go/bin/go"; fi
NETLAUNCH_WIN_RUNTIME="${NETLAUNCH_WINDOWS_RUNTIME:-$PWD/.local/windows-runtime}"
if [ "$(tr -d '\r' < "$NETLAUNCH_WIN_RUNTIME/manifest.json")" != "$(tr -d '\r' < scripts/runtime-manifest.windows-amd64.json)" ]; then
  echo 'Runtime manifest differs from the repository pin.' >&2; exit 1
fi
NETLAUNCH_VERSION=$("$NETLAUNCH_BUILD_GO" run ./cmd/netlaunch version)
NETLAUNCH_MODE="${NETLAUNCH_WINDOWS_MODE:-offline}"
case "$NETLAUNCH_MODE" in
  offline) NETLAUNCH_TAGS="" ;;
  home) NETLAUNCH_TAGS="windows_home" ;;
  validation) NETLAUNCH_TAGS="windows_validation" ;;
  *) echo 'NETLAUNCH_WINDOWS_MODE must be offline, home or validation.' >&2; exit 1 ;;
esac
NETLAUNCH_PACKAGE="$PWD/dist/NetLaunch-Windows-amd64-$NETLAUNCH_VERSION-$NETLAUNCH_MODE"
mkdir -p "$NETLAUNCH_PACKAGE/runtime/bin" "$NETLAUNCH_PACKAGE/runtime/certs" "$NETLAUNCH_PACKAGE/runtime/notices/openconnect" "$NETLAUNCH_PACKAGE/examples" "$NETLAUNCH_PACKAGE/licenses"
GOOS=windows GOARCH=amd64 "$NETLAUNCH_BUILD_GO" build -trimpath -tags "$NETLAUNCH_TAGS" -o "$NETLAUNCH_PACKAGE/netlaunch.exe" ./cmd/netlaunch
cp -f README.md THIRD_PARTY.md "$NETLAUNCH_PACKAGE/"
cp -f licenses/*.txt "$NETLAUNCH_PACKAGE/licenses/"
cp -f examples/policy.json examples/bootstrap.json "$NETLAUNCH_PACKAGE/examples/"
cp -f scripts/entries-windows/*.cmd "$NETLAUNCH_PACKAGE/"
cp -f "$NETLAUNCH_WIN_RUNTIME/manifest.json" "$NETLAUNCH_PACKAGE/runtime/"
cp -f "$NETLAUNCH_WIN_RUNTIME/bin/"*.exe "$NETLAUNCH_WIN_RUNTIME/bin/"*.dll "$NETLAUNCH_PACKAGE/runtime/bin/"
cp -f "$NETLAUNCH_WIN_RUNTIME/certs/ca-bundle.crt" "$NETLAUNCH_PACKAGE/runtime/certs/"
cp -f "$NETLAUNCH_WIN_RUNTIME/notices/Go-LICENSE" "$NETLAUNCH_WIN_RUNTIME/notices/mihomo-LICENSE" "$NETLAUNCH_WIN_RUNTIME/notices/yaml-LICENSE" "$NETLAUNCH_WIN_RUNTIME/notices/windows-components.txt" "$NETLAUNCH_PACKAGE/runtime/notices/"
cp -f "$NETLAUNCH_WIN_RUNTIME/notices/openconnect/COPYING.LGPL" "$NETLAUNCH_PACKAGE/runtime/notices/openconnect/"
"$NETLAUNCH_BUILD_GO" run ./cmd/packagezip "$NETLAUNCH_PACKAGE" "$NETLAUNCH_PACKAGE.zip" windows
(cd "$NETLAUNCH_PACKAGE/.." && shasum -a 256 "$(basename "$NETLAUNCH_PACKAGE").zip") > "$NETLAUNCH_PACKAGE.zip.sha256"
echo "$NETLAUNCH_PACKAGE.zip"
