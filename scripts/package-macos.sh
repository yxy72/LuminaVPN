#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
NETLAUNCH_BUILD_GO="${NETLAUNCH_GO:-go}"
if [ -x .tools/go/bin/go ] && [ "${NETLAUNCH_GO:-}" = "" ]; then NETLAUNCH_BUILD_GO="$PWD/.tools/go/bin/go"; fi
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
  echo 'This runtime package targets macOS arm64.' >&2; exit 1
fi
cmp runtime/manifest.json scripts/runtime-manifest.macos-arm64.json
NETLAUNCH_TEST_RUNTIME="$PWD/runtime" "$NETLAUNCH_BUILD_GO" test ./internal/app -run TestBundledCoreWithoutTUN -count=1
NETLAUNCH_VERSION=$("$NETLAUNCH_BUILD_GO" run ./cmd/netlaunch version)
NETLAUNCH_PACKAGE="$PWD/dist/NetLaunch-macOS-arm64-$NETLAUNCH_VERSION"
mkdir -p "$NETLAUNCH_PACKAGE/runtime/bin" "$NETLAUNCH_PACKAGE/runtime/lib" "$NETLAUNCH_PACKAGE/runtime/notices" "$NETLAUNCH_PACKAGE/examples" "$NETLAUNCH_PACKAGE/licenses"
"$NETLAUNCH_BUILD_GO" build -trimpath -o "$NETLAUNCH_PACKAGE/netlaunch" ./cmd/netlaunch
cp -f README.md THIRD_PARTY.md "$NETLAUNCH_PACKAGE/"
cp -f licenses/*.txt "$NETLAUNCH_PACKAGE/licenses/"
cp -f examples/policy.json examples/bootstrap.json "$NETLAUNCH_PACKAGE/examples/"
cp -f runtime/manifest.json "$NETLAUNCH_PACKAGE/runtime/"
cp -f runtime/bin/mihomo runtime/bin/openconnect "$NETLAUNCH_PACKAGE/runtime/bin/"
cp -f runtime/lib/libcrypto.3.dylib runtime/lib/libssl.3.dylib "$NETLAUNCH_PACKAGE/runtime/lib/"
cp -f -Rf runtime/notices/. "$NETLAUNCH_PACKAGE/runtime/notices/"
cp -f scripts/entries/*.command "$NETLAUNCH_PACKAGE/"
chmod 755 "$NETLAUNCH_PACKAGE/netlaunch" "$NETLAUNCH_PACKAGE/"*.command
"$NETLAUNCH_BUILD_GO" run ./cmd/packagezip "$NETLAUNCH_PACKAGE" "$NETLAUNCH_PACKAGE.zip"
(cd "$NETLAUNCH_PACKAGE/.." && /usr/bin/shasum -a 256 "$(basename "$NETLAUNCH_PACKAGE").zip") > "$NETLAUNCH_PACKAGE.zip.sha256"
echo "$NETLAUNCH_PACKAGE.zip"
