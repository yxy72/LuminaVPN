#!/bin/sh
# Local ad-hoc resource sealing; this does not provide Developer ID trust.
set -eu
LUMINA_REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LUMINA_APP=${1:?Provide the generated LuminaVPN.app path}
python3 "$LUMINA_REPO/scripts/check-desktop-package.py" "$LUMINA_APP"

# The shipped runtime bytes are already signed and must remain unchanged.
/usr/bin/codesign --verify --strict "$LUMINA_APP/Contents/Resources/backend/netlaunch"
for LUMINA_CODE in "$LUMINA_APP/Contents/Resources/runtime/bin/mihomo" "$LUMINA_APP/Contents/Resources/runtime/bin/openconnect" "$LUMINA_APP/Contents/Resources/runtime/lib/libcrypto.3.dylib" "$LUMINA_APP/Contents/Resources/runtime/lib/libssl.3.dylib"; do
  /usr/bin/codesign --verify --strict "$LUMINA_CODE"
done

# Electron helper metadata changes when packaging. Seal those bundles first;
# never deep-sign the app, which would alter manifest-verified runtime files.
for LUMINA_FRAMEWORK in "$LUMINA_APP/Contents/Frameworks/"*.framework; do
  /usr/bin/codesign --force --sign - --timestamp=none "$LUMINA_FRAMEWORK"
done
for LUMINA_HELPER in "$LUMINA_APP/Contents/Frameworks/"*.app; do
  /usr/bin/codesign --force --sign - --timestamp=none "$LUMINA_HELPER"
done
/usr/bin/codesign --force --sign - --timestamp=none --identifier app.luminavpn.desktop "$LUMINA_APP"
/usr/bin/codesign --verify --deep --strict "$LUMINA_APP"
python3 "$LUMINA_REPO/scripts/check-desktop-package.py" "$LUMINA_APP"
printf 'Local ad-hoc preview signature and unchanged runtime digests verified.\n'
