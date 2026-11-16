# Third-party components

NetLaunch executes Mihomo and OpenConnect as separate processes. Their licenses remain applicable to those components. Bundled notices are in `runtime/notices/`.

| Component | Version | License / source |
|---|---|---|
| Mihomo | v1.19.32-lumina.1 (macOS and Windows) | GPL-3.0, https://github.com/MetaCubeX/mihomo/tree/v1.19.32 |
| OpenConnect | 9.21 | LGPL-2.1, https://www.infradead.org/openconnect/ |
| OpenSSL | 3.x (exact bundled hashes in runtime manifest) | Apache-2.0, https://www.openssl.org/source/ |
| go-yaml | v3.0.1 | MIT / Apache-2.0, https://github.com/go-yaml/yaml/tree/v3.0.1 |
| golang.org/x/sys | v0.49.0 | BSD-3-Clause, https://cs.opensource.google/go/x/sys/+/refs/tags/v0.49.0 |
| Go runtime | build toolchain version | BSD-3-Clause, https://go.dev/LICENSE |

The Mac and Windows Mihomo derivatives apply `scripts/patches/mihomo-v1.19.32-fakeip-pool-reuse.patch` to upstream commit `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`. Compatible in-memory pools retain the same mappings and allocation cursor across resolver reloads. Persistent pools and incompatible prefixes or capacities use the upstream clone behavior. `scripts/patches/` contains the original GPL license, fixed source identities, and offline rebuild recipes for macOS arm64 and Windows amd64. The macOS recipe requires Go 1.27.3 and produces the ad hoc signed Mach-O pinned in `scripts/runtime-manifest.macos-arm64.json`. The Windows build provenance and its binary digest are recorded beside the patch.

The Mac runtime uses relocated relative library paths and ad-hoc signatures. Its package manifest fixes the exact binary hashes. This local preview does not include personal node data, company credentials or test logs. Public distribution and code signing are separate release work; retain required licenses and provide corresponding sources under the applicable component licenses.
