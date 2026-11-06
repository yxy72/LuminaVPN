# Third-party components

NetLaunch executes Mihomo and OpenConnect as separate processes. Their licenses remain applicable to those components. Bundled notices are in `runtime/notices/`.

| Component | Version | License / source |
|---|---|---|
| Mihomo | v1.19.32 (macOS); v1.19.32-lumina.1 (Windows) | GPL-3.0, https://github.com/MetaCubeX/mihomo/tree/v1.19.32 |
| OpenConnect | 9.21 | LGPL-2.1, https://www.infradead.org/openconnect/ |
| OpenSSL | 3.x (exact bundled hashes in runtime manifest) | Apache-2.0, https://www.openssl.org/source/ |
| go-yaml | v3.0.1 | MIT / Apache-2.0, https://github.com/go-yaml/yaml/tree/v3.0.1 |
| golang.org/x/sys | v0.49.0 | BSD-3-Clause, https://cs.opensource.google/go/x/sys/+/refs/tags/v0.49.0 |
| Go runtime | build toolchain version | BSD-3-Clause, https://go.dev/LICENSE |

The Windows Mihomo derivative uses upstream commit `88dcbf7f1614a67c3b36b848ee3592dfa92ada36` with the in-memory fake-IP pool reuse change in `scripts/patches/mihomo-v1.19.32-fakeip-pool-reuse.patch`. The original GPL license, source identities, build recipe and derivative binary hash are retained beside that patch. The change keeps one pool across resolver reloads; persistent pools and other platforms' runtime manifests retain their upstream behavior.

The Mac runtime uses relocated relative library paths and ad-hoc signatures. Its package manifest fixes the exact binary hashes. This local preview does not include personal node data, company credentials or test logs. Public distribution and code signing are separate release work; retain required licenses and provide corresponding sources under the applicable component licenses.
