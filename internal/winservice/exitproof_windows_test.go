//go:build windows

package winservice

import "testing"

func TestLocalProofWalksEveryRawAncestorAndRejectsRemoteOrDevicePaths(t *testing.T) {
	parts, anchor, ok := localPathChain(`C:\Users\Example\AppData\Roaming`, `C:\Users\Example\AppData\Roaming\NetLaunch\runs`)
	if !ok || anchor != 4 || len(parts) != 7 || parts[0] != `C:\` || parts[3] != `C:\Users\Example\AppData` {
		t.Fatalf("ancestor chain incomplete: %v %d %v", parts, anchor, ok)
	}
	for _, path := range []string{`\\server\share\profile`, `\\?\C:\Users\Example`, `C:\Users\Example:stream`, `C:\Users\Example\..\Other`, `relative`} {
		if _, _, ok := localPathChain(path, path); ok {
			t.Fatalf("untrusted local evidence path accepted: %s", path)
		}
	}
}
