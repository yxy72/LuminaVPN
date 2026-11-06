package winservice

import (
	"errors"
	"testing"
)

func TestOnlyImpersonationCapableCallerTokensAuthorizeWork(t *testing.T) {
	for _, values := range [][2]uint32{{1, 2}, {2, 0}, {2, 1}, {2, 4}, {0, 0}} {
		if requireImpersonationToken(values[0], values[1]) == nil {
			t.Fatalf("unusable caller token accepted: %v", values)
		}
	}
	for _, level := range []uint32{2, 3} {
		if err := requireImpersonationToken(2, level); err != nil {
			t.Fatal(err)
		}
	}
}
func TestUnknownElevationCannotBeClassifiedAsOrdinary(t *testing.T) {
	for _, sample := range []struct {
		value, size uint32
		err         error
	}{{0, 4, errors.New("query denied")}, {0, 0, nil}, {0, 8, nil}, {2, 4, nil}} {
		if ordinary, err := knownTokenElevation(sample.value, sample.size, sample.err); err == nil || ordinary {
			t.Fatal("unknown elevation became an ordinary token")
		}
	}
	if elevated, err := knownTokenElevation(0, 4, nil); err != nil || elevated {
		t.Fatal("known ordinary elevation rejected")
	}
	if elevated, err := knownTokenElevation(1, 4, nil); err != nil || !elevated {
		t.Fatal("known elevated token misclassified")
	}
}
