package winservice

import (
	"errors"
	"testing"
)

func testDesktopFacts() EnrollmentFacts {
	return EnrollmentFacts{SID: "S-1-5-21-1", LogonSID: "S-1-5-5-1-1", AuthenticationID: "auth-1", SessionID: 1, TokenType: 1, ElevationType: tokenElevationLimited, AdminDenyOnly: true, LogonEpoch: "epoch-1", Interactive: true, ProfileID: "profile"}
}

func testUnfilteredAdminFacts() EnrollmentFacts {
	f := testDesktopFacts()
	f.ElevationType, f.Elevated, f.EnabledAdmin, f.AdminDenyOnly = tokenElevationDefault, true, true, false
	return f
}

func TestDesktopTokenModesRetainObservedElevation(t *testing.T) {
	limited := testDesktopFacts()
	standard := limited
	standard.ElevationType, standard.AdminDenyOnly = tokenElevationDefault, false
	for _, f := range []EnrollmentFacts{limited, standard, testUnfilteredAdminFacts()} {
		before := f
		want := desktopStandard
		if f.Elevated {
			want = desktopUnfilteredAdmin
		}
		if desktopTokenMode(f) != want || f != before {
			t.Fatal("token mode was rejected or observations changed")
		}
		if err := requireDesktopProcess(f); err != nil {
			t.Fatal("valid worker process rejected", err)
		}
		f.TokenType, f.ImpersonationLevel = 2, 2
		v, err := verifiedDesktopPrincipal(f)
		if err != nil || !v.Verified() || !v.desktopEligible || v.profileID != f.ProfileID {
			t.Fatal("verified desktop caller rejected", err)
		}
		binding := testBinding("profile")
		binding.LogonEpoch = f.LogonEpoch
		if err := authorize(v, binding, "S-1-5-18", "service-1"); err != nil {
			t.Fatal(err)
		}
		for name, change := range map[string]func(*Binding){
			"owner":          func(b *Binding) { b.OwnerSID = "S-1-5-21-2" },
			"profile":        func(b *Binding) { b.ProfileID = "other" },
			"logon":          func(b *Binding) { b.LogonSID = "S-1-5-5-1-2" },
			"authentication": func(b *Binding) { b.AuthenticationID = "other" },
			"session":        func(b *Binding) { b.SessionID = 2 },
			"epoch":          func(b *Binding) { b.LogonEpoch = "epoch-2" },
		} {
			foreign := binding
			change(&foreign)
			if authorize(v, foreign, "S-1-5-18", "service-1") == nil {
				t.Fatalf("desktop caller crossed %s binding", name)
			}
		}
	}
}

func TestDesktopTokenRejectsUnknownPrivilegedAndForeignContexts(t *testing.T) {
	for name, change := range map[string]func(*EnrollmentFacts){
		"unknown-type":               func(f *EnrollmentFacts) { f.ElevationType = 0 },
		"full":                       func(f *EnrollmentFacts) { f.ElevationType = tokenElevationFull },
		"limited-elevated":           func(f *EnrollmentFacts) { f.ElevationType = tokenElevationLimited },
		"disabled-admin":             func(f *EnrollmentFacts) { f.EnabledAdmin = false },
		"deny-only-admin":            func(f *EnrollmentFacts) { f.AdminDenyOnly = true },
		"not-elevated-enabled-admin": func(f *EnrollmentFacts) { f.Elevated = false },
		"system":                     func(f *EnrollmentFacts) { f.SID = "S-1-5-18" },
		"service":                    func(f *EnrollmentFacts) { f.SID = "S-1-5-19" },
		"network-service":            func(f *EnrollmentFacts) { f.SID = "S-1-5-20" },
		"anonymous":                  func(f *EnrollmentFacts) { f.SID = "S-1-5-7" },
		"missing-logon":              func(f *EnrollmentFacts) { f.LogonSID = "" },
		"missing-authentication":     func(f *EnrollmentFacts) { f.AuthenticationID = "" },
		"missing-epoch":              func(f *EnrollmentFacts) { f.LogonEpoch = "" },
		"missing-profile":            func(f *EnrollmentFacts) { f.ProfileID = "" },
		"session-zero":               func(f *EnrollmentFacts) { f.SessionID = 0 },
		"noninteractive":             func(f *EnrollmentFacts) { f.Interactive = false },
	} {
		t.Run(name, func(t *testing.T) {
			f := testUnfilteredAdminFacts()
			change(&f)
			if desktopTokenMode(f) != desktopRejected {
				t.Fatal("invalid desktop mode accepted")
			}
			if requireDesktopProcess(f) == nil {
				t.Fatal("invalid mode accepted by worker")
			}
			f.TokenType, f.ImpersonationLevel = 2, 2
			if v, err := verifiedDesktopPrincipal(f); err == nil || v.Verified() {
				t.Fatal("invalid mode became verified IPC authority")
			}
		})
	}
	for _, token := range [][2]uint32{{1, 2}, {2, 0}, {2, 1}, {2, 4}, {0, 2}, {3, 2}} {
		f := testUnfilteredAdminFacts()
		f.TokenType, f.ImpersonationLevel = token[0], token[1]
		if v, err := verifiedDesktopPrincipal(f); err == nil || v.Verified() {
			t.Fatal("non-impersonation token became IPC authority", token)
		}
	}
	for _, tokenType := range []uint32{0, 2, 3} {
		f := testUnfilteredAdminFacts()
		f.TokenType = tokenType
		if requireDesktopProcess(f) == nil {
			t.Fatal("worker accepted nonprimary token", tokenType)
		}
	}
}

func TestUnknownElevationTypeIsRejected(t *testing.T) {
	for _, sample := range []struct {
		value, size uint32
		err         error
	}{{1, 4, errors.New("query denied")}, {1, 0, nil}, {1, 8, nil}, {0, 4, nil}, {4, 4, nil}} {
		if _, err := knownTokenElevationType(sample.value, sample.size, sample.err); err == nil {
			t.Fatal("unknown elevation type accepted")
		}
	}
	for value := uint32(1); value <= 3; value++ {
		if got, err := knownTokenElevationType(value, 4, nil); err != nil || got != value {
			t.Fatal("known elevation type rejected")
		}
	}
}

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
