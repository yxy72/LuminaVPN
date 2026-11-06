package winservice

import "errors"

const (
	tokenElevationDefault uint32 = 1
	tokenElevationFull    uint32 = 2
	tokenElevationLimited uint32 = 3
)

type desktopMode uint8

const (
	desktopRejected desktopMode = iota
	desktopStandard
	desktopUnfilteredAdmin
)

func knownTokenElevationType(value, returned uint32, queryErr error) (uint32, error) {
	if queryErr != nil || returned != 4 || value < tokenElevationDefault || value > tokenElevationLimited {
		return 0, errors.New("token elevation type observation unknown")
	}
	return value, nil
}

func validInteractiveIdentity(f EnrollmentFacts) bool {
	return sidText.MatchString(f.SID) && f.SID != "S-1-5-18" && f.SID != "S-1-5-19" && f.SID != "S-1-5-20" && f.SID != "S-1-5-7" && sidText.MatchString(f.LogonSID) && f.AuthenticationID != "" && len(f.AuthenticationID) <= 128 && f.SessionID != 0 && f.LogonEpoch != "" && f.Interactive && ValidProfileID(f.ProfileID)
}

func desktopTokenMode(f EnrollmentFacts) desktopMode {
	if !validInteractiveIdentity(f) {
		return desktopRejected
	}
	switch f.ElevationType {
	case tokenElevationDefault:
		if f.Elevated && f.EnabledAdmin && !f.AdminDenyOnly {
			return desktopUnfilteredAdmin
		}
		if !f.Elevated && !f.EnabledAdmin {
			return desktopStandard
		}
	case tokenElevationLimited:
		if !f.Elevated && !f.EnabledAdmin {
			return desktopStandard
		}
	}
	return desktopRejected
}

func sameDesktopLogin(a, b EnrollmentFacts) bool {
	return validInteractiveIdentity(a) && validInteractiveIdentity(b) && a.SID == b.SID && a.LogonSID == b.LogonSID && a.AuthenticationID == b.AuthenticationID && a.SessionID == b.SessionID && a.LogonEpoch == b.LogonEpoch && a.ProfileID == b.ProfileID
}

func requireDesktopProcess(f EnrollmentFacts) error {
	if f.TokenType != 1 || desktopTokenMode(f) == desktopRejected {
		return errors.New("verified interactive user process required")
	}
	return nil
}

func verifiedDesktopPrincipal(f EnrollmentFacts) (VerifiedPrincipal, error) {
	if err := requireImpersonationToken(f.TokenType, f.ImpersonationLevel); err != nil {
		return VerifiedPrincipal{}, err
	}
	if desktopTokenMode(f) == desktopRejected {
		return VerifiedPrincipal{}, errors.New("verified interactive desktop token required")
	}
	return VerifiedPrincipal{sid: f.SID, logonSID: f.LogonSID, authenticationID: f.AuthenticationID, sessionID: f.SessionID, logonEpoch: f.LogonEpoch, profileID: f.ProfileID, desktopEligible: true, verified: true}, nil
}

func knownTokenElevation(value, returned uint32, queryErr error) (bool, error) {
	if queryErr != nil || returned != 4 || value > 1 {
		return false, errors.New("token elevation observation unknown")
	}
	return value == 1, nil
}

// TokenImpersonation=2; SecurityImpersonation=2 and SecurityDelegation=3.
// Identification and anonymous tokens cannot authorize privileged work even
// when their user SID can be queried successfully.
func requireImpersonationToken(tokenType, level uint32) error {
	if tokenType != 2 || level < 2 || level > 3 {
		return errors.New("caller token cannot authorize impersonated work")
	}
	return nil
}
