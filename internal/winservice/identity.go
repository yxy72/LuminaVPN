package winservice

import "errors"

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
