package winservice

import "errors"

// journalServicePrefix represents only exact, independently inspected native
// values. The adapter must reject unknown SID/failure configurations before
// reducing them to these booleans; false means the exact unset value.
type journalServicePrefix struct {
	Present, SID, Command, Actions, NonCrash bool
}

func validateJournalServicePrefix(name string, prefix journalServicePrefix, partial bool) error {
	if name != ServiceName && name != RecoveryServiceName {
		return errors.New("unknown installer service name")
	}
	if !prefix.Present {
		if !partial || prefix.SID || prefix.Command || prefix.Actions || prefix.NonCrash {
			return errors.New("invalid absent installer service configuration")
		}
		return nil
	}
	if name == RecoveryServiceName {
		if prefix.Command || prefix.Actions || prefix.NonCrash || (!partial && !prefix.SID) {
			return errors.New("invalid recovery service configuration prefix")
		}
		return nil
	}
	unset := false
	for _, configured := range []bool{prefix.SID, prefix.Command, prefix.Actions, prefix.NonCrash} {
		if !configured {
			unset = true
		} else if unset {
			return errors.New("main service configuration is not an ordered prefix")
		}
	}
	if !partial && unset {
		return errors.New("main service configuration is incomplete")
	}
	return nil
}

func validatePreparedServicePrefixes(main, recovery journalServicePrefix) error {
	if err := validateJournalServicePrefix(ServiceName, main, true); err != nil {
		return err
	}
	if err := validateJournalServicePrefix(RecoveryServiceName, recovery, true); err != nil {
		return err
	}
	// Recovery creation happens only after the main configuration is complete.
	if recovery.Present {
		return validateJournalServicePrefix(ServiceName, main, false)
	}
	return nil
}
