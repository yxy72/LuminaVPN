package winservice

import (
	"fmt"
	"testing"
)

func prefixFromBits(present bool, bits int) journalServicePrefix {
	return journalServicePrefix{Present: present, SID: bits&1 != 0, Command: bits&2 != 0, Actions: bits&4 != 0, NonCrash: bits&8 != 0}
}

func TestInstallJournalServicePrefixesRejectEveryOutOfOrderConfiguration(t *testing.T) {
	for _, name := range []string{ServiceName, RecoveryServiceName} {
		for _, present := range []bool{false, true} {
			for _, partial := range []bool{false, true} {
				for bits := 0; bits < 16; bits++ {
					t.Run(fmt.Sprintf("%s/present=%t/partial=%t/bits=%d", name, present, partial, bits), func(t *testing.T) {
						want := partial && !present && bits == 0
						if present {
							if name == ServiceName {
								want = bits == 15 || (partial && (bits == 0 || bits == 1 || bits == 3 || bits == 7))
							} else {
								want = bits == 1 || (partial && bits == 0)
							}
						}
						if err := validateJournalServicePrefix(name, prefixFromBits(present, bits), partial); (err == nil) != want {
							t.Fatalf("unexpected prefix acceptance: want=%t err=%v", want, err)
						}
					})
				}
			}
		}
	}
}

func TestInstallJournalServicePrefixRejectsForeignNames(t *testing.T) {
	for _, name := range []string{"", "OtherService", ServiceName + "-copy"} {
		for _, partial := range []bool{false, true} {
			if err := validateJournalServicePrefix(name, prefixFromBits(true, 15), partial); err == nil {
				t.Fatal("foreign service accepted", name)
			}
		}
	}
}

func TestInstallJournalPreparedPrefixesRequireMainCompleteBeforeRecoveryExists(t *testing.T) {
	for _, mainPresent := range []bool{false, true} {
		for _, recoveryPresent := range []bool{false, true} {
			for mainBits := 0; mainBits < 16; mainBits++ {
				for recoveryBits := 0; recoveryBits < 16; recoveryBits++ {
					main := prefixFromBits(mainPresent, mainBits)
					recovery := prefixFromBits(recoveryPresent, recoveryBits)
					mainValid := (!mainPresent && mainBits == 0) || (mainPresent && (mainBits == 0 || mainBits == 1 || mainBits == 3 || mainBits == 7 || mainBits == 15))
					recoveryValid := (!recoveryPresent && recoveryBits == 0) || (recoveryPresent && (recoveryBits == 0 || recoveryBits == 1))
					want := mainValid && recoveryValid && (!recoveryPresent || (mainPresent && mainBits == 15))
					if err := validatePreparedServicePrefixes(main, recovery); (err == nil) != want {
						t.Fatalf("main=%+v recovery=%+v want=%t err=%v", main, recovery, want, err)
					}
				}
			}
		}
	}
}
