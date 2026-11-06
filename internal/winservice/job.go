package winservice

import (
	"errors"
	"time"
)

func waitJobEmpty(deadline time.Time, now func() time.Time, sleep func(time.Duration), query func() (uint32, error)) error {
	for {
		if !now().Before(deadline) {
			return errors.New("owned worker job exit deadline reached")
		}
		active, err := query()
		if !now().Before(deadline) {
			return errors.New("owned worker job exit readback was late")
		}
		if err != nil {
			return errors.New("owned worker job exit is unknown")
		}
		if active == 0 {
			return nil
		}
		sleep(min(50*time.Millisecond, deadline.Sub(now())))
	}
}
