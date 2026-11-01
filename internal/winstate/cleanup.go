package winstate

import "errors"

// CheckRecovered checks durable completion without invoking native networking.
func CheckRecovered(j Journal) error {
	if j.Version != 1 || j.BootID == "" || !j.Stopping {
		return errors.New("journal recovery is incomplete")
	}
	states := []string{}
	for _, v := range j.Routes {
		states = append(states, v.State)
	}
	for _, v := range j.DNS {
		states = append(states, v.State)
	}
	for _, v := range j.Addresses {
		states = append(states, v.State)
	}
	for _, v := range j.MTU {
		states = append(states, v.State)
	}
	for _, v := range j.Guards {
		states = append(states, v.State)
	}
	for _, v := range j.Pairs {
		states = append(states, v.VPN.State, v.Capture.State)
	}
	for _, state := range states {
		if state != "restored" {
			return errors.New("journal contains an unrestored resource")
		}
	}
	return nil
}
