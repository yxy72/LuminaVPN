package selector

import "time"

type ProbeState struct {
	Alive   bool `json:"alive"`
	History []struct {
		Time  time.Time `json:"time"`
		Delay *int      `json:"delay"`
	} `json:"history"`
}

// HealthyDelay verifies the per-URL result, not the node's general alive flag.
// Mihomo can return a positive delay when the expected HTTP status was missed.
func HealthyDelay(started, finished time.Time, delay *int, state ProbeState) int {
	if delay == nil || *delay < 0 || !state.Alive || len(state.History) == 0 {
		return -1
	}
	last := state.History[len(state.History)-1]
	if last.Delay == nil || *last.Delay != *delay || last.Time.Before(started.Add(-time.Millisecond)) || last.Time.After(finished.Add(time.Millisecond)) {
		return -1
	}
	return *delay
}
