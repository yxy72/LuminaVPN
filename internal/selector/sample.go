package selector

import "time"

type ProbeState struct {
	Alive   *bool `json:"alive"`
	History []struct {
		Time  time.Time `json:"time"`
		Delay *int      `json:"delay"`
	} `json:"history"`
}

// HealthyDelay verifies the per-URL result, not the node's general alive flag.
// Mihomo can return a positive delay when the expected HTTP status was missed.
func HealthyDelay(started, finished time.Time, delay *int, state ProbeState) int {
	value, _ := ObservedDelay(started, finished, delay, state)
	return value
}

// Missing/mismatched history is unknown, not proof that the node failed.
func ObservedDelay(started, finished time.Time, delay *int, state ProbeState) (int, bool) {
	if delay == nil || *delay < 0 || state.Alive == nil || len(state.History) == 0 {
		return -1, false
	}
	last := state.History[len(state.History)-1]
	if last.Delay == nil || last.Time.Before(started.Add(-time.Millisecond)) || last.Time.After(finished.Add(time.Millisecond)) {
		return -1, false
	}
	if !*state.Alive {
		return -1, true
	}
	if *last.Delay != *delay {
		return -1, false
	}
	return *delay, true
}
