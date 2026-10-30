package selector

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDelayMustMatchFreshSuccessfulURLResult(t *testing.T) {
	start := time.Date(2026, 10, 30, 1, 2, 3, 0, time.UTC)
	delay := 12
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"good", `{"alive":true,"history":[{"time":"2026-10-30T01:02:03Z","delay":12}]}`, 12},
		{"wrong_status", `{"alive":false,"history":[{"time":"2026-10-30T01:02:03Z","delay":12}]}`, -1},
		{"stale", `{"alive":true,"history":[{"time":"2026-10-30T01:02:00Z","delay":12}]}`, -1},
		{"future", `{"alive":true,"history":[{"time":"2026-10-30T01:02:20Z","delay":12}]}`, -1},
		{"missing", `{"alive":true}`, -1},
		{"different_probe", `{"alive":true,"history":[{"time":"2026-10-30T01:02:03Z","delay":13}]}`, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var state ProbeState
			if e := json.Unmarshal([]byte(tc.body), &state); e != nil {
				t.Fatal(e)
			}
			if got := HealthyDelay(start, start.Add(time.Second), &delay, state); got != tc.want {
				t.Fatal(got)
			}
		})
	}
}
