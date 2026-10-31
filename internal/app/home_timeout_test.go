package app

import (
	"testing"
	"time"
)

func TestHomeSessionHasBoundedDefaultAndExplicitLimit(t *testing.T) {
	for _, tc := range []struct {
		input, want time.Duration
		valid       bool
	}{
		{0, 8 * time.Hour, true}, {time.Second, time.Second, true}, {12 * time.Hour, 12 * time.Hour, true},
		{-time.Second, 0, false}, {time.Millisecond, 0, false}, {12*time.Hour + time.Second, 0, false},
	} {
		got, err := homeSessionTimeout(tc.input)
		if (err == nil) != tc.valid || got != tc.want {
			t.Fatal(tc.input, got, err)
		}
	}
}
