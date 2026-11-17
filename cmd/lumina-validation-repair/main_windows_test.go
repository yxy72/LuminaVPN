//go:build windows && windows_client_predecessor_repair

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDecodePlanRequiresExactFreshGrant(t *testing.T) {
	now := time.Unix(1000, 0)
	nonce := strings.Repeat("a", 32)
	valid := repairPlan{
		Version: 1, Purpose: repairPurpose, Nonce: nonce,
		ImageSHA256: strings.Repeat("b", 64), CreatedUnix: 980, ExpiresUnix: 1200,
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodePlan(raw, nonce, now); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		data  []byte
		nonce string
		time  time.Time
	}{
		{"wrong nonce", raw, strings.Repeat("c", 32), now},
		{"unsafe nonce", raw, `..\other`, now},
		{"expired", raw, nonce, time.Unix(1200, 0)},
		{"future issued", raw, nonce, time.Unix(979, 0)},
		{"long grant", []byte(strings.Replace(string(raw), `"expires_unix":1200`, `"expires_unix":1281`, 1)), nonce, now},
		{"unknown input", []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"path":"test"`, 1)), nonce, now},
		{"trailing input", append(append([]byte(nil), raw...), []byte(`{}`)...), nonce, now},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodePlan(test.data, test.nonce, test.time); err == nil {
				t.Fatal("unexpected valid grant")
			}
		})
	}
}
