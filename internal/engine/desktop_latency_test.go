//go:build darwin || windows

package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManualLatencyRetriesCompletedFailuresOnly(t *testing.T) {
	const target = "https://target.example/"
	calls := map[string]int{}
	var lock sync.Mutex
	request := func(_ context.Context, path string, out any) error {
		u, err := url.Parse(path)
		if err != nil {
			return err
		}
		name := strings.Split(u.Path, "/")[2]
		if strings.HasSuffix(u.Path, "/delay") {
			if u.Query().Get("timeout") != "4500" {
				t.Errorf("manual probe used the wrong limit")
			}
			lock.Lock()
			calls[name]++
			attempt := calls[name]
			lock.Unlock()
			switch {
			case name == "P002":
				return &coreFailure{status: 401}
			case name == "P003" || name == "P001" && attempt == 1:
				return &coreFailure{status: 504}
			default:
				return json.Unmarshal([]byte("{\"delay\":120}"), out)
			}
		}
		history := fmt.Sprintf("{\"extra\":{%q:{\"alive\":true,\"history\":[{\"time\":%q,\"delay\":120}]}}}",
			target, time.Now().Format(time.RFC3339Nano))
		return json.Unmarshal([]byte(history), out)
	}
	values := measureDesktopCandidates(t.Context(), []string{"P001", "P002", "P003"}, target, request)
	if len(values) != 2 || values["P001"] != 120 || values["P003"] != -1 ||
		calls["P001"] != 2 || calls["P002"] != 1 || calls["P003"] != 2 {
		t.Fatalf("unexpected measured delay or retry counts: %v, %v", values, calls)
	}
}
