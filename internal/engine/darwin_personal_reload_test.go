//go:build darwin

package engine

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"netlaunch/internal/policy"
)

func TestDarwinPersonalReloadClosesOldCandidateAndLeavesEveryGateClosed(t *testing.T) {
	compiled := func(candidate bool) map[string]any {
		groups := []any{}
		for _, name := range []string{"PHYSICAL", "PERSONAL", "CORP"} {
			groups = append(groups, map[string]any{"name": name, "type": "select", "proxies": []string{"REJECT"}})
		}
		if candidate {
			groups = append(groups, map[string]any{"name": candidateGroup, "type": "select", "proxies": []any{"REJECT", "P007"}})
		}
		return map[string]any{
			"proxy-groups": groups,
			"profile":      map[string]any{"store-selected": false, "store-fake-ip": false},
			"dns":          map[string]any{"enable": true, "enhanced-mode": "fake-ip", "fake-ip-range": "198.19.0.1/16"},
		}
	}
	previous, next := compiled(true), compiled(false)
	previous["proxies"] = []any{policy.Node{"name": "P007"}}
	want := []string{
		"PHYSICAL=REJECT", "PERSONAL=REJECT", "CORP=REJECT", candidateGroup + "=REJECT",
		"GET /connections", "DELETE /connections/retired-candidate", "DELETE /connections/direct",
		"save", "PUT /configs?force=true", "PHYSICAL=REJECT", "PERSONAL=REJECT", "CORP=REJECT", "POST /cache/dns/flush",
		"GET /connections", "DELETE /connections/in-flight",
	}
	for failed := -1; failed < len(want); failed++ {
		var actions []string
		sentinel := errors.New("injected step failure")
		step := func(action string) error {
			actions = append(actions, action)
			if len(actions)-1 == failed {
				return sentinel
			}
			return nil
		}
		err := prepareDarwinPersonalConfig(next, previous, "core.json", desktopReloadControl{
			selectGroup: func(group, target string) error { return step(group + "=" + target) },
			request: func(method, path string, payload, out any) error {
				if err := step(method + " " + path); err != nil {
					return err
				}
				if out != nil {
					if len(actions) > 12 {
						return json.Unmarshal([]byte(`{"connections":[{"id":"in-flight","chains":["P007"]}]}`), out)
					}
					return json.Unmarshal([]byte(`{"connections":[{"id":"retired-candidate","chains":["P007"]},{"id":"direct","chains":["PHYSICAL-BOUND","PHYSICAL"]},{"id":"company","chains":["CORP-BOUND","CORP"]}]}`), out)
				}
				return nil
			},
			save: func(map[string]any) error { return step("save") },
		})
		if failed < 0 {
			if err != nil || !reflect.DeepEqual(actions, want) {
				t.Fatal("prepare did not preserve the barrier", actions, err)
			}
		} else if !errors.Is(err, sentinel) || !reflect.DeepEqual(actions, want[:failed+1]) {
			t.Fatal("prepare continued past a failed step", failed, actions, err)
		}
	}
	next["profile"].(map[string]any)["store-fake-ip"] = true
	err := prepareDarwinPersonalConfig(next, previous, "core.json", desktopReloadControl{})
	if err == nil || !strings.Contains(err.Error(), "in-memory fake-IP") {
		t.Fatal("reload attempted to change the pool's storage semantics", err)
	}
}
