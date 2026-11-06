//go:build windows

package engine

import (
	"encoding/json"
	"errors"
	"netlaunch/internal/policy"
	"reflect"
	"strings"
	"testing"
)

func TestDesktopReloadKeepsGroupsClosedUntilResolverReplacement(t *testing.T) {
	want := []string{"select PHYSICAL REJECT", "select PERSONAL REJECT", "select CORP REJECT", "GET /connections", "DELETE /connections/personal-id", "DELETE /connections/direct-id", "DELETE /connections/probe-id", "save", "PUT /configs?force=true", "select PHYSICAL REJECT", "select PERSONAL REJECT", "select CORP REJECT", "POST /cache/dns/flush", "select PHYSICAL PHYSICAL-BOUND", "select PERSONAL PHYSICAL"}
	for fail := -1; fail < len(want); fail++ {
		var got []string
		step := func(s string) error {
			got = append(got, s)
			if len(got)-1 == fail {
				return errors.New("injected unavailable core capability")
			}
			return nil
		}
		c := desktopReloadControl{
			selectGroup: func(group, target string) error { return step("select " + group + " " + target) },
			save:        func(map[string]any) error { return step("save") },
			request: func(method, path string, payload, out any) error {
				if err := step(method + " " + path); err != nil {
					return err
				}
				if out != nil {
					return json.Unmarshal([]byte(`{"connections":[{"id":"company-id","chains":["CORP-BOUND","CORP"]},{"id":"personal-id","chains":["P001","PERSONAL"]},{"id":"direct-id","chains":["PHYSICAL-BOUND","PHYSICAL"]},{"id":"probe-id","chains":["P001"]}]}`), out)
				}
				return nil
			},
		}
		err := applyDesktopConfig(map[string]any{"proxies": []any{policy.Node{"name": "P001"}}}, `C:\protected\core.json`, true, c)
		if fail < 0 {
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal(err, got)
			}
		} else if err == nil || !reflect.DeepEqual(got, want[:fail+1]) {
			t.Fatal("continued after failed barrier step", fail, err, got)
		}
		for _, s := range got {
			if s == "DELETE /connections/company-id" || s == "DELETE /connections" {
				t.Fatal("resolver transition closed unrelated company flow")
			}
		}
	}
}

func TestDesktopReloadUnknownConnectionsCannotOpenDirect(t *testing.T) {
	for _, raw := range []string{`{"connections":[{"id":"unknown","chains":[]}]}`, `{"connections":[{"id":"conflict","chains":["CORP","PHYSICAL"]}]}`, `{"connections":[{"id":"bad/path","chains":["PERSONAL"]}]}`} {
		opened := false
		c := desktopReloadControl{
			selectGroup: func(_, target string) error { opened = opened || target != "REJECT"; return nil },
			request: func(method, path string, payload, out any) error {
				if method != "GET" || path != "/connections" {
					t.Fatal("continued after unknown ownership", method, path)
				}
				return json.Unmarshal([]byte(raw), out)
			},
			save: func(map[string]any) error { t.Fatal("saved unknown transition"); return nil },
		}
		if err := applyDesktopConfig(nil, "unused", true, c); err == nil || opened {
			t.Fatal("unknown connection authorized direct", err)
		}
	}
}

func TestDesktopProxyTransitionDoesNotOpenPersonal(t *testing.T) {
	var opened []string
	c := desktopReloadControl{
		selectGroup: func(group, target string) error {
			if target != "REJECT" {
				opened = append(opened, group+"="+target)
			}
			return nil
		},
		request: func(method, path string, payload, out any) error {
			if out != nil {
				return json.Unmarshal([]byte(`{"connections":[]}`), out)
			}
			return nil
		},
		save: func(map[string]any) error { return nil },
	}
	if err := applyDesktopConfig(nil, "unused", false, c); err != nil || strings.Join(opened, ",") != "PHYSICAL=PHYSICAL-BOUND" {
		t.Fatal(err, opened)
	}
}
