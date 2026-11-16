//go:build darwin || windows

package engine

import (
	"errors"
	"net/url"
	"strings"

	"netlaunch/internal/policy"
)

type desktopReloadControl struct {
	selectGroup func(group, target string) error
	request     func(method, path string, payload, out any) error
	save        func(config map[string]any) error
}

func closeDesktopEgress(config map[string]any, c desktopReloadControl) error {
	candidates := map[string]bool{}
	if proxies, ok := config["proxies"].([]any); ok {
		for _, raw := range proxies {
			var p map[string]any
			switch value := raw.(type) {
			case policy.Node:
				p = value
			case map[string]any:
				p = value
			}
			if name, ok := p["name"].(string); ok && name != "PHYSICAL-BOUND" && name != "CORP-BOUND" {
				candidates[name] = true
			}
		}
	}
	var snapshot struct {
		Connections []struct {
			ID     string   `json:"id"`
			Chains []string `json:"chains"`
		} `json:"connections"`
	}
	if err := c.request("GET", "/connections", nil, &snapshot); err != nil {
		return err
	}
	for _, connection := range snapshot.Connections {
		egress, company, rejected := false, false, false
		for _, chain := range connection.Chains {
			if candidates[chain] {
				egress = true // An in-flight independent probe of a frozen candidate.
			}
			switch chain {
			case "PERSONAL", "PHYSICAL", "PHYSICAL-BOUND":
				egress = true
			case "CORP", "CORP-BOUND":
				company = true
			case "REJECT":
				rejected = true
			}
		}
		if !egress {
			if company || rejected {
				continue
			}
			return errors.New("unclassified owned core connection during resolver transition")
		}
		if company || connection.ID == "" || len(connection.ID) > 128 || strings.ContainsAny(connection.ID, "/\\\x00\r\n") {
			return errors.New("ambiguous owned core connection during resolver transition")
		}
		if err := c.request("DELETE", "/connections/"+url.PathEscape(connection.ID), nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func addDesktopPhysicalGate(config map[string]any) error {
	var physical map[string]any
	for _, raw := range config["proxies"].([]any) {
		if proxy, ok := raw.(map[string]any); ok && proxy["name"] == "PHYSICAL" {
			if physical != nil || proxy["type"] != "direct" {
				return errors.New("ambiguous physical egress")
			}
			physical = proxy
		}
	}
	if physical == nil {
		return errors.New("physical egress is missing")
	}
	physical["name"] = "PHYSICAL-BOUND"
	config["proxy-groups"] = append(config["proxy-groups"].([]any), map[string]any{
		"name": "PHYSICAL", "type": "select", "proxies": []string{"REJECT", "PHYSICAL-BOUND"},
	})
	return nil
}

func gateDesktopConfig(c desktopReloadControl) error {
	for _, group := range []string{"PHYSICAL", "PERSONAL", "CORP"} {
		if err := c.selectGroup(group, "REJECT"); err != nil {
			return err
		}
	}
	return nil
}

// Keep the groups closed until the caller has confirmed the new resolver and
// native networking state. Flush real DNS answers, leaving the patched fake-IP
// allocator and the synthetic addresses already held by clients intact.
func prepareDesktopConfig(config, previous map[string]any, path string, c desktopReloadControl) error {
	if err := gateDesktopConfig(c); err != nil {
		return err
	}
	return replaceGatedDesktopConfig(config, previous, path, c)
}

func replaceGatedDesktopConfig(config, previous map[string]any, path string, c desktopReloadControl) error {
	if err := closeDesktopEgress(previous, c); err != nil {
		return err
	}
	if err := c.save(config); err != nil {
		return err
	}
	if err := c.request("PUT", "/configs?force=true", map[string]string{"path": path}, nil); err != nil {
		return err
	}
	if err := gateDesktopConfig(c); err != nil {
		return err
	}
	return c.request("POST", "/cache/dns/flush", nil, nil)
}

func openDesktopConfig(selectGroup func(group, target string) error, direct bool) error {
	if err := selectGroup("PHYSICAL", "PHYSICAL-BOUND"); err != nil {
		return err
	}
	if direct {
		return selectGroup("PERSONAL", "PHYSICAL")
	}
	return nil
}

func applyDesktopConfig(config map[string]any, path string, direct bool, c desktopReloadControl) error {
	if err := prepareDesktopConfig(config, config, path, c); err != nil {
		return err
	}
	return openDesktopConfig(c.selectGroup, direct)
}
