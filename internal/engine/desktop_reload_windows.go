//go:build windows

package engine

import (
	"errors"
	"net/url"
	"netlaunch/internal/policy"
	"strings"
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

// Existing personal/direct connections and every group stay closed until the new resolver
// configuration and its DNS cache flush have succeeded. The pinned Windows core
// retains the same fake-IP pool; flushing it would reuse addresses still held by
// clients. Missing core
// capabilities leave the transition closed and cause owned recovery.
func applyDesktopConfig(config map[string]any, path string, direct bool, c desktopReloadControl) error {
	for _, group := range []string{"PHYSICAL", "PERSONAL", "CORP"} {
		if err := c.selectGroup(group, "REJECT"); err != nil {
			return err
		}
	}
	if err := closeDesktopEgress(config, c); err != nil {
		return err
	}
	if err := c.save(config); err != nil {
		return err
	}
	if err := c.request("PUT", "/configs?force=true", map[string]string{"path": path}, nil); err != nil {
		return err
	}
	for _, group := range []string{"PHYSICAL", "PERSONAL", "CORP"} {
		if err := c.selectGroup(group, "REJECT"); err != nil {
			return err
		}
	}
	if err := c.request("POST", "/cache/dns/flush", nil, nil); err != nil {
		return err
	}
	if err := c.selectGroup("PHYSICAL", "PHYSICAL-BOUND"); err != nil {
		return err
	}
	if direct {
		return c.selectGroup("PERSONAL", "PHYSICAL")
	}
	return nil
}
