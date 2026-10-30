package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Node map[string]any

// Subscription content is node data, never executable routing policy.
func ImportNodes(data []byte) ([]Node, error) {
	nodes, e := decodeNodes(data)
	if e != nil {
		return nil, e
	}
	return SanitizeNodes(nodes)
}
func decodeNodes(data []byte) ([]Node, error) {
	if len(data) > 4<<20 {
		return nil, errors.New("node input exceeds 4 MiB")
	}
	var document struct {
		Proxies []Node `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil || len(document.Proxies) == 0 {
		return nil, errors.New("expected a YAML/JSON object containing proxies")
	}
	if len(document.Proxies) > 256 {
		return nil, errors.New("personal pool accepts at most 256 subscription entries")
	}
	return document.Proxies, nil
}

type NodeIssue struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// ImportSupportedNodes makes mixed subscriptions usable while reporting every
// omitted entry. It never relaxes certificate verification or inherits rules.
func ImportSupportedNodes(data []byte) ([]Node, []NodeIssue, error) {
	nodes, e := decodeNodes(data)
	if e != nil {
		return nil, nil, e
	}
	accepted := []Node{}
	issues := []NodeIssue{}
	for i, n := range nodes {
		clean, e := SanitizeNodes([]Node{n})
		if e != nil {
			reason := strings.TrimPrefix(e.Error(), "node 1")
			issues = append(issues, NodeIssue{i + 1, strings.TrimSpace(strings.TrimPrefix(reason, ":"))})
			continue
		}
		accepted = append(accepted, clean[0])
	}
	if len(accepted) == 0 {
		return nil, issues, errors.New("subscription has no supported nodes with certificate verification enabled")
	}
	accepted, e = SanitizeNodes(accepted)
	return accepted, issues, e
}

func SanitizeNodes(input []Node) ([]Node, error) {
	if len(input) == 0 || len(input) > 256 {
		return nil, errors.New("personal pool needs 1–256 supported nodes")
	}
	common := []string{"type", "server", "port", "udp", "tls", "sni", "servername", "client-fingerprint", "fingerprint"}
	special := map[string][]string{
		"vless":     {"uuid", "flow", "network", "ws-opts", "reality-opts"},
		"hysteria2": {"password", "ports", "mport", "up", "down", "obfs", "obfs-password"},
	}
	var result []Node
	for i, entry := range input {
		typ, _ := entry["type"].(string)
		keys, ok := special[typ]
		if !ok {
			return nil, fmt.Errorf("node %d: v1 supports vless and hysteria2", i+1)
		}
		server, _ := entry["server"].(string)
		server = strings.TrimSuffix(strings.ToLower(server), ".")
		if _, err := IPv4(server); err != nil && !ValidDomain(server) {
			return nil, fmt.Errorf("node %d needs an IPv4 address or exact DNS hostname", i+1)
		}
		p, err := strconv.Atoi(fmt.Sprint(entry["port"]))
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("node %d has an invalid port", i+1)
		}
		credential := "uuid"
		if typ == "hysteria2" {
			credential = "password"
		}
		if v, ok := entry[credential].(string); !ok || len(v) == 0 || len(v) > 8192 {
			return nil, fmt.Errorf("node %d is missing its protocol credential", i+1)
		}
		if skip, _ := entry["skip-cert-verify"].(bool); skip {
			return nil, fmt.Errorf("node %d disables certificate verification", i+1)
		}
		n := Node{"name": fmt.Sprintf("P%03d", i+1), "port": p}
		for _, k := range append(common, keys...) {
			if v, exists := entry[k]; exists {
				n[k] = v
			}
		}
		n["server"] = server
		// Round-trip to JSON rejects YAML-only values and breaks input aliases.
		b, err := json.Marshal(n)
		if err != nil {
			return nil, errors.New("node contains unsupported field values")
		}
		if err = json.Unmarshal(b, &n); err != nil {
			return nil, errors.New("invalid node representation")
		}
		result = append(result, n)
	}
	return result, nil
}
