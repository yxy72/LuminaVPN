// Package subscription reads only explicitly configured sources and extracts
// node data and bounded personal rules. Remote settings never control VPN/DNS/TUN.
package subscription

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
)

type Source struct {
	URL         string            `json:"url,omitempty"`
	File        string            `json:"file,omitempty"`
	Format      string            `json:"format,omitempty"`
	Target      string            `json:"target,omitempty"`
	Groups      map[string]string `json:"groups,omitempty"`
	UseRules    bool              `json:"use_rules,omitempty"`
	StrictRules bool              `json:"strict_rules,omitempty"`
}
type Sources struct {
	Nodes           Source   `json:"nodes"`
	Rules           []Source `json:"rules,omitempty"`
	IntervalMinutes int      `json:"interval_minutes,omitempty"`
}
type Bootstrap struct {
	Version       int           `json:"version"`
	Policy        policy.Config `json:"policy"`
	Subscriptions Sources       `json:"subscriptions"`
}
type Result struct {
	Nodes        []policy.Node `json:"nodes"`
	Rules        []policy.Rule `json:"rules"`
	SkippedNodes int           `json:"skipped_nodes"`
	SkippedRules int           `json:"skipped_rules"`
	RuleOrigins  []RuleOrigin  `json:"rule_origins,omitempty"`
	Issues       []ImportIssue `json:"issues,omitempty"`
}

// Source labels and one-based entry indexes are safe to report. Raw URLs,
// subscription lines and node credentials are deliberately excluded.
type RuleOrigin struct {
	Source string `json:"source"`
	Index  int    `json:"index"`
}
type ImportIssue struct {
	Source string `json:"source"`
	Kind   string `json:"kind"`
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}
type RuleIssue struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}
type RuleReport struct {
	Rules   []policy.Rule
	Indexes []int
	Issues  []RuleIssue
}

func Decode(data []byte, base string) (Bootstrap, error) {
	return DecodeForIntent(data, base, policy.DefaultIntent())
}

// DecodeForIntent preserves source validation while allowing a disabled channel
// to be configured later. It never fetches a source or enables a channel.
func DecodeForIntent(data []byte, base string, intent policy.ChannelIntent) (Bootstrap, error) {
	return decodeForValidation(data, base, intent, false)
}

func DecodeForStorage(data []byte, base string) (Bootstrap, error) {
	return decodeForValidation(data, base, policy.ChannelIntent{}, true)
}

func decodeForValidation(data []byte, base string, intent policy.ChannelIntent, storage bool) (Bootstrap, error) {
	var b Bootstrap
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if len(data) > 1<<20 || d.Decode(&b) != nil {
		return b, errors.New("invalid bootstrap file")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || b.Version != 1 {
		return b, errors.New("invalid bootstrap version or trailing data")
	}
	validateErr := b.Policy.ValidateForIntent(intent)
	if storage {
		validateErr = b.Policy.ValidateForStorage()
	}
	if validateErr != nil {
		return b, errors.New("invalid bootstrap network policy")
	}
	if b.Subscriptions.IntervalMinutes == 0 {
		b.Subscriptions.IntervalMinutes = 60
	}
	if b.Subscriptions.IntervalMinutes < 1 || b.Subscriptions.IntervalMinutes > 10080 || len(b.Subscriptions.Rules) > 8 {
		return b, errors.New("invalid subscription interval or source count")
	}
	if e := normalize(&b.Subscriptions.Nodes, base); e != nil {
		return b, e
	}
	for i := range b.Subscriptions.Rules {
		if e := normalize(&b.Subscriptions.Rules[i], base); e != nil {
			return b, e
		}
	}
	return b, nil
}
func normalize(s *Source, base string) error {
	if (s.File == "") == (s.URL == "") {
		return errors.New("source needs one HTTPS URL or local file")
	}
	if s.URL != "" {
		u, e := url.Parse(s.URL)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.HasSuffix(u.Host, ":") {
			return errors.New("subscription URL must use HTTPS without URL userinfo; query tokens are supported")
		}
	}
	if s.File != "" {
		if !filepath.IsAbs(s.File) {
			s.File = filepath.Join(base, s.File)
		}
		s.File = filepath.Clean(s.File)
	}
	if s.Format == "" {
		s.Format = "classical"
	}
	if s.Format != "classical" && s.Format != "domain" && s.Format != "ipcidr" {
		return errors.New("unsupported rule source format")
	}
	if s.Target == "" {
		s.Target = "personal"
	}
	if !target(s.Target) {
		return errors.New("invalid rule source target")
	}
	for _, v := range s.Groups {
		if !target(v) {
			return errors.New("subscription groups cannot select company access")
		}
	}
	return nil
}
func target(s string) bool { return s == "personal" || s == "direct" || s == "reject" }
func Read(ctx context.Context, s Source) ([]byte, error) {
	if e := normalize(&s, "."); e != nil {
		return nil, e
	}
	if s.File != "" {
		b, e := securefile.Read(s.File, 4<<20, false)
		if e != nil {
			return nil, errors.New("local subscription unavailable")
		}
		return b, nil
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	defer transport.CloseIdleConnections()
	return readHTTPS(ctx, s, transport)
}
func readHTTPS(ctx context.Context, s Source, transport http.RoundTripper) ([]byte, error) {
	client := &http.Client{Timeout: 20 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("subscription redirects are not followed")
	}}
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if e != nil {
		return nil, errors.New("invalid subscription request")
	}
	req.Header.Set("User-Agent", "clash.meta NetLaunch/0.1")
	req.Header.Set("Accept", "application/yaml, application/json, text/yaml, */*")
	response, e := client.Do(req)
	if e != nil {
		return nil, errors.New("subscription download failed; URL and response omitted")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, errors.New("subscription server did not return success")
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if e != nil || len(data) > 4<<20 {
		return nil, errors.New("subscription response invalid or too large")
	}
	return data, nil
}
func Fetch(ctx context.Context, s Sources) (Result, error) { return FetchWith(ctx, s, Read) }
func FetchWith(ctx context.Context, s Sources, read func(context.Context, Source) ([]byte, error)) (Result, error) {
	_, result, err := fetchSnapshotWith(ctx, s, read)
	return result, err
}
func parseWith(ctx context.Context, s Sources, read func(context.Context, Source) ([]byte, error)) (Result, error) {
	var out Result
	data, e := read(ctx, s.Nodes)
	if e != nil {
		return out, e
	}
	nodes, issues, e := policy.ImportSupportedNodes(data)
	if e != nil {
		return out, errors.New("subscription contains no usable supported nodes")
	}
	out.Nodes = nodes
	out.SkippedNodes = len(issues)
	for _, issue := range issues {
		out.Issues = append(out.Issues, ImportIssue{Source: "nodes", Kind: "node", Index: issue.Index, Reason: "unsupported_or_invalid_node"})
	}
	sources := s.Rules
	if s.Nodes.UseRules {
		sources = append([]Source{s.Nodes}, sources...)
	}
	seen := map[policy.Rule]bool{}
	for i, source := range sources {
		raw := data
		if !(s.Nodes.UseRules && i == 0) {
			raw, e = read(ctx, source)
			if e != nil {
				return Result{}, e
			}
		}
		report, e := ParseRulesDetailed(raw, source)
		if e != nil {
			return Result{}, e
		}
		label := fmt.Sprintf("rules[%d]", i)
		if s.Nodes.UseRules {
			label = fmt.Sprintf("rules[%d]", i-1)
			if i == 0 {
				label = "nodes"
			}
		}
		out.SkippedRules += len(report.Issues)
		for _, issue := range report.Issues {
			out.Issues = append(out.Issues, ImportIssue{Source: label, Kind: "rule", Index: issue.Index, Reason: issue.Reason})
		}
		for index, rule := range report.Rules {
			if !seen[rule] {
				seen[rule] = true
				out.Rules = append(out.Rules, rule)
				out.RuleOrigins = append(out.RuleOrigins, RuleOrigin{Source: label, Index: report.Indexes[index]})
			}
		}
	}
	if e := policy.ValidateRules(out.Rules); e != nil {
		return Result{}, e
	}
	return out, nil
}
func ParseRules(data []byte, s Source) ([]policy.Rule, int, error) {
	report, err := ParseRulesDetailed(data, s)
	return report.Rules, len(report.Issues), err
}
func ParseRulesDetailed(data []byte, s Source) (RuleReport, error) {
	var report RuleReport
	var doc struct {
		Rules   []string `yaml:"rules"`
		Payload []string `yaml:"payload"`
	}
	if len(data) > 4<<20 || yaml.Unmarshal(data, &doc) != nil {
		return report, errors.New("invalid rule subscription")
	}
	lines := doc.Rules
	if len(lines) == 0 {
		lines = doc.Payload
	}
	if len(lines) == 0 || len(lines) > 20000 {
		return report, errors.New("rule subscription is empty or too large")
	}
	for index, line := range lines {
		skip := func(reason string) {
			report.Issues = append(report.Issues, RuleIssue{Index: index + 1, Reason: reason})
		}
		r := policy.Rule{Target: s.Target}
		if r.Target == "" {
			r.Target = "personal"
		}
		switch s.Format {
		case "domain":
			r.Type = "DOMAIN"
			r.Value = strings.ToLower(strings.TrimSpace(line))
			if strings.HasPrefix(r.Value, "+.") {
				r.Type = "DOMAIN-SUFFIX"
				r.Value = strings.TrimPrefix(r.Value, "+.")
			}
		case "ipcidr":
			r.Type = "IP-CIDR"
			r.Value = strings.TrimSpace(line)
		default:
			parts := strings.Split(line, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			if len(parts) < 2 || len(parts) > 4 {
				skip("unsupported_syntax")
				continue
			}
			r.Type = strings.ToUpper(parts[0])
			r.Value = strings.ToLower(parts[1])
			if r.Type != "DOMAIN" && r.Type != "DOMAIN-SUFFIX" && r.Type != "IP-CIDR" {
				skip("unsupported_rule_type")
				continue
			}
			if len(parts) >= 3 && parts[2] != "no-resolve" {
				mapped, ok := s.Groups[parts[2]]
				if !ok {
					mapped, ok = map[string]string{"PROXY": "personal", "PERSONAL": "personal", "DIRECT": "direct", "REJECT": "reject"}[parts[2]]
				}
				if !ok {
					skip("unmapped_group")
					continue
				}
				r.Target = mapped
			}
			if (len(parts) >= 3 && parts[2] == "no-resolve" && (r.Type != "IP-CIDR" || len(parts) != 3)) || (len(parts) == 4 && (r.Type != "IP-CIDR" || parts[3] != "no-resolve")) {
				skip("unsupported_options")
				continue
			}
		}
		if policy.ValidateRules([]policy.Rule{r}) != nil {
			skip("invalid_or_unauthorized_rule")
			continue
		}
		report.Rules = append(report.Rules, r)
		report.Indexes = append(report.Indexes, index+1)
	}
	if len(report.Rules) == 0 {
		return report, errors.New("rule subscription has no supported rules")
	}
	if s.StrictRules && len(report.Issues) != 0 {
		return report, errors.New("rule subscription omitted entries in strict mode")
	}
	return report, nil
}
