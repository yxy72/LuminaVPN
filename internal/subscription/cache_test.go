package subscription

import (
	"context"
	"strings"
	"testing"
)

func TestContentSnapshotReparseAndSourceIdentity(t *testing.T) {
	sources := Sources{Nodes: Source{URL: "https://source.example.org/?token=fixture-secret", UseRules: true, Groups: map[string]string{"Custom": "personal"}}}
	calls := 0
	snapshot, original, err := fetchSnapshotWith(context.Background(), sources, func(context.Context, Source) ([]byte, error) {
		calls++
		return []byte(nodeFixture), nil
	})
	if err != nil || calls != 1 || original.Rules[0].Target != "personal" {
		t.Fatal(calls, err)
	}
	fp, err := snapshot.Fingerprint(sources)
	if err != nil {
		t.Fatal(err)
	}
	sources.IntervalMinutes = 123
	intervalFP, err := snapshot.Fingerprint(sources)
	if err != nil || intervalFP != fp {
		t.Fatal("refresh interval changed interpretation", err)
	}
	sources.Nodes.Groups = map[string]string{"Custom": "reject"}
	mappedFP, err := snapshot.Fingerprint(sources)
	if err != nil || mappedFP == fp {
		t.Fatal("mapping failed to invalidate parsed result", err)
	}
	parsed, err := snapshot.Parse(sources)
	if err != nil || parsed.Rules[0].Target != "reject" || calls != 1 {
		t.Fatal("offline reparse failed", err)
	}
	sources.Nodes.URL += "-changed"
	if _, err := snapshot.Fingerprint(sources); err == nil || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatal("changed source accepted or disclosed", err)
	}
	if _, err := snapshot.Parse(sources); err == nil {
		t.Fatal("parse crossed source identity")
	}
}

func TestContentSnapshotDeduplicatesFetchButKeepsInterpretations(t *testing.T) {
	sources := Sources{Nodes: Source{URL: "https://source.example.org/", UseRules: true, Groups: map[string]string{"Custom": "personal"}}, Rules: []Source{{URL: "https://source.example.org/", Groups: map[string]string{"Custom": "direct"}}}}
	calls := 0
	snapshot, result, err := fetchSnapshotWith(context.Background(), sources, func(context.Context, Source) ([]byte, error) {
		calls++
		return []byte(nodeFixture), nil
	})
	if err != nil || calls != 1 || len(snapshot.Contents) != 1 || len(result.Rules) != 3 {
		t.Fatal(calls, len(result.Rules), err)
	}
	if result.Rules[0].Target != "personal" || result.Rules[2].Target != "direct" {
		t.Fatal("source order or mapping lost")
	}
}

func TestContentSnapshotRejectsCorruptionOversizeAndCancellation(t *testing.T) {
	sources := Sources{Nodes: Source{File: "fixture.yaml"}}
	snapshot, _, err := fetchSnapshotWith(context.Background(), sources, func(context.Context, Source) ([]byte, error) { return []byte(nodeFixture), nil })
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Contents[0].Data[0] ^= 1
	if _, err := snapshot.Fingerprint(sources); err == nil {
		t.Fatal("content corruption accepted")
	}
	if _, err := snapshot.Parse(sources); err == nil {
		t.Fatal("corrupted content parsed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := fetchSnapshotWith(ctx, sources, func(context.Context, Source) ([]byte, error) { t.Fatal("cancelled fetch started"); return nil, nil }); err == nil {
		t.Fatal("cancel ignored")
	}
	if _, _, err := fetchSnapshotWith(context.Background(), sources, func(context.Context, Source) ([]byte, error) { return make([]byte, (4<<20)+1), nil }); err == nil {
		t.Fatal("oversized content accepted")
	}
}

func TestRuleOriginsIssuesAndStrictReparse(t *testing.T) {
	sources := Sources{Nodes: Source{File: "fixture.yaml", UseRules: true, Groups: map[string]string{"Custom": "personal"}}, Rules: []Source{{File: "rules.yaml"}}}
	snapshot, result, err := fetchSnapshotWith(context.Background(), sources, func(_ context.Context, s Source) ([]byte, error) {
		if s.File == "rules.yaml" {
			return []byte(`rules: ["DOMAIN,blocked.example.org,REJECT", "DOMAIN,new.example.org,DIRECT", "DOMAIN,ignored.example.org,PrivateGroup", "IP-CIDR,10.0.0.0/8,PROXY"]`), nil
		}
		return []byte(nodeFixture), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RuleOrigins) != len(result.Rules) || len(result.Rules) != 3 {
		t.Fatal("missing origins")
	}
	if result.RuleOrigins[0] != (RuleOrigin{Source: "nodes", Index: 1}) || result.RuleOrigins[1] != (RuleOrigin{Source: "nodes", Index: 2}) || result.RuleOrigins[2] != (RuleOrigin{Source: "rules[0]", Index: 2}) {
		t.Fatal("entry order or deduplicated origin incorrect", result.RuleOrigins)
	}
	counts := map[string]int{}
	for _, issue := range result.Issues {
		counts[issue.Reason]++
	}
	if result.SkippedRules != 3 || counts["unsupported_rule_type"] != 1 || counts["unmapped_group"] != 1 || counts["invalid_or_unauthorized_rule"] != 1 || counts["unsupported_or_invalid_node"] != 1 {
		t.Fatal(counts)
	}
	sources.Nodes.StrictRules = true
	if _, err := snapshot.Parse(sources); err == nil {
		t.Fatal("strict mode reused permissive result")
	}
}
