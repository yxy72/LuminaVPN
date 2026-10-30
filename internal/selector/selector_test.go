package selector

import (
	"testing"
	"time"
)

func TestHysteresisSurvivesUnchangedCommit(t *testing.T) {
	p := New([]string{"a", "b"})
	now := time.Unix(1000, 0)
	n, _ := p.Decide(now, map[string]int{"a": 100, "b": 200})
	p.Commit(n, now)
	if p.Current != "a" {
		t.Fatal(p.Current)
	}
	n, _ = p.Decide(now.Add(time.Second), map[string]int{"a": 500, "b": 100})
	p.Commit(n, now.Add(time.Second))
	if p.Current != "a" {
		t.Fatal("minimum hold bypassed")
	}
	for i := 0; i < 3; i++ {
		at := now.Add(time.Duration(61+i) * time.Second)
		n, _ = p.Decide(at, map[string]int{"a": 500, "b": 100})
		p.Commit(n, at)
		if i < 2 && p.Current != "a" {
			t.Fatal("changed before confirmations")
		}
	}
	if p.Current != "b" {
		t.Fatal("unchanged commit discarded confirmation history")
	}
}
func TestFailureAndRecovery(t *testing.T) {
	p := New([]string{"a"})
	now := time.Unix(1000, 0)
	p.Commit("a", now)
	n, _ := p.Decide(now, map[string]int{"a": -1})
	p.Commit(n, now)
	if n != Reject {
		t.Fatal("failed node retained")
	}
	n, _ = p.Decide(now.Add(time.Second), map[string]int{"a": 5})
	if n != Reject {
		t.Fatal("recovered without cooldown")
	}
	n, _ = p.Decide(now.Add(11*time.Second), map[string]int{"a": 5})
	if n != "a" {
		t.Fatal("healthy node did not recover")
	}
	if p.Current != Reject {
		t.Fatal("decision was committed before API success")
	}
}
func TestMissingMeasurementAndNoise(t *testing.T) {
	p := New([]string{"a", "b"})
	now := time.Now()
	p.Commit("a", now.Add(-time.Hour))
	n, _ := p.Decide(now, map[string]int{"a": 100, "b": 90})
	if n != "a" {
		t.Fatal("switched for noise")
	}
	n, _ = p.Decide(now, map[string]int{})
	if n != Reject {
		t.Fatal("missing samples were healthy")
	}
}

func TestRealRequestFailureOverridesLatencySample(t *testing.T) {
	p := New([]string{"fast-but-broken", "working"})
	now := time.Unix(1000, 0)
	node, _ := p.Decide(now, map[string]int{"fast-but-broken": 10, "working": 100})
	p.Commit(node, now)
	p.ReportFailure(node, now.Add(time.Second))
	if p.Current != node {
		t.Fatal("failure report committed a group change before API confirmation")
	}
	p.Commit(Reject, now.Add(time.Second))
	node, _ = p.Decide(now.Add(2*time.Second), map[string]int{"fast-but-broken": 10, "working": 100})
	if node != "working" {
		t.Fatal("fresh latency overrode a real request failure", node)
	}
	p.Commit(node, now.Add(2*time.Second))
	p.Options.MinHold = 0
	p.Options.AdvantageMS = 0
	p.Options.Confirmations = 1
	node, _ = p.Decide(now.Add(12*time.Second), map[string]int{"fast-but-broken": 10, "working": 100})
	if node != "fast-but-broken" {
		t.Fatal("recovered node did not return after cooldown and multiple fresh samples", node)
	}
}
