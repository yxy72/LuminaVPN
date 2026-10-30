//go:build darwin || windows

package engine

import (
	"context"
	"errors"
	"net"
	"net/url"
	"netlaunch/internal/selector"
	"strconv"
	"time"
)

type terminalReadinessError struct{ error }

func wait(ctx context.Context, run string, limit time.Duration, check func() error) error {
	deadline := time.Now().Add(limit)
	var last error
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e := pulse(run); e != nil {
			return e
		}
		last = check()
		if last == nil {
			return nil
		}
		var terminal *terminalReadinessError
		if errors.As(last, &terminal) {
			return last
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	if last != nil {
		return last
	}
	return errors.New("readiness deadline exceeded")
}

func choose(run string, p *selector.Policy) error {
	s, e := load(run)
	if e != nil {
		return e
	}
	probes := []string{}
	for _, v := range s.Manifest.Config.Probes {
		if v.Channel == "personal" {
			probes = append(probes, v.URL)
		}
	}
	type sample struct {
		name string
		ms   int
	}
	results := make(chan sample, len(p.Nodes))
	sem := make(chan struct{}, 8)
	for _, node := range p.Nodes {
		go func(n string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			ms := -1
			for _, u := range probes {
				started := time.Now()
				var d struct {
					Delay *int `json:"delay"`
				}
				q := url.Values{"url": {u}, "timeout": {"3000"}, "expected": {"200-399"}}
				if api(run, "GET", "/proxies/"+url.PathEscape(n)+"/delay?"+q.Encode(), nil, &d) != nil {
					continue
				}
				var details struct {
					Extra map[string]selector.ProbeState `json:"extra"`
				}
				if api(run, "GET", "/proxies/"+url.PathEscape(n), nil, &details) != nil {
					continue
				}
				ms = selector.HealthyDelay(started, time.Now(), d.Delay, details.Extra[u])
				if ms >= 0 {
					break
				}
			}
			results <- sample{n, ms}
		}(node)
	}
	values := map[string]int{}
	for range p.Nodes {
		v := <-results
		values[v.name] = v.ms
	}
	node, _ := p.Decide(time.Now(), values)
	if e = selectPersonal(run, node); e != nil {
		return e
	}
	if node != selector.Reject {
		client := personalProbeClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Manifest.Config.Ports.Proxy)))
		probeErr := verifyPersonalSelection(context.Background(), client, s.Manifest.Config.Probes)
		client.CloseIdleConnections()
		if probeErr != nil {
			return rejectPersonal(run, p, node, probeErr)
		}
	}
	p.Commit(node, time.Now())
	return update(run, func(s *State) error {
		s.Personal = node
		if node == selector.Reject && s.Phase == "ready" {
			s.Phase = "degraded"
		}
		return nil
	})
}

func rejectPersonal(run string, p *selector.Policy, node string, failure error) error {
	if e := selectPersonal(run, selector.Reject); e != nil {
		return e
	}
	p.ReportFailure(node, time.Now())
	p.Commit(selector.Reject, time.Now())
	return update(run, func(s *State) error {
		s.Personal = selector.Reject
		s.Error = failure.Error()
		if s.Phase == "ready" {
			s.Phase = "degraded"
		}
		return nil
	})
}

func ensurePersonalSelection(run string, p *selector.Policy) error {
	if p.Current != selector.Reject {
		return nil
	}
	if e := choose(run, p); e != nil {
		return e
	}
	if p.Current == selector.Reject {
		return errors.New("personal proxy is not ready")
	}
	return nil
}
