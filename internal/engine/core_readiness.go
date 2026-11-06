//go:build darwin || windows

package engine

import (
	"context"
	"errors"
	"net"
	"net/url"
	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
	"strconv"
	"time"
)

func wait(ctx context.Context, run string, limit time.Duration, check func(context.Context) error) error {
	return waitReady(ctx, limit, func() error { return pulse(run) }, check)
}

func choose(ctx context.Context, run string, p *selector.Policy) error {
	probes, err := personalProbeURLs(run)
	if err != nil {
		return err
	}
	started := time.Now()
	values := measurePersonal(ctx, run, p.NextBatch(8), probes)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return applyPersonalSamples(ctx, run, p, started, values)
}

func personalProbeURLs(run string) ([]string, error) {
	s, err := load(run)
	if err != nil {
		return nil, err
	}
	var probes []string
	for _, probe := range s.Manifest.Config.Probes {
		if probe.Channel == "personal" {
			probes = append(probes, probe.URL)
		}
	}
	return probes, nil
}

func measurePersonal(ctx context.Context, run string, names, probes []string) map[string]int {
	return measurePersonalWith(ctx, names, probes, func(ctx context.Context, path string, out any) error {
		return apiContext(ctx, run, "GET", path, nil, out)
	})
}

func measurePersonalWith(ctx context.Context, names, probes []string, request func(context.Context, string, any) error) map[string]int {
	return sampleNodes(ctx, names, 6*time.Second, 8, func(ctx context.Context, n string) (int, bool) {
		unknown := len(probes) == 0
		for _, u := range probes {
			started := time.Now()
			var d struct {
				Delay *int `json:"delay"`
			}
			// Rank network paths only. Selected ingress verifies service expectations
			// separately, so a business outage does not cause node cooldown/churn.
			q := url.Values{"url": {u}, "timeout": {"3000"}, "expected": {"200-599"}}
			if err := request(ctx, "/proxies/"+url.PathEscape(n)+"/delay?"+q.Encode(), &d); err != nil {
				if ctx.Err() != nil {
					return 0, false
				}
				if !delayTargetFailure(err) {
					unknown = true
				}
				continue
			}
			var details struct {
				Extra map[string]selector.ProbeState `json:"extra"`
			}
			if request(ctx, "/proxies/"+url.PathEscape(n), &details) != nil {
				return 0, false
			}
			ms, known := selector.ObservedDelay(started, time.Now(), d.Delay, details.Extra[u])
			if !known {
				unknown = true
				continue
			}
			if ms >= 0 {
				return ms, true
			}
		}
		return -1, ctx.Err() == nil && !unknown
	})
}

func applyPersonalSamples(parent context.Context, run string, p *selector.Policy, started time.Time, values map[string]int) error {
	return applyPersonalSamplesWith(parent, run, p, func(now time.Time) (string, string) { return p.DecideSamplesSince(now, started, values) })
}

func applyPersonalTimedSamples(parent context.Context, run string, p *selector.Policy, samples map[string]selector.TimedSample) error {
	return applyPersonalSamplesWith(parent, run, p, func(now time.Time) (string, string) { return p.DecideTimedSamples(now, samples) })
}

func applyPersonalSamplesWith(parent context.Context, run string, p *selector.Policy, decide func(time.Time) (string, string)) error {
	if parent.Err() != nil {
		return parent.Err()
	}
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	s, e := load(run)
	if e != nil {
		return e
	}
	node, _ := decide(time.Now())
	if e = selectPersonalContext(ctx, run, node); e != nil {
		return e
	}
	if node != selector.Reject {
		client := personalProbeClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Manifest.Config.Ports.Proxy)))
		probeErr := verifyPersonalSelection(ctx, client, s.Manifest.Config.Probes)
		client.CloseIdleConnections()
		if probeErr != nil {
			if ctx.Err() != nil {
				if parent.Err() != nil {
					return parent.Err()
				}
				// The selected ingress is unverified. Close it without inventing a
				// failed node observation or putting that node into recovery cooldown.
				if err := selectPersonal(run, selector.Reject); err != nil {
					return err
				}
				p.Commit(selector.Reject, time.Now())
				return update(run, func(s *State) error {
					s.Personal = selector.Reject
					s.Error = "personal_verification_timeout"
					personalUnavailable(s, "verification_budget_expired")
					if s.Phase == "ready" {
						s.Phase = "degraded"
					}
					return nil
				})
			}
			return rejectPersonal(run, p, node, probeErr)
		}
	}
	p.Commit(node, time.Now())
	return update(run, func(s *State) error {
		s.Personal = node
		if node == selector.Reject {
			personalUnavailable(s, "no_verified_node")
		}
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
	if nodeProbeFailure(failure) {
		p.ReportFailure(node, time.Now())
	}
	p.Commit(selector.Reject, time.Now())
	return update(run, func(s *State) error {
		s.Personal = selector.Reject
		s.Error = failure.Error()
		personalUnavailable(s, probeReason(failure))
		h := s.Channels["personal"]
		h.ChannelStatus = observeChannel(ChannelStatus{}, failure, time.Now(), policy.Probe{Channel: "personal"})
		h.ProbeScope = "mixed_ingress"
		s.Channels["personal"] = h
		if s.Phase == "ready" {
			s.Phase = "degraded"
		}
		return nil
	})
}

func ensurePersonalSelection(ctx context.Context, run string, p *selector.Policy) error {
	if p.Current != selector.Reject {
		return nil
	}
	if e := choose(ctx, run, p); e != nil {
		return e
	}
	if p.Current == selector.Reject {
		return errors.New("personal proxy is not ready")
	}
	return nil
}
